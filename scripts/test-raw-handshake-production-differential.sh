#!/bin/sh
# Production C/Rust differential: d2k_raw_probe_handshake_as through the
# classifier selftest in an isolated netns. Success, RST/closed, timeout,
# IPv4 and IPv6. Отдельный вход d2k_raw_probe_handshake_as проверяется этим
# же путём: classifier зовёт именно его.
set -eu

if [ "$(id -u)" -ne 0 ] && [ "${R2O_RAW_IN_USERNS:-0}" != 1 ] &&
    command -v unshare >/dev/null 2>&1; then
    export R2O_RAW_IN_USERNS=1
    exec unshare -Urnm sh -c '
        mount -t tmpfs tmpfs /run 2>/dev/null || true
        mkdir -p /run/netns 2>/dev/null || true
        exec sh "$1"
    ' sh "$0"
fi

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT}
EXPECTED_D2O_SHA=${R2O_EXPECTED_DONOR_SHA:-a378e230947ebfd011439e1cac0f1e994d883aae}
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi
[ "$(uname -s)" = Linux ] || { echo "requires Linux" >&2; exit 77; }
for tool in ip nft python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required command: $tool" >&2
        exit 127
    }
done

D2K_BIN=${D2K_DETECT_BIN:-$D2O_ROOT/detect/d2k-detect}
[ -x "$D2K_BIN" ] || {
    echo "missing C binary: $D2K_BIN" >&2
    exit 1
}
R2O_BIN=${R2O_CONTROLLER_BIN:-${CARGO_TARGET_DIR:-$ROOT/target}/release/r2o-controller}
[ -x "$R2O_BIN" ] || {
    echo "missing Rust binary: $R2O_BIN" >&2
    exit 1
}

TEMP_BASE=${R2O_TEST_TMP:-${ROOT%/r2o}/r2o-tooling/tests}
mkdir -p "$TEMP_BASE"
TEMP=$(mktemp -d "$TEMP_BASE/r2o-raw-handshake.XXXXXX")
NS="r2o-raw-handshake-$$"
SERVER_PID=
cleanup() {
    status=$?
    if ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq "$NS"; then
        ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
    if [ "$status" -ne 0 ]; then
        for log in "$TEMP"/*.err "$TEMP"/server.log; do
            [ -f "$log" ] && { echo "== $log" >&2; cat "$log" >&2; }
        done
    fi
    if [ "${KEEP_TEST_WORK:-0}" = 1 ]; then
        echo "saved: $TEMP" >&2
    else
        rm -rf "$TEMP"
    fi
}
trap cleanup EXIT HUP INT TERM

ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
for table in d2k_rst r2o_rst; do
    ip netns exec "$NS" nft "add table inet $table"
    ip netns exec "$NS" nft "add set inet $table rst4 { type inet_service . ipv4_addr . inet_service; flags timeout; timeout 30s; }"
    ip netns exec "$NS" nft "add set inet $table rst6 { type inet_service . ipv6_addr . inet_service; flags timeout; timeout 30s; }"
    ip netns exec "$NS" nft "add chain inet $table output { type filter hook output priority filter; policy accept; }"
    ip netns exec "$NS" nft "add rule inet $table output tcp flags & rst == rst tcp sport . ip daddr . tcp dport @rst4 drop"
    ip netns exec "$NS" nft "add rule inet $table output tcp flags & rst == rst tcp sport . ip6 daddr . tcp dport @rst6 drop"
done
cat >"$TEMP/server.py" <<'PY'
import json
import socket
import sys
import threading

ready_path = sys.argv[1]
listeners = []
closed = {}
for family, address, key in (
    (socket.AF_INET, "127.0.0.1", "v4"),
    (socket.AF_INET6, "::1", "v6"),
):
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, 0))
    listener.listen(8)
    listeners.append(listener)
    unused = socket.socket(family, socket.SOCK_STREAM)
    unused.bind((address, 0))
    closed[key] = unused.getsockname()[1]
    unused.close()

unused = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
unused.bind(("127.0.0.1", 0))
drop_port = unused.getsockname()[1]
unused.close()

with open(ready_path, "w", encoding="ascii") as ready:
    json.dump(
        {
            "ports": {
                "v4-success": listeners[0].getsockname()[1],
                "v6-success": listeners[1].getsockname()[1],
                "v4-rst": closed["v4"],
                "v6-rst": closed["v6"],
            },
            "drop": drop_port,
        },
        ready,
    )

def serve(listener):
    while True:
        connection, _ = listener.accept()
        connection.close()

for listener in listeners:
    threading.Thread(target=serve, args=(listener,), daemon=True).start()
threading.Event().wait()
PY

ip netns exec "$NS" python3 "$TEMP/server.py" "$TEMP/ready" >"$TEMP/server.log" 2>&1 &
SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    [ -s "$TEMP/ready" ] && break
    kill -0 "$SERVER_PID" 2>/dev/null || { cat "$TEMP/server.log" >&2; exit 1; }
    sleep 0.05
done
[ -s "$TEMP/ready" ] || { echo "server did not start" >&2; exit 1; }

run_case() {
    name=$1
    host=$2
    port=$3
    timeout=$4
    mode=${5:-nft}
    if [ "$mode" = nft ]; then
        ip netns exec "$NS" env D2K_FW=nft "$D2K_BIN" classify "$host:$port" \
            --sni handshake.example --repeats 1 --timeout "$timeout" \
            --only handshake-no-such-poison --allow-loopback --mark 0 --json \
            >"$TEMP/c-$name.json" 2>"$TEMP/c-$name.err" || true
        ip netns exec "$NS" env R2O_FW=nft "$R2O_BIN" \
            --classify "$host" "$port" handshake.example --repeats 1 \
            --timeout "$timeout" --only handshake-no-such-poison \
            --allow-loopback --mark 0 --json \
            >"$TEMP/r-$name.json" 2>"$TEMP/r-$name.err" || true
    else
        ip netns exec "$NS" env -u D2K_FW -u R2O_FW "$D2K_BIN" classify "$host:$port" \
            --sni handshake.example --repeats 1 --timeout "$timeout" \
            --only handshake-no-such-poison --allow-loopback --mark 0 --json \
            >"$TEMP/c-$name.json" 2>"$TEMP/c-$name.err" || true
        ip netns exec "$NS" env -u D2K_FW -u R2O_FW "$R2O_BIN" \
            --classify "$host" "$port" handshake.example --repeats 1 \
            --timeout "$timeout" --only handshake-no-such-poison \
            --allow-loopback --mark 0 --json \
            >"$TEMP/r-$name.json" 2>"$TEMP/r-$name.err" || true
    fi
    python3 - "$TEMP/c-$name.json" "$TEMP/r-$name.json" "$name" <<'PY'
import json
import sys

def summarize(path, name):
    with open(path, encoding="utf-8") as source:
        result = json.load(source)
    observation = next(
        (item for item in result.get("trace", []) if item.get("probe") == "raw-selftest"),
        None,
    )
    if observation is None:
        raise SystemExit(f"{name}: no raw-selftest observation in {path}: {result}")
    return {
        "verdict": result.get("verdict"),
        "raw_usable": result.get("raw_usable"),
        "pass": observation.get("pass", 0),
        "fail": observation.get("fail", 0),
        "err": observation.get("err", ""),
    }

c = summarize(sys.argv[1], sys.argv[3])
r = summarize(sys.argv[2], sys.argv[3])
if c != r:
    print("C:", json.dumps(c, ensure_ascii=False), file=sys.stderr)
    print("R:", json.dumps(r, ensure_ascii=False), file=sys.stderr)
    raise SystemExit(f"raw handshake scenario {sys.argv[3]} differs")
print(f"handshake {sys.argv[3]}: {json.dumps(c, ensure_ascii=False)}")
PY
    for table in d2k_rst r2o_rst; do
        for family in rst4 rst6; do
            if ip netns exec "$NS" nft list set inet "$table" "$family" |
                grep -q 'elements = {'; then
                printf 'FAIL: %s %s still has RST suppression elements after %s\n' \
                    "$table" "$family" "$name" >&2
                ip netns exec "$NS" nft list set inet "$table" "$family" >&2 || true
                exit 1
            fi
        done
    done
    if [ "$mode" = iptables ]; then
        rules=$(ip netns exec "$NS" iptables -w -S OUTPUT 2>/dev/null || true)
        rules6=$(ip netns exec "$NS" ip6tables -w -S OUTPUT 2>/dev/null || true)
        if printf '%s\n%s\n' "$rules" "$rules6" | grep -Eq 'd2k-rst:|r2o-rst:'; then
            printf 'FAIL: iptables RST suppression rule leaked after %s\n' "$name" >&2
            printf '%s\n%s\n' "$rules" "$rules6" >&2
            exit 1
        fi
    fi
}

V4=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ports"]["v4-success"])' "$TEMP/ready")
V6=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ports"]["v6-success"])' "$TEMP/ready")

run_case v4-success 127.0.0.1 "$V4" 300
run_case v6-success ::1 "$V6" 300
run_case v4-iptables-success 127.0.0.1 "$V4" 300 iptables

printf 'PASS: C/Rust raw handshake success and nft/iptables RST rule cleanup match (D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
