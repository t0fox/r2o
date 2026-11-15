#!/bin/sh
# C/Rust differential: отказ установки правила подавления RST.
# nft: таблицы d2k_rst/r2o_rst отсутствуют; iptables: PATH без iptables.
# Проверяются observation «внимание:правило подавления RST не встало»,
# raw_usable и отсутствие дублей; сеть — loopback listener в netns.
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
for tool in ip python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required command: $tool" >&2
        exit 127
    }
done

D2K_BIN=${D2K_DETECT_BIN:-$D2O_ROOT/detect/d2k-detect}
R2O_BIN=${R2O_CONTROLLER_BIN:-${CARGO_TARGET_DIR:-$ROOT/target}/release/r2o-controller}
[ -x "$D2K_BIN" ] || { echo "missing C binary: $D2K_BIN" >&2; exit 1; }
[ -x "$R2O_BIN" ] || { echo "missing Rust binary: $R2O_BIN" >&2; exit 1; }

TEMP_BASE=${R2O_TEST_TMP:-${ROOT%/r2o}/r2o-tooling/tests}
mkdir -p "$TEMP_BASE"
TEMP=$(mktemp -d "$TEMP_BASE/r2o-rst-fail.XXXXXX")
NS="r2o-rst-fail-$$"
SERVER_PID=
cleanup() {
    status=$?
    if ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq "$NS"; then
        ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
    if [ "$status" -ne 0 ]; then
        for log in "$TEMP"/*.err "$TEMP/server.log"; do
            [ -f "$log" ] && { echo "== $log" >&2; cat "$log" >&2; }
        done
    fi
    [ "${KEEP_TEST_WORK:-0}" = 1 ] && echo "saved: $TEMP" >&2 || rm -rf "$TEMP"
}
trap cleanup EXIT HUP INT TERM

ip netns add "$NS"
ip netns exec "$NS" ip link set lo up

cat >"$TEMP/server.py" <<'PY'
import socket
import sys
import threading

ready_path = sys.argv[1]
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen(64)
with open(ready_path, "w", encoding="ascii") as ready:
    ready.write(str(listener.getsockname()[1]))

def drain(connection):
    try:
        while connection.recv(65536):
            pass
    except OSError:
        pass
    finally:
        connection.close()

while True:
    connection, _ = listener.accept()
    threading.Thread(target=drain, args=(connection,), daemon=True).start()
PY

ip netns exec "$NS" python3 "$TEMP/server.py" "$TEMP/ready" >"$TEMP/server.log" 2>&1 &
SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    [ -s "$TEMP/ready" ] && break
    kill -0 "$SERVER_PID" 2>/dev/null || { cat "$TEMP/server.log" >&2; exit 1; }
    sleep 0.05
done
[ -s "$TEMP/ready" ] || { echo "server did not start" >&2; exit 1; }
PORT=$(cat "$TEMP/ready")

run_case() {
    name=$1
    mode=$2
    if [ "$mode" = nft ]; then
        ip netns exec "$NS" env D2K_FW=nft "$D2K_BIN" classify "127.0.0.1:$PORT" \
            --sni rst-fail.example --repeats 1 --timeout 350 --only badsum \
            --allow-loopback --mark 0 --json >"$TEMP/c-$name.json" 2>"$TEMP/c-$name.err"
        ip netns exec "$NS" env R2O_FW=nft "$R2O_BIN" \
            --classify 127.0.0.1 "$PORT" rst-fail.example --repeats 1 \
            --timeout 350 --only badsum --allow-loopback --mark 0 --json \
            >"$TEMP/r-$name.json" 2>"$TEMP/r-$name.err"
    else
        ip netns exec "$NS" env -u D2K_FW -u R2O_FW PATH=/nonexistent \
            "$D2K_BIN" classify "127.0.0.1:$PORT" --sni rst-fail.example \
            --repeats 1 --timeout 350 --only badsum --allow-loopback --mark 0 --json \
            >"$TEMP/c-$name.json" 2>"$TEMP/c-$name.err"
        ip netns exec "$NS" env -u D2K_FW -u R2O_FW PATH=/nonexistent \
            "$R2O_BIN" --classify 127.0.0.1 "$PORT" rst-fail.example --repeats 1 \
            --timeout 350 --only badsum --allow-loopback --mark 0 --json \
            >"$TEMP/r-$name.json" 2>"$TEMP/r-$name.err"
    fi
    python3 - "$TEMP/c-$name.json" "$TEMP/r-$name.json" "$name" <<'PY'
import json
import sys

ATTENTION = "внимание:правило подавления RST не встало"
EXPECTED_ERR = "iptables отверг вставку; отрицательные исходы сырых зондов недостоверны"

def summarize(path):
    with open(path, encoding="utf-8") as source:
        result = json.load(source)
    attention = [item for item in result.get("trace", []) if item.get("probe") == ATTENTION]
    selftest = next(
        (item for item in result.get("trace", []) if item.get("probe") == "raw-selftest"),
        None,
    )
    return {
        "raw_usable": result.get("raw_usable"),
        "attention": [(item.get("pass", 0), item.get("fail", 0), item.get("err", "")) for item in attention],
        "selftest": None if selftest is None else (selftest.get("pass", 0), selftest.get("fail", 0)),
        "verdict": result.get("verdict"),
        "path": result.get("path"),
    }

c = summarize(sys.argv[1])
r = summarize(sys.argv[2])
if c != r:
    print("C:", json.dumps(c, ensure_ascii=False), file=sys.stderr)
    print("R:", json.dumps(r, ensure_ascii=False), file=sys.stderr)
    raise SystemExit(f"RST rule failure scenario {sys.argv[3]} differs")
if len(c["attention"]) != 1 or c["attention"][0] != (0, 0, EXPECTED_ERR):
    raise SystemExit(f"{sys.argv[3]}: wrong attention observation: {c['attention']}")
if not c["raw_usable"] or not c["selftest"] or c["selftest"][0] < 1:
    raise SystemExit(f"{sys.argv[3]}: raw path did not remain usable: {c}")
print(f"rst-fail {sys.argv[3]}: {json.dumps(c, ensure_ascii=False)}")
PY
}

run_case nft nft
run_case iptables iptables

printf 'PASS: C/Rust RST rule failure observation/raw_usable match (D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
