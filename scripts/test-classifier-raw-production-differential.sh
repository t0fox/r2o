#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/r2o}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi
[ "$(uname -s)" = Linux ] || {
    echo "production raw classifier differential requires Linux" >&2
    exit 77
}
for tool in ip nft python3 make; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required command: $tool" >&2
        exit 127
    }
done

D2K_BIN=${D2K_DETECT_BIN:-$D2O_ROOT/detect/d2k-detect}
if [ ! -x "$D2K_BIN" ]; then
    make -C "$D2O_ROOT/detect" d2k-detect
fi
R2O_BIN=${R2O_CONTROLLER_BIN:-${CARGO_TARGET_DIR:-$ROOT/target}/release/r2o-controller}
if [ ! -x "$R2O_BIN" ]; then
    cargo build --release --locked --package r2o-controller
fi
[ -x "$D2K_BIN" ] && [ -x "$R2O_BIN" ] || {
    echo "C or Rust classifier binary is missing" >&2
    exit 1
}

TEMP_BASE=${R2O_TEST_TMP:-${ROOT%/r2o}/r2o-tooling/tests}
mkdir -p "$TEMP_BASE"
TEMP=$(mktemp -d "$TEMP_BASE/r2o-classifier-raw.XXXXXX")
NS="r2o-classifier-raw-$$"
SERVER_PID=
cleanup() {
    test_exit_status=$?
    if ip netns list | awk '{print $1}' | grep -Fxq "$NS"; then
        ip netns pids "$NS" | xargs -r kill 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
    if [ "$test_exit_status" -ne 0 ]; then
        for test_log in "$TEMP/d2o.err" "$TEMP/r2o.err" "$TEMP/server.log"; do
            if [ -f "$test_log" ]; then cat "$test_log" >&2 || true; fi
        done
    fi
    if [ "${KEEP_TEST_WORK:-0}" = 1 ]; then
        echo "saved test files: $TEMP" >&2
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
    ip netns exec "$NS" nft "add chain inet $table output { type filter hook output priority filter; policy accept; }"
    ip netns exec "$NS" nft "add rule inet $table output tcp flags & rst == rst tcp sport . ip daddr . tcp dport @rst4 drop"
done

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
[ -s "$TEMP/ready" ] || { echo "loopback sink did not start" >&2; exit 1; }
PORT=$(cat "$TEMP/ready")

ip netns exec "$NS" env D2K_FW=nft "$D2K_BIN" classify "127.0.0.1:$PORT" \
    --sni classifier.example --repeats 1 --timeout 350 --only badsum \
    --allow-loopback --mark 0 --json >"$TEMP/d2o.json" 2>"$TEMP/d2o.err"
ip netns exec "$NS" env R2O_FW=nft "$R2O_BIN" \
    --classify 127.0.0.1 "$PORT" classifier.example --repeats 1 \
    --timeout 350 --only badsum --allow-loopback --mark 0 --json \
    >"$TEMP/r2o.json" 2>"$TEMP/r2o.err"

python3 - "$TEMP/d2o.json" "$TEMP/r2o.json" <<'PY'
import json
import sys

def summarize(path):
    with open(path, encoding="utf-8") as source:
        result = json.load(source)
    trace = result["trace"]
    selected = []
    for name in ("raw-selftest", "poison:badsum"):
        observation = next((item for item in trace if item["probe"] == name), None)
        if observation is None:
            raise SystemExit(f"missing production observation {name} in {path}")
        selected.append((name, observation.get("pass", 0), observation.get("fail", 0)))
    if not result.get("raw_usable"):
        raise SystemExit(f"raw selftest did not mark the raw layer usable in {path}")
    return result["verdict"], result["raw_usable"], tuple(selected)

c_result = summarize(sys.argv[1])
rust_result = summarize(sys.argv[2])
if c_result != rust_result:
    print("D2O:", json.dumps(c_result, ensure_ascii=False), file=sys.stderr)
    print("R2O:", json.dumps(rust_result, ensure_ascii=False), file=sys.stderr)
    raise SystemExit("production raw classifier results differ")
print("D2O/R2O production raw path:", json.dumps(c_result, ensure_ascii=False))
PY

echo "PASSED: pinned D2O and R2O production classifiers matched raw selftest and badsum probe in an isolated network namespace"