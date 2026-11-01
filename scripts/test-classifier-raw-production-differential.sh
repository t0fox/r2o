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
        for test_log in "$TEMP/d2o.err" "$TEMP/r2o.err" "$TEMP/server.log" "$TEMP/d2o-positive.err" "$TEMP/r2o-positive.err" "$TEMP/positive-d2o-server.log" "$TEMP/positive-r2o-server.log"; do
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

ip netns exec "$NS" env D2K_FW=nft "$D2K_BIN" classify "127.0.0.1:$PORT" \
    --sni classifier.example --repeats 1 --timeout 200 \
    --allow-loopback --mark 0 --progress --json \
    >"$TEMP/d2o-full.json" 2>"$TEMP/d2o-full.err"
ip netns exec "$NS" env R2O_FW=nft "$R2O_BIN" \
    --classify 127.0.0.1 "$PORT" classifier.example --repeats 1 \
    --timeout 200 --allow-loopback --mark 0 --progress --json \
    >"$TEMP/r2o-full.json" 2>"$TEMP/r2o-full.err"

python3 - "$TEMP/d2o-full.json" "$TEMP/r2o-full.json" \
    "$TEMP/d2o-full.err" "$TEMP/r2o-full.err" <<'PY'
import json
import re
import sys

def summarize(path):
    with open(path, encoding="utf-8") as source:
        result = json.load(source)
    trace = []
    for item in result["trace"]:
        trace.append({
            "probe": item["probe"],
            "pass": item.get("pass", 0),
            "fail": item.get("fail", 0),
            "delay_ms": item.get("delay_ms", 0),
            "cuts": item.get("cuts", []),
            "error": bool(item.get("err") or item.get("error")),
        })
    return {
        "verdict": result["verdict"],
        "reason": result["reason"],
        "repeats": result["repeats"],
        "probes": result["probes"],
        "trigger_len": result["trigger_len"],
        "props": result.get("props"),
        "composed": result.get("composed", False),
        "raw_usable": result.get("raw_usable", False),
        "trace": trace,
    }

c_result = summarize(sys.argv[1])
rust_result = summarize(sys.argv[2])
if c_result != rust_result:
    print("D2O full classifier:", json.dumps(c_result, ensure_ascii=False), file=sys.stderr)
    print("R2O full classifier:", json.dumps(rust_result, ensure_ascii=False), file=sys.stderr)
    raise SystemExit("full production classifier tree differs")
print("D2O/R2O full production classifier:", json.dumps(c_result, ensure_ascii=False))

progress_pattern = re.compile(
    r"^\s*\[\s*(\d+) с\]\s+(.+?)\s+прошло=(\d+) не прошло=(\d+)"
)

def summarize_progress(path):
    events = []
    seconds = []
    with open(path, encoding="utf-8") as source:
        for line in source:
            match = progress_pattern.match(line)
            if match is None:
                continue
            seconds.append(int(match.group(1)))
            events.append((match.group(2).strip(), int(match.group(3)), int(match.group(4))))
    if not events:
        raise SystemExit(f"missing completed --progress observations in {path}")
    if any(right < left for left, right in zip(seconds, seconds[1:])):
        raise SystemExit(f"--progress elapsed seconds moved backwards in {path}")
    return tuple(events), seconds[-1]

c_progress, c_elapsed = summarize_progress(sys.argv[3])
rust_progress, rust_elapsed = summarize_progress(sys.argv[4])
if c_progress != rust_progress:
    print(f"D2O --progress observations: {len(c_progress)}", file=sys.stderr)
    print(f"R2O --progress observations: {len(rust_progress)}", file=sys.stderr)
    for index in range(max(len(c_progress), len(rust_progress))):
        c_event = c_progress[index] if index < len(c_progress) else None
        rust_event = rust_progress[index] if index < len(rust_progress) else None
        if c_event != rust_event:
            print(f"first difference at {index}: D2O={c_event}, R2O={rust_event}", file=sys.stderr)
            break
    raise SystemExit("full production classifier progress events differ")
print(
    f"D2O/R2O completed --progress observations matched: {len(c_progress)}; "
    f"elapsed_seconds={c_elapsed}/{rust_elapsed}"
)
PY

cat >"$TEMP/positive-server.py" <<'PY'
import socket
import sys
import threading
import time

ready_path = sys.argv[1]
target = b"classifier.example"
control = b"probe-d2k.invalid-control.example"
alert = b"\x15\x03\x03\x00\x02\x02\x28"
server_hello = b"\x16\x03\x03\x00\x02\x02\x00"
control_seen = threading.Event()
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 0))
listener.listen(64)
with open(ready_path, "w", encoding="ascii") as ready:
    ready.write(str(listener.getsockname()[1]))

def answer(connection):
    connection.settimeout(0.35)
    data = bytearray()
    try:
        while len(data) < 8192:
            try:
                part = connection.recv(4096)
            except socket.timeout:
                break
            if not part:
                break
            data.extend(part)
            if control in data or target in data:
                break
        if control in data:
            control_seen.set()
            connection.sendall(alert)
            action = "control-alert"
        elif control_seen.is_set() and data:
            connection.sendall(server_hello)
            action = "post-control-serverhello"
        else:
            action = "ignore"
        print(
            f"action={action} bytes={len(data)} "
            f"target={target in data} control={control in data}",
            flush=True,
        )
        time.sleep(0.05)
    except OSError as error:
        print(f"connection error: {error}", flush=True)
    finally:
        connection.close()

while True:
    connection, _ = listener.accept()
    threading.Thread(target=answer, args=(connection,), daemon=True).start()
PY

wait_positive_response() {
    log_path=$1
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        if [ -f "$log_path" ] && grep -Fq "post-control-serverhello" "$log_path"; then
            grep -Fq "control-alert" "$log_path" || return 1
            return 0
        fi
        sleep 0.05
    done
    echo "positive server did not emit a ServerHello: $log_path" >&2
    return 1
}

start_positive_server() {
    ready_path=$1
    log_path=$2
    ip netns exec "$NS" python3 "$TEMP/positive-server.py" "$ready_path" >"$log_path" 2>&1 &
    SERVER_PID=$!
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        [ -s "$ready_path" ] && break
        kill -0 "$SERVER_PID" 2>/dev/null || { cat "$log_path" >&2; exit 1; }
        sleep 0.05
    done
    [ -s "$ready_path" ] || { echo "positive loopback server did not start" >&2; exit 1; }
}

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=

start_positive_server "$TEMP/positive-d2o.ready" "$TEMP/positive-d2o-server.log"
POSITIVE_PORT=$(cat "$TEMP/positive-d2o.ready")
ip netns exec "$NS" env D2K_FW=nft "$D2K_BIN" classify "127.0.0.1:$POSITIVE_PORT" \
    --sni classifier.example --repeats 1 --timeout 350 \
    --allow-loopback --mark 0 --json \
    >"$TEMP/d2o-positive.json" 2>"$TEMP/d2o-positive.err"
wait_positive_response "$TEMP/positive-d2o-server.log"
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=

start_positive_server "$TEMP/positive-r2o.ready" "$TEMP/positive-r2o-server.log"
POSITIVE_PORT=$(cat "$TEMP/positive-r2o.ready")
ip netns exec "$NS" env R2O_FW=nft "$R2O_BIN" \
    --classify 127.0.0.1 "$POSITIVE_PORT" classifier.example --repeats 1 \
    --timeout 350 --allow-loopback --mark 0 --json \
    >"$TEMP/r2o-positive.json" 2>"$TEMP/r2o-positive.err"
wait_positive_response "$TEMP/positive-r2o-server.log"

python3 - "$TEMP/d2o-positive.json" "$TEMP/r2o-positive.json" \
    "$TEMP/positive-d2o-server.log" "$TEMP/positive-r2o-server.log" <<'PY'
import json
import sys

def summarize(path):
    with open(path, encoding="utf-8") as source:
        result = json.load(source)
    trace = [
        (
            item["probe"],
            item.get("pass", 0),
            item.get("fail", 0),
            item.get("delay_ms", 0),
            item.get("cuts", []),
            bool(item.get("err") or item.get("error")),
        )
        for item in result["trace"]
    ]
    property_hit = next(
        (item for item in trace if item[0] == "свойство:перекрытие слева"),
        None,
    )
    if (
        result["verdict"] != "poisonable"
        or result.get("path") != "свойство"
        or result.get("composed", False)
        or not result.get("raw_usable")
        or property_hit is None
        or property_hit[1:3] != (1, 0)
    ):
        raise SystemExit(f"expected a positive production property hit in {path}")
    return (
        result["verdict"],
        result.get("path"),
        result.get("composed", False),
        result.get("raw_usable", False),
        result.get("props"),
        trace,
    )

c_result = summarize(sys.argv[1])
rust_result = summarize(sys.argv[2])
for path in sys.argv[3:]:
    with open(path, encoding="utf-8") as source:
        log = source.read()
    if "control-alert" not in log or "post-control-serverhello" not in log:
        raise SystemExit(f"positive server did not traverse both response states: {path}")
if c_result != rust_result:
    print("D2O positive property:", json.dumps(c_result, ensure_ascii=False), file=sys.stderr)
    print("R2O positive property:", json.dumps(rust_result, ensure_ascii=False), file=sys.stderr)
    raise SystemExit("positive production property results differ")
print("D2O/R2O positive production property:", json.dumps(c_result, ensure_ascii=False))
PY

echo "PASSED: actual D2O and R2O production classifiers matched a positive raw property hit"
