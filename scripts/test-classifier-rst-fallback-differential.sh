#!/bin/sh
# C/Rust differential: iptables без xt_comment. Первая вставка с --comment
# отвергается (exit 2), fallback без комментария проходит; трасса не должна
# получать attention об отказе правила.
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

D2K_BIN=${D2K_DETECT_BIN:-$D2O_ROOT/detect/d2k-detect}
R2O_BIN=${R2O_CONTROLLER_BIN:-${CARGO_TARGET_DIR:-$ROOT/target}/release/r2o-controller}
if [ "${R2O_SKIP_RELEASE_BUILD:-0}" != 1 ]; then
    (cd "$ROOT" && cargo build --release --locked --offline \
        -p r2o-controller --bin r2o-controller) || {
        echo "failed to build release r2o-controller" >&2
        exit 1
    }
fi
[ -x "$D2K_BIN" ] || { echo "missing C binary: $D2K_BIN" >&2; exit 1; }
[ -x "$R2O_BIN" ] || { echo "missing Rust binary: $R2O_BIN" >&2; exit 1; }

TEMP_BASE=${R2O_TEST_TMP:-${ROOT%/r2o}/r2o-tooling/tests}
mkdir -p "$TEMP_BASE"
TEMP=$(mktemp -d "$TEMP_BASE/r2o-rst-fallback.XXXXXX")
NS="r2o-rst-fallback-$$"
SERVER_PID=
cleanup() {
    status=$?
    if ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq "$NS"; then
        ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
    if [ "$status" -ne 0 ]; then
        for log in "$TEMP"/*.err "$TEMP"/*.log; do
            [ -f "$log" ] && { echo "== $log" >&2; cat "$log" >&2; }
        done
    fi
    [ "${KEEP_TEST_WORK:-0}" = 1 ] && echo "saved: $TEMP" >&2 || rm -rf "$TEMP"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$TEMP/bin"
for program in iptables ip6tables; do
    cat >"$TEMP/bin/$program" <<'SH'
#!/bin/sh
echo "$*" >>"${RULE_LOG:?}"
case "$*" in
    *"-S OUTPUT"*) exit 0 ;;
    *"-I OUTPUT"*"--comment"*) exit 2 ;;
    *"-I OUTPUT"*) exit 0 ;;
    *"-D OUTPUT"*) exit 0 ;;
    *"-C OUTPUT"*) exit 1 ;;
    *) exit 0 ;;
esac
SH
    chmod +x "$TEMP/bin/$program"
done

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

ip netns exec "$NS" env -u D2K_FW -u R2O_FW RULE_LOG="$TEMP/c-rules.log" PATH="$TEMP/bin:$PATH" \
    "$D2K_BIN" classify "127.0.0.1:$PORT" \
    --sni fallback.example --repeats 1 --timeout 350 --only badsum \
    --allow-loopback --mark 0 --json >"$TEMP/c.json" 2>"$TEMP/c.err"
ip netns exec "$NS" env -u D2K_FW -u R2O_FW RULE_LOG="$TEMP/r-rules.log" PATH="$TEMP/bin:$PATH" \
    "$R2O_BIN" --classify 127.0.0.1 "$PORT" fallback.example \
    --repeats 1 --timeout 350 --only badsum --allow-loopback --mark 0 --json \
    >"$TEMP/r.json" 2>"$TEMP/r.err"

python3 - "$TEMP/c.json" "$TEMP/r.json" "$TEMP/c-rules.log" "$TEMP/r-rules.log" <<'PY' || exit 1
import json
import sys

ATTENTION = "внимание:правило подавления RST не встало"

def summary(path):
    with open(path, encoding="utf-8") as source:
        data = json.load(source)
    attention = [item for item in data.get("trace", []) if item.get("probe") == ATTENTION]
    selftest = next(
        (item for item in data.get("trace", []) if item.get("probe") == "raw-selftest"),
        None,
    )
    return {
        "raw_usable": data.get("raw_usable"),
        "attention": attention,
        "selftest": None if selftest is None else (selftest.get("pass", 0), selftest.get("fail", 0)),
        "notes": data.get("notes", []),
    }

c = summary(sys.argv[1])
r = summary(sys.argv[2])
if c != r:
    print("C:", c, file=sys.stderr)
    print("R:", r, file=sys.stderr)
    raise SystemExit("fallback results differ")
if c["attention"] or not c["raw_usable"] or not c["selftest"] or c["selftest"][0] < 1:
    raise SystemExit(f"fallback did not keep raw usable: {c}")

for path, name in ((sys.argv[3], "C"), (sys.argv[4], "R")):
    with open(path, encoding="utf-8") as source:
        lines = [line.strip() for line in source if "-I OUTPUT" in line]
    with_comment = [line for line in lines if "--comment" in line]
    without_comment = [line for line in lines if "--comment" not in line]
    if not with_comment or not without_comment:
        raise SystemExit(f"{name} did not try comment+fallback: {lines}")
    if with_comment[0] != lines[0] or without_comment[0] != lines[1]:
        raise SystemExit(f"{name} fallback order is wrong: {lines}")
print(f"D2O/R2O iptables fallback without xt_comment matched: C={len(lines)} R={len(lines)} inserts")
PY

printf 'PASS: C/Rust iptables fallback without xt_comment match (D2O %s)\n' "$ACTUAL_D2O_SHA"
