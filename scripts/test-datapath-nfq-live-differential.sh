#!/bin/sh
# C/Rust differential: живой NFQUEUE (open/recv/parse/verdict) в netns.
#
# Без root переисполняется через `unshare -Urn`; nft-правило на output
# направляет один UDP-пакет в очередь. Сверяются hook/hw/outdev/mark/id,
# длина и L4-хеш пакета, cap/trunc/ts/lost.
set -eu

if [ -z "${R2O_IN_USERNS:-}" ] && [ "$(id -u)" -ne 0 ]; then
    R2O_IN_USERNS=1 exec unshare -Urn sh "$0" "$@"
fi

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
DONOR_DATAPATH=${R2O_DONOR_DATAPATH:-"$D2O_ROOT/datapath"}
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT/target"}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}
QUEUE=4242
PORT=39000
SPORT=39001

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi
for tool in ip nft python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "required command is missing: $tool" >&2
        exit 1
    }
done

ip link set lo up 2>/dev/null || true
mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-nfq-live.XXXXXX")
cleanup() {
    nft delete table ip r2ot_live 2>/dev/null || true
    rm -rf -- "$TEMP"
}
trap cleanup EXIT HUP INT TERM

nft delete table ip r2ot_live 2>/dev/null || true
nft add table ip r2ot_live
if [ "${R2O_NFQ_HOOK:-output}" = input ]; then
    nft add chain ip r2ot_live in "{ type filter hook input priority 0 ; }"
    nft add rule ip r2ot_live in queue num "$QUEUE"
else
    nft add chain ip r2ot_live out "{ type filter hook output priority 0 ; }"
    nft add rule ip r2ot_live out queue num "$QUEUE"
fi

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$DONOR_DATAPATH/include" -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-nfq-live" \
    "$ROOT/crates/r2o-datapath/tests/d2o_nfq_live_differential.c" \
    "$DONOR_DATAPATH/nfq.c" "$DONOR_DATAPATH/nl.c"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --test d2o_nfq_live --no-run >"$TEMP/build.log" 2>&1
RUST_BIN=
for candidate in "$TARGET_DIR"/debug/deps/d2o_nfq_live-*; do
    case "$candidate" in
        *.d) continue ;;
    esac
    if [ -x "$candidate" ]; then
        RUST_BIN=$candidate
    fi
done
[ -n "$RUST_BIN" ] || {
    echo "не найден тестовый бинарник d2o_nfq_live" >&2
    exit 2
}

wait_for_open() {
    file=$1
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        if grep -q '^open=1' "$file" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        attempt=$((attempt + 1))
    done
    return 1
}

send_udp() {
    python3 -c '
import socket, sys, time
receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver.bind(("127.0.0.1", int(sys.argv[1])))
print("ready", flush=True)
print(receiver.recv(64).decode(), flush=True)
' "$PORT" >"$TEMP/recv.out" 2>&1 &
    recv_pid=$!
    # Дать получателю привязать порт.
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        if grep -q '^ready$' "$TEMP/recv.out" 2>/dev/null; then
            break
        fi
        sleep 0.05
        attempt=$((attempt + 1))
    done
    python3 -c '
import socket, sys, time
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender.bind(("127.0.0.1", int(sys.argv[1])))
time.sleep(0.1)
sender.sendto(b"nfq-live", ("127.0.0.1", int(sys.argv[2])))
' "$SPORT" "$PORT" >"$TEMP/send.log" 2>&1 &
    send_pid=$!
    wait "$send_pid" 2>/dev/null || true
    wait "$recv_pid" 2>/dev/null || true
}

run_c() {
    : >"$TEMP/c.raw"
    R2O_NFQ_LIVE_QUEUE=$QUEUE timeout 20 "$TEMP/d2o-nfq-live" \
        >"$TEMP/c.raw" 2>"$TEMP/c.err" &
    pid=$!
    if ! wait_for_open "$TEMP/c.raw"; then
        cat "$TEMP/c.err" >&2 || true
        echo "C NFQUEUE did not open" >&2
        exit 1
    fi
    send_udp
    wait "$pid" 2>/dev/null || true
}

run_rust() {
    rm -f "$TEMP/rust.ready" "$TEMP/rust.out"
    R2O_NFQ_LIVE_QUEUE=$QUEUE \
        R2O_NFQ_LIVE_READY="$TEMP/rust.ready" \
        R2O_NFQ_LIVE_DIFF_OUTPUT="$TEMP/rust.out" \
        timeout 30 "$RUST_BIN" --exact --ignored --nocapture \
        nfqueue_live_open_recv_verdict_matches_c \
        >"$TEMP/rust.log" 2>&1 &
    pid=$!
    if ! wait_for_open "$TEMP/rust.ready"; then
        cat "$TEMP/rust.log" >&2 || true
        echo "Rust NFQUEUE did not open" >&2
        exit 1
    fi
    send_udp
    wait "$pid" 2>/dev/null || true
}

run_c
run_rust

grep -q '^recv=1' "$TEMP/c.raw"
grep -q '^recv=1' "$TEMP/rust.out"
if [ "${R2O_SHOW_OUTPUT:-0}" = 1 ]; then
    cat "$TEMP/c.raw"
fi
diff -u "$TEMP/c.raw" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.raw")"
printf 'PASS: live NFQUEUE C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
