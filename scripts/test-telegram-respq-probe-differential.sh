#!/bin/sh
# TG8: paired C/Rust differential resPQ probe на общем fake MTProto DC.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-gcc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-respq.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
if [ -z "$OPENSSL_CFLAGS" ]; then
    OPENSSL_CFLAGS="-I/tmp/openssl-dev/usr/include -I/tmp/openssl-dev/usr/include/x86_64-linux-gnu"
fi

# shellcheck disable=SC2086  # флаги — намеренный набор аргументов
"$CC" -std=c11 -O2 -Wall -Wextra $OPENSSL_CFLAGS \
    -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/telegram/include" -I"$D2O_ROOT/telegram/src" \
    -o "$TEMP/d2o-respq" \
    "$ROOT/crates/r2o-telegram/tests/d2o_res_pq_probe_differential.c" \
    "$D2O_ROOT/telegram/src/mtproto_probe.c" \
    "$D2O_ROOT/telegram/src/mtproto_crypto.c" \
    -Wl,--gc-sections -pthread \
    -L/lib/x86_64-linux-gnu -l:libssl.so.3 -l:libcrypto.so.3

"$CARGO" build --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --examples

: > "$TEMP/trace"
for mode in valid wrong-nonce non-plain pq-too-long empty-fingerprints trailing bad-msg-id; do
    rm -f "$TEMP/port" "$TEMP/server.log"
    "$ROOT/target/debug/examples/res_pq_server" "$TEMP/port" "$mode" 2 \
        > "$TEMP/server.log" 2>&1 &
    server_pid=$!
    attempt=0
    while [ ! -s "$TEMP/port" ]; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 200 ] || { echo "server did not start: $mode" >&2; exit 1; }
        sleep 0.05
    done
    port=$(cat "$TEMP/port")

    "$TEMP/d2o-respq" "$port" > "$TEMP/c.out"
    "$ROOT/target/debug/examples/res_pq_probe_client" "$port" > "$TEMP/rust.out"

    wait "$server_pid"
    grep -q '^ok=' "$TEMP/c.out"
    grep -q '^ok=' "$TEMP/rust.out"
    if ! cmp "$TEMP/c.out" "$TEMP/rust.out"; then
        echo "FAIL $mode: C/Rust probe differ" >&2
        cat "$TEMP/c.out" "$TEMP/rust.out" >&2
        exit 1
    fi
    requests=$(grep -c 'probe request=req_pq_multi' "$TEMP/server.log" || true)
    [ "$requests" -eq 2 ] || {
        echo "FAIL $mode: expected 2 req_pq_multi, got $requests" >&2
        cat "$TEMP/server.log" >&2
        exit 1
    }
    printf '%s %s\n' "$mode" "$(cat "$TEMP/c.out")" >> "$TEMP/trace"
done

cat "$TEMP/trace"
grep -q '^valid ok=1$' "$TEMP/trace" || {
    echo "valid resPQ probe was not healthy" >&2
    exit 1
}
printf 'PASS: C/Rust resPQ probe health and validation match (D2O %s)\n' "$ACTUAL_D2O_SHA"
