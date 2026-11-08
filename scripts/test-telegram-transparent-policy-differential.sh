#!/bin/sh
# TG16: paired C/Rust differential политики прозрачного перехвата.
#
# C-оракул — static `destination_allowed` из production `transparent.c`;
# Rust — `transparent::destination_allowed`.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-policy.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
if [ -z "$OPENSSL_CFLAGS" ]; then
    OPENSSL_CFLAGS="-I/tmp/openssl-dev/usr/include -I/tmp/openssl-dev/usr/include/x86_64-linux-gnu"
fi

# shellcheck disable=SC2086  # флаги — намеренный набор аргументов
"$CC" -std=c11 -O2 -Wall -Wextra -pthread $OPENSSL_CFLAGS \
    -I"$D2O_ROOT/telegram/include" -I"$D2O_ROOT/telegram/src" \
    -o "$TEMP/d2o-policy" \
    "$ROOT/crates/r2o-telegram/tests/d2o_transparent_policy_differential.c" \
    "$D2O_ROOT/telegram/src/dc_map_store.c" \
    "$D2O_ROOT/telegram/src/dc_map_json.c" \
    "$D2O_ROOT/telegram/src/dc_map.c" \
    "$D2O_ROOT/telegram/src/mtproto_crypto.c" \
    "$D2O_ROOT/telegram/src/listener.c" \
    -L/lib/x86_64-linux-gnu -l:libssl.so.3 -l:libcrypto.so.3
"$TEMP/d2o-policy" > "$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg16_policy_trace > "$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: transparent policy C/Rust differential\n' >&2
    exit 1
fi

cat "$TEMP/c.out"
printf 'PASS: C/Rust transparent port/CIDR/self-dial policy matches (D2O %s)\n' "$ACTUAL_D2O_SHA"
