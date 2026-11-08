#!/bin/sh
# TG17: paired C/Rust differential official secret/DD.
#
# C-оракул — production `tg_dc_handshake_secrets` и
# `tg_transparent_select_route`; Rust — `handshake_secrets_for_at`,
# `parse_client_init_with_secrets` и `select_transparent_route`.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-secret-dd.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

python3 "$ROOT/scripts/fixtures/make_tg17_snapshot.py" "$TEMP/snapshot.json"
"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg17_trace -- generate "$TEMP/handshakes"
"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg17_trace -- \
    trace "$TEMP/handshakes" "$TEMP/snapshot.json" > "$TEMP/rust.out"

OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
if [ -z "$OPENSSL_CFLAGS" ]; then
    OPENSSL_CFLAGS="-I/tmp/openssl-dev/usr/include -I/tmp/openssl-dev/usr/include/x86_64-linux-gnu"
fi

# shellcheck disable=SC2086  # флаги — намеренный набор аргументов
"$CC" -std=c11 -O2 -Wall -Wextra -pthread $OPENSSL_CFLAGS \
    -I"$D2O_ROOT/telegram/include" \
    -o "$TEMP/d2o-tg17" \
    "$ROOT/crates/r2o-telegram/tests/d2o_tg17_differential.c" \
    "$D2O_ROOT/telegram/src/transparent.c" \
    "$D2O_ROOT/telegram/src/dc_map_store.c" \
    "$D2O_ROOT/telegram/src/dc_map_json.c" \
    "$D2O_ROOT/telegram/src/dc_map.c" \
    "$D2O_ROOT/telegram/src/mtproto_crypto.c" \
    "$D2O_ROOT/telegram/src/listener.c" \
    -L/lib/x86_64-linux-gnu -l:libssl.so.3 -l:libcrypto.so.3

"$TEMP/d2o-tg17" secrets "$TEMP/snapshot.json" > "$TEMP/c.out"
"$TEMP/d2o-tg17" route "$TEMP/snapshot.json" "$TEMP/handshakes" >> "$TEMP/c.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: official secret/DD C/Rust differential\n' >&2
    exit 1
fi

cat "$TEMP/c.out"
printf 'PASS: C/Rust official secret scope and DD route selection match (D2O %s)\n' "$ACTUAL_D2O_SHA"
