#!/bin/sh
# TG6: paired C/Rust differential MTProto splitter.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-splitter.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

# В этом окружении OpenSSL-заголовки берутся из распакованного libssl-dev,
# а libcrypto — из системного runtime. Если pkg-config доступен, он главнее.
OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
OPENSSL_LIBS=$(pkg-config --libs openssl 2>/dev/null || true)
if [ -z "$OPENSSL_CFLAGS" ]; then
    OPENSSL_CFLAGS="-I/tmp/openssl-dev/usr/include -I/tmp/openssl-dev/usr/include/x86_64-linux-gnu"
fi
if [ -z "$OPENSSL_LIBS" ]; then
    OPENSSL_LIBS="-L/lib/x86_64-linux-gnu -l:libcrypto.so.3"
fi

# shellcheck disable=SC2086  # флаги — намеренный набор аргументов
"$CC" -std=gnu11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/telegram/include" $OPENSSL_CFLAGS \
    -o "$TEMP/d2o-splitter" \
    "$ROOT/scripts/fixtures/d2o_mtproto_splitter_trace.c" \
    "$D2O_ROOT/telegram/src/mtproto_splitter.c" \
    "$D2O_ROOT/telegram/src/mtproto_crypto.c" \
    "$D2O_ROOT/telegram/src/memory_budget.c" \
    $OPENSSL_LIBS
"$TEMP/d2o-splitter" > "$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example mtproto_splitter_trace > "$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: MTProto splitter C/Rust differential\n' >&2
    exit 1
fi

printf 'PASS: C/Rust MTProto splitter frames and flush match (D2O %s)\n' "$ACTUAL_D2O_SHA"
