#!/bin/sh
# TG4: paired C/Rust differential `help.getConfig` → dcOption → DcSnapshot.
#
# C-оракул — production `telegram/src/mtproto_config.c` (`tg_mtproto_config_parse`).
# Проверяются флаги media/tcpo/cdn/static/this_port_only, IPv4/IPv6, порты,
# секреты, gzip_packed (включая вложенность), покрытие DC1–5 и отказ на
# неизвестных флагах/хвостовых байтах/некорректных полях.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-config.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

# В этом окружении заголовки OpenSSL/zlib берутся из распакованных -dev пакетов,
# а runtime-библиотеки — системные. При наличии pkg-config он главнее.
OPENSSL_CFLAGS=$(pkg-config --cflags openssl 2>/dev/null || true)
ZLIB_CFLAGS=$(pkg-config --cflags zlib 2>/dev/null || true)
ZLIB_LIBS=$(pkg-config --libs zlib 2>/dev/null || true)
if [ -z "$OPENSSL_CFLAGS" ]; then
    OPENSSL_CFLAGS="-I/tmp/openssl-dev/usr/include -I/tmp/openssl-dev/usr/include/x86_64-linux-gnu"
fi
if [ -z "$ZLIB_CFLAGS" ]; then
    ZLIB_CFLAGS="-I/tmp/zlib-dev/usr/include"
fi
if [ -z "$ZLIB_LIBS" ]; then
    ZLIB_LIBS="-L/lib/x86_64-linux-gnu -l:libz.so.1"
fi

# shellcheck disable=SC2086  # флаги — намеренный набор аргументов
"$CC" -std=gnu11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/telegram/include" -I"$D2O_ROOT/telegram/src" \
    $OPENSSL_CFLAGS $ZLIB_CFLAGS \
    -o "$TEMP/d2o-config-trace" \
    "$ROOT/scripts/fixtures/d2o_config_trace.c" \
    "$D2O_ROOT/telegram/src/mtproto_config.c" \
    "$D2O_ROOT/telegram/src/dc_map.c" \
    "$D2O_ROOT/telegram/src/dc_map_json.c" \
    $ZLIB_LIBS

mkdir -p "$TEMP/cases"
"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example dc_config_trace -- "$TEMP/cases" > "$TEMP/rust.out"

: > "$TEMP/c.out"
while IFS= read -r name; do
    "$TEMP/d2o-config-trace" "$name" "$TEMP/cases/$name.bin" 1800000000 >> "$TEMP/c.out"
done < "$TEMP/cases/cases.txt"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: help.getConfig C/Rust differential\n' >&2
    exit 1
fi

printf 'PASS: C/Rust help.getConfig dcOption flags, gzip and validation match (D2O %s)\n' "$ACTUAL_D2O_SHA"
