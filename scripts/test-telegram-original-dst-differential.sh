#!/bin/sh
# TG15: paired C/Rust differential разбора SO_ORIGINAL_DST.
#
# C-оракул — production `tg_listener_decode_original_dst_any`; Rust —
# `transparent::decode_original_destination`, используемый listener-путём.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-original-dst.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/telegram/include" \
    -o "$TEMP/d2o-original-dst" \
    "$ROOT/crates/r2o-telegram/tests/d2o_original_dst_differential.c" \
    "$D2O_ROOT/telegram/src/listener.c"
"$TEMP/d2o-original-dst" > "$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example tg15_trace > "$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: SO_ORIGINAL_DST C/Rust differential\n' >&2
    exit 1
fi

cat "$TEMP/c.out"
printf 'PASS: C/Rust SO_ORIGINAL_DST sockaddr decode matches (D2O %s)\n' "$ACTUAL_D2O_SHA"
