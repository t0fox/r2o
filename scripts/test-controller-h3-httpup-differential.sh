#!/bin/sh
# CL14: paired C/Rust differential HTTP/3 helpers и httpup.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-cl14-h3-httpup.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -C "$D2O_ROOT/core" crypto.o diagnostics.o >/dev/null
"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-h3-httpup" \
    "$ROOT/crates/r2o-controller/tests/d2o_h3_httpup_differential.c" \
    "$D2O_ROOT/core/h3.c" \
    "$D2O_ROOT/core/quicwire.c" \
    "$D2O_ROOT/core/httpup_logic.c" \
    "$D2O_ROOT/core/crypto.o" \
    "$D2O_ROOT/core/diagnostics.o"
"$TEMP/d2o-h3-httpup" >"$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --example tg_cl14_h3_httpup_trace >"$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: HTTP/3 + httpup differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(wc -l < "$TEMP/c.out")"
grep '^h3status static25 ' "$TEMP/c.out"
printf 'PASS: C/Rust HTTP/3 helpers and httpup match (D2O %s)\n' "$ACTUAL_D2O_SHA"
