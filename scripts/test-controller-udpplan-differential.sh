#!/bin/sh
# M6: paired C/Rust differential udpplan — голосовой план Discord.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-m6-udpplan.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-udpplan" \
    "$ROOT/crates/r2o-controller/tests/d2o_udpplan_differential.c" \
    "$D2O_ROOT/core/udpplan.c" \
    -Wl,--gc-sections
"$TEMP/d2o-udpplan" >"$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --example m6_udpplan_trace >"$TEMP/rust.out"

sed -e 's/^d2k-plan /plan /' -e 's/^r2o-plan /plan /' \
    -e 's/^id .*/id X/' "$TEMP/c.out" >"$TEMP/c.norm"
sed -e 's/^d2k-plan /plan /' -e 's/^r2o-plan /plan /' \
    -e 's/^id .*/id X/' "$TEMP/rust.out" >"$TEMP/rust.norm"

if ! diff -u "$TEMP/c.norm" "$TEMP/rust.norm"; then
    printf 'FAIL: udpplan differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(grep -c '^case ' "$TEMP/c.out")"
grep -A3 '^case voice-1$' "$TEMP/c.norm" | head -4
printf 'PASS: C/Rust voice plan text matches (D2O %s)\n' "$ACTUAL_D2O_SHA"
