#!/bin/sh
# C stdout-differential: static `print_journal` против r2o_write_journal.
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

DENY="$D2O_ROOT/datapath"
make -s -C "$DENY" journal.o CC="$CC" >/dev/null
mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-journal.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$DENY/include" -I"$D2O_ROOT/core/include" -I"$DENY" \
    -DD2K_RELEASE_ID='"dev"' \
    -o "$TEMP/d2o-journal" \
    "$ROOT/crates/r2o-datapath/tests/d2o_journal_differential.c" \
    "$DENY/journal.o" -Wl,--gc-sections
"$TEMP/d2o-journal" >"$TEMP/c.out"

R2O_JOURNAL_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --bin r2o-datapath \
    app::tests::journal_differential_matches_c -- --exact >"$TEMP/cargo.log" 2>&1

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: print_journal stdout differential\n' >&2
    exit 1
fi

printf 'lines=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: C print_journal/Rust writer stdout match (D2O %s)\n' "$ACTUAL_D2O_SHA"
