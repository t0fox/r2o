#!/bin/sh
# C/Rust differential: search_report/d2k_diag_event на 6 событиях.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CC=${CC:-cc}
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-search-report.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra -ffunction-sections -fdata-sections \
    -I"$DONOR/core" -I"$DONOR/core/include" -I"$DONOR/datapath/include" \
    -I"$DONOR/runtime" -DD2K_RELEASE_ID='"dev"' \
    -o "$TEMP/c" \
    "$ROOT/crates/r2o-controller/tests/d2o_search_report_differential.c" \
    -Wl,--gc-sections -lpthread -lm
"$TEMP/c" >"$TEMP/c.out"
R2O_SEARCH_REPORT_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller search_report_events_match_c \
    >"$TEMP/rust.log" 2>&1
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'PASS: search_report events match C (%s).\n' "$ACTUAL_SHA"
