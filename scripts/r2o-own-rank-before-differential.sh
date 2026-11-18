#!/bin/sh
# C/Rust differential: own_rank_before (core/sched.c).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CC=${CC:-clang-18}
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-own-rank.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

(
    cd "$DONOR/core"
    "$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
        -ffunction-sections -fdata-sections -pthread \
        -I. -Iinclude -I../datapath/include -I../runtime \
        -DD2K_RELEASE_ID='"dev"' \
        -o "$TEMP/c" \
        "$ROOT/crates/r2o-controller/tests/d2o_own_rank_before_differential.c" \
        -Wl,--gc-sections
)
"$TEMP/c" >"$TEMP/c.out"
R2O_OWN_RANK_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib own_rank_before_matches_c >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }
diff -u "$TEMP/c.out" "$TEMP/rust.out"
cat "$TEMP/c.out"
printf 'PASS: own_rank_before matches C (D2O %s)\n' "$ACTUAL_SHA"
