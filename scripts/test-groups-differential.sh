#!/bin/sh
# C/Rust differential: d2k_group_learn и d2k_group_restore.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-groups.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-groups" \
    "$ROOT/crates/r2o-controller/tests/d2o_groups_differential.c" \
    "$D2O_ROOT/core/groups.c" "$D2O_ROOT/core/domain.c"
"$TEMP/d2o-groups" >"$TEMP/c.out"

R2O_GROUPS_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib groups::tests::groups_learn_restore_trace_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: groups learn/restore differential\n' >&2
    exit 1
fi

printf 'scenarios=%s lines=%s\n' \
    "$(grep -c '^scenario' "$TEMP/c.out")" \
    "$(wc -l <"$TEMP/c.out")"
printf 'PASS: C/Rust group learn/restore match (D2O %s)\n' "$ACTUAL_D2O_SHA"
