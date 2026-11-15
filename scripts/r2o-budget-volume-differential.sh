#!/bin/sh
# C/Rust differential: budget_cut_reject при измеренном объёмном обрыве
# (t->vol.rx_cut=1) — лучший partial, один план, бюджет «оборван».
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
TEMP=$(mktemp -d "$TMPDIR/r2o-budget-volume.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -s -C "$DONOR/core" test_sched CC="$CC" >/dev/null
SCHED_OBJ=$(make -C "$DONOR/core" -pn 2>/dev/null |
    sed -n 's/^SCHED_TEST_OBJ = //p' | head -1 |
    sed 's/ sched\.o / /')
[ -n "$SCHED_OBJ" ] || {
    echo "не удалось прочитать SCHED_TEST_OBJ" >&2
    exit 2
}
(
    cd "$DONOR/core"
    "$CC" -std=gnu11 -O2 -Wall -Wextra \
        -I. -Iinclude -I../datapath/include -I../runtime \
        -o "$TEMP/c" \
        "$ROOT/crates/r2o-controller/tests/d2o_budget_volume_differential.c" \
        $SCHED_OBJ diagnostics.o libd2k_udp.a -lpthread -lm
)
"$TEMP/c" shared >"$TEMP/c.out"
"$TEMP/c" >"$TEMP/c.full"
R2O_BUDGET_VOLUME_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    tests::budget_volume_partial_finish_matches_c -- --exact \
    >"$TEMP/rust.log" 2>&1
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'C-оракул (state/trial/verfd/revision/sync):\n'
grep 'state=' "$TEMP/c.full"
printf 'PASS: budget_cut_reject volume_block partial_finish matches C (%s).\n' \
    "$ACTUAL_SHA"
