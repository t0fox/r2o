#!/bin/sh
# C/Rust differential: терминальные отчёты scheduler.
# C: task_reset/local-abort, task_fail/failed, task_done/cancelled,
# remeasure_snapped/superseded, d2k_sched_free/shutdown.
# Rust: production update/report_terminal/reset_for_remeasure/
# r2o_complete_outcome/report_shutdown.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-scheduler-terminal.XXXXXX")
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
        "$ROOT/crates/r2o-controller/tests/d2o_scheduler_terminal_report_differential.c" \
        $SCHED_OBJ diagnostics.o libd2k_udp.a -lpthread -lm
)
"$TEMP/c" >"$TEMP/c.out"
R2O_SCHED_TERMINAL_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    tests::scheduler_terminal_reports_match_c -- --exact \
    >"$TEMP/rust.log" 2>&1
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: scheduler terminal reports match C (%s).\n' "$ACTUAL_SHA"
