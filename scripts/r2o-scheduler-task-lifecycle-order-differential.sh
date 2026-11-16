#!/bin/sh
# C/Rust differential: порядок терминальной жизни scheduler-задачи.
#
# C: production task_reset/local-abort, task_done/cancelled,
# task_fail/failed, d2k_sched_free/shutdown из core/sched.c. Наблюдаются
# отчёт (id/outcome/path/probe_units/queue), однократность, состояние слота,
# join worker'а до отчёта, закрытие fd, порядок отчётов по слотам и счётчики
# madvise(MADV_DONTNEED).
#
# Rust: production update/report_terminal/r2o_finish_watching_task/
# r2o_complete_outcome/report_shutdown_in_slot_order + Drop for
# DiscoveryWorker. У Rust нет per-task fd и madvise: это архитектурное
# отличие, ресурсные строки C и Rust печатаются отдельно и не подгоняются.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-scheduler-lifecycle.XXXXXX")
if [ "${KEEP_TEMP:-0}" = 1 ]; then
    printf 'TEMP=%s\n' "$TEMP"
else
    trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
fi

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
        "$ROOT/crates/r2o-controller/tests/d2o_scheduler_task_lifecycle_differential.c" \
        $SCHED_OBJ diagnostics.o libd2k_udp.a -lpthread -lm
)
"$TEMP/c" "$TEMP/c.resources" >"$TEMP/c.out"
R2O_SCHED_LIFECYCLE_DIFF_OUTPUT="$TEMP/rust.out" \
R2O_SCHED_LIFECYCLE_RESOURCES_OUTPUT="$TEMP/rust.resources" \
    cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    tests::scheduler_task_lifecycle_order_matches_c -- --exact \
    >"$TEMP/rust.log" 2>&1
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf '%s\n' '--- C resources (production fds/join/madvise) ---'
cat "$TEMP/c.resources"
printf '%s\n' '--- Rust resources (RAII/no pending fd/no madvise) ---'
cat "$TEMP/rust.resources"
printf 'PASS: scheduler task lifecycle order matches C (%s).\n' "$ACTUAL_SHA"
