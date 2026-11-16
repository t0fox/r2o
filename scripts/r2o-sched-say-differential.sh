#!/bin/sh
# C/Rust differential: d2kc `sched_say` — локальный префикс `ЧЧ:ММ:СС` и
# перевод строки. C-оракул — production-функция из d2kc.c; Rust —
# production `sched_log::r2o_sched_say_at`.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CORE="$DONOR/core"
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-sched-say.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

# d2kc.c тянет весь контроллер; линкуются только реально нужные секции.
clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$CORE" -I"$CORE/include" -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
    -DD2K_RELEASE_ID='"dev"' \
    "$ROOT/crates/r2o-controller/tests/d2o_sched_say_differential.c" \
    -Wl,--gc-sections -lpthread -o "$TEMP/c"

# Если между `time(NULL)` до и после вызова сменилась секунда, берём
# следующий запуск: иначе timestamp нельзя однозначно сопоставить epoch.
attempt=0
while [ "$attempt" -lt 50 ]; do
    "$TEMP/c" >"$TEMP/c.out"
    window=$(tail -n 1 "$TEMP/c.out")
    before=$(printf '%s\n' "$window" | cut -d' ' -f2)
    after=$(printf '%s\n' "$window" | cut -d' ' -f3)
    [ "$before" = "$after" ] && break
    attempt=$((attempt + 1))
done
[ "$before" = "$after" ] || {
    printf 'FAIL: не удалось получить sched_say внутри одной секунды\n' >&2
    exit 1
}
head -n 1 "$TEMP/c.out" >"$TEMP/c.line"

TZ=UTC0 R2O_SCHED_SAY_EPOCH="$before" \
    R2O_SCHED_SAY_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --locked -p r2o-controller --lib \
    sched_log::tests::sched_say_matches_c -- --exact \
    >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }
diff -u "$TEMP/c.line" "$TEMP/rust.out"
printf 'PASS: sched_say timestamp matches C (%s, epoch %s)\n' \
    "$ACTUAL_SHA" "$before"
