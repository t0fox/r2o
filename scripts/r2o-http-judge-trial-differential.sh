#!/bin/sh
# C/Rust differential: production `judge_trial` (core/httpsearch.c:902-955).
#
# Побочные `next_candidate`/`confirmed` в копии C-файла переименованы в
# `unused_*`: differential сравнивает решение judge_trial (next/repeat/
# confirmed, ok/had/retried), а не весь цикл поиска. `trial_executed`,
# `say` и `d2k_hs_answer_name` остаются production.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-http-judge-trial.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

# Переименовываем только определения; forward declaration next_candidate
# и все вызовы остаются, поэтому вызовы связываются со стендовыми заглушками.
sed \
    -e 's/^static void next_candidate(d2k_httpsearch \*hs, int64_t now) {$/static void unused_next_candidate(d2k_httpsearch *hs, int64_t now) {/' \
    -e 's/^static void confirmed(d2k_httpsearch \*hs, int64_t now) {$/static void unused_confirmed(d2k_httpsearch *hs, int64_t now) {/' \
    "$CORE/httpsearch.c" >"$TEMP/httpsearch.c"

grep -q 'static void unused_next_candidate' "$TEMP/httpsearch.c" || {
    printf 'FAIL: next_candidate definition was not renamed\n' >&2
    exit 1
}
grep -q 'static void unused_confirmed' "$TEMP/httpsearch.c" || {
    printf 'FAIL: confirmed definition was not renamed\n' >&2
    exit 1
}

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror \
    -Wno-unused-function -Wno-unused-variable \
    -ffunction-sections -fdata-sections \
    -I"$TEMP" -I"$CORE" -I"$CORE/include" \
    -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
    -DD2K_RELEASE_ID='"dev"' \
    "$ROOT/crates/r2o-controller/tests/d2o_http_judge_trial_differential.c" \
    -Wl,--gc-sections -lpthread -lm -o "$TEMP/c"

"$TEMP/c" >"$TEMP/c.raw"
# split_no/checksum_no/nextq — только C-side evidence, не сравниваются.
sed 's/ split_no=.*$//' "$TEMP/c.raw" >"$TEMP/c.out"

R2O_HTTP_JUDGE_TRIAL_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --locked -p r2o-controller --bin r2o-controller \
    tests::judge_trial_decisions_match_c -- --exact \
    >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'PASS: judge_trial decisions match C (%s, %s cases)\n' \
    "$ACTUAL_SHA" "$(wc -l <"$TEMP/c.out" | tr -d ' ')"
