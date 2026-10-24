#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_core="${R2O_DONOR_CORE:-${r2o_script_dir%/*}/d2o/core}"
r2o_donor_datapath="${R2O_DONOR_DATAPATH:-${r2o_donor_core%/core}/datapath}"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-ask-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_started_at=$(date +%s)

r2o_run_timed() {
    r2o_label=$1
    shift
    r2o_started=$(date +%s)
    if "$@"; then
        r2o_status=0
    else
        r2o_status=$?
    fi
    printf '\nВремя %s: %s с (код %s)\n' \
        "$r2o_label" "$(( $(date +%s) - r2o_started ))" "$r2o_status"
    return "$r2o_status"
}

r2o_show_log_on_error() {
    r2o_status=$?
    if [ "$r2o_status" -ne 0 ] && [ -f "$r2o_log" ]; then
        cat "$r2o_log"
    fi
}
trap r2o_show_log_on_error EXIT

if [ ! -d "$r2o_donor_core" ] || [ ! -d "$r2o_donor_datapath" ]; then
    printf 'Каталог C-эталона или datapath не найден: %s %s\n' \
        "$r2o_donor_core" "$r2o_donor_datapath" >&2
    exit 2
fi
mkdir -p "$r2o_log_dir"
{
    printf 'Дифференциальная проверка Ask: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники C core: %s\n' "$r2o_donor_core"
    printf 'Исходники C datapath: %s\n' "$r2o_donor_datapath"
    printf '\nSHA-256 исходников C\n'
    sha256sum "$r2o_donor_core/d2kask.c" \
        "$r2o_donor_core/test_d2kask.c" \
        "$r2o_donor_core/compose.c" \
        "$r2o_donor_core/hello.c" \
        "$r2o_donor_core/link.c" \
        "$r2o_donor_datapath/ctlprobe.c"
    printf '\nСборка C CLI и тестового control datapath\n'
    r2o_run_timed 'сборка d2kask и C теста' make -C "$r2o_donor_core" \
        d2kask test_d2kask CC=clang-18
    r2o_run_timed 'сборка ctlprobe' make -C "$r2o_donor_datapath" \
        ctlprobe CC=clang-18
    printf '\nФункциональный тест C Ask\n'
    r2o_run_timed 'тест d2kask C' sh -c \
        "cd \"\$1\" && ./test_d2kask" sh "$r2o_donor_core"
    printf '\nФункциональные тесты Rust Ask\n'
    r2o_run_timed 'тесты Rust ask' cargo +1.98.0 test \
        -p r2o-controller --lib --locked --offline ask::tests
    printf '\nПолная длительность набора: %s с\n' "$(( $(date +%s) - r2o_started_at ))"
} >"$r2o_log" 2>&1

grep -q 'd2kask: все проверки прошли' "$r2o_log"
grep -q 'test result: ok\. 9 passed; 0 failed' "$r2o_log"
grep -q 'question_order_and_plan_parameters_match_the_five_donor_probes .*ok' "$r2o_log"
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
