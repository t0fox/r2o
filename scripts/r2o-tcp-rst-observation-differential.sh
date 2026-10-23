#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath="${R2O_DONOR_DATAPATH:-${r2o_script_dir%/*}/d2o/datapath}"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-tcp-rst-observation-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_started_at=$(date +%s)
r2o_cleanup() {
    r2o_status=$?
    if [ "$r2o_status" -ne 0 ] && [ -f "$r2o_log" ]; then
        cat "$r2o_log"
    fi
}
trap r2o_cleanup EXIT

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

if [ ! -d "$r2o_donor_datapath" ]; then
    printf 'Каталог исходников донора не найден: %s\n' "$r2o_donor_datapath" >&2
    exit 2
fi
mkdir -p "$r2o_log_dir"
{
    printf 'Проверка раннего TCP RST по результату донора: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники донора: %s\n' "$r2o_donor_datapath"
    printf '\nSHA-256 исходников сценария\n'
    sha256sum \
        "$r2o_donor_datapath/session.c" \
        "$r2o_donor_datapath/track.c" \
        "$r2o_donor_datapath/tls.c" \
        "$r2o_donor_datapath/journal.c" \
        "$r2o_donor_datapath/include/d2k_session.h" \
        "$r2o_donor_datapath/include/d2k_journal.h" \
        "$r2o_script_dir/crates/r2o-datapath/src/engine.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/flow_journal.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/main.rs"
    if [ -n "${R2O_EXPECTED_DONOR_SHA:-}" ] && \
        [ "$(git -C "$r2o_donor_datapath" rev-parse HEAD)" != "$R2O_EXPECTED_DONOR_SHA" ]; then
        printf 'Коммит донора отличается от закреплённого снимка\n' >&2
        exit 1
    fi
    printf '\nКонтрольные тесты исходников донора\n'
    r2o_run_timed 'пересборка и тестирование сессии донора' make -B -C "$r2o_donor_datapath" \
        test_session CC=clang-18
    printf '\nСценарий состояния TCP Rust\n'
    r2o_run_timed 'учёт раннего RST Rust' cargo +1.98.0 test \
        -p r2o-datapath --lib tcp_ранний_rst_создаёт_отдельное_наблюдение \
        --locked --offline -- --nocapture
    printf '\nСценарий runtime Rust\n'
    r2o_run_timed 'журналирование раннего RST Rust' cargo +1.98.0 test \
        -p r2o-datapath --bin r2o-datapath r2o_передаёт_ранний_rst_в_общий_журнал \
        --locked --offline -- --nocapture
} >"$r2o_log" 2>&1

r2o_expected_result='R2O_DIFF code=1 ttl=127 ref=124 tos=46 ipid=23063 planned=2 shape=2 client_is_low=1'
r2o_engine_result=$(grep '^R2O_DIFF ' "$r2o_log" | sed -n '1p')
r2o_runtime_result=$(grep '^R2O_DIFF ' "$r2o_log" | tail -n 1)
{
    printf '\nСравнение с отпечатком C-донора для указанного хэша session.c\n'
    printf 'C:             %s\nRust engine:   %s\nRust runtime:  %s\n' \
        "$r2o_expected_result" "$r2o_engine_result" "$r2o_runtime_result"
    if [ "$r2o_engine_result" != "$r2o_expected_result" ] || \
        [ "$r2o_runtime_result" != "$r2o_expected_result" ]; then
        printf 'Отпечаток Rust отличается от результата C-донора\n' >&2
        exit 1
    fi
    printf '\nПолная длительность набора: %s с\n' \
        "$(( $(date +%s) - r2o_started_at ))"
} >>"$r2o_log" 2>&1

grep -q 'tcp_ранний_rst_создаёт_отдельное_наблюдение .*ok' "$r2o_log"
grep -q 'r2o_передаёт_ранний_rst_в_общий_журнал .*ok' "$r2o_log"
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
