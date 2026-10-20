#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath="${R2O_DONOR_DATAPATH:-${r2o_script_dir%/*}/d2o/datapath}"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-udp-exchange-differential-$(date +%Y%m%d-%H%M%S).log"
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

if [ ! -d "$r2o_donor_datapath" ]; then
    printf 'Каталог C-эталона не найден: %s\n' "$r2o_donor_datapath" >&2
    exit 2
fi
mkdir -p "$r2o_log_dir"
{
    printf 'Дифференциальная проверка первой обратной UDP-датаграммы: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники C: %s\n' "$r2o_donor_datapath"
    printf '\nSHA-256 исходников C\n'
    sha256sum "$r2o_donor_datapath/session.c" \
        "$r2o_donor_datapath/test_quic_session.c" \
        "$r2o_donor_datapath/include/d2k_journal.h"
    printf '\nAST Clang 18: обработчик UDP\n'
    clang-18 -std=c99 \
        -I"$r2o_donor_datapath/include" \
        -I"$r2o_donor_datapath/../core/include" \
        -DD2K_RELEASE_ID='"dev"' \
        -fsyntax-only -Xclang -ast-dump "$r2o_donor_datapath/session.c" 2>/dev/null \
        | grep -E 'FunctionDecl.*handle_udp'
    printf '\nТесты сценариев QUIC в C-эталоне\n'
    r2o_run_timed 'сборка и тесты QUIC-сессии C' make -C "$r2o_donor_datapath" \
        test-quic-session CC=clang-18
    printf '\nПервая обратная UDP-датаграмма Rust\n'
    r2o_run_timed 'событие первой QUIC-датаграммы Rust' cargo +1.98.0 test \
        -p r2o-datapath --lib quic_журналирует_только_первую_обратную_датаграмму_включая_пустую \
        --locked --offline
    r2o_run_timed 'кодирование UDP-обмена Rust' cargo +1.98.0 test \
        -p r2o-datapath --test flow_journal \
        запись_udp_обмена_сохраняет_первый_ответ_и_длину_пустой_датаграммы \
        --locked --offline
    r2o_run_timed 'подключение UDP-обмена к runtime Rust' cargo +1.98.0 test \
        -p r2o-datapath --bin r2o-datapath \
        app::tests::r2o_передаёт_первый_udp_ответ_из_runtime_в_общий_журнал \
        --locked --offline
    printf '\nПолная длительность набора: %s с\n' "$(( $(date +%s) - r2o_started_at ))"
} >"$r2o_log" 2>&1

grep -q 'quic_журналирует_только_первую_обратную_датаграмму_включая_пустую .*ok' "$r2o_log"
grep -q 'запись_udp_обмена_сохраняет_первый_ответ_и_длину_пустой_датаграммы .*ok' "$r2o_log"
grep -q 'r2o_передаёт_первый_udp_ответ_из_runtime_в_общий_журнал .*ok' "$r2o_log"
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
