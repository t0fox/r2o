#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath="${R2O_DONOR_DATAPATH:-${r2o_script_dir%/*}/d2o/datapath}"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-tcp-rst-cut-differential-$(date +%Y%m%d-%H%M%S).log"
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
    printf 'Дифференциальная проверка защитного снятия TCP RST: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники C: %s\n' "$r2o_donor_datapath"
    printf '\nSHA-256 источников сценария\n'
    sha256sum \
        "$r2o_donor_datapath/session.c" \
        "$r2o_donor_datapath/test_session.c" \
        "$r2o_script_dir/crates/r2o-datapath/src/engine.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/flow_journal.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/main.rs"
    printf '\nAST Clang 18: обработчик TCP-сессии C\n'
    clang-18 -std=c99 \
        -I"$r2o_donor_datapath/include" \
        -I"$r2o_donor_datapath/../core/include" \
        -DD2K_RELEASE_ID='"dev"' \
        -fsyntax-only -Xclang -ast-dump "$r2o_donor_datapath/session.c" 2>/dev/null \
        | grep -E 'FunctionDecl.*(session_packet|d2k_session_packet)'
    printf '\nПроверка сценария C\n'
    r2o_run_timed 'сборка и тесты TCP-сессии C' make -B -C "$r2o_donor_datapath" \
        test-session CC=clang-18
    printf '\nПроверка состояния TCP Rust\n'
    r2o_run_timed 'детектор RST-CUT Rust' cargo +1.98.0 test \
        -p r2o-datapath --lib \
        rst_alien_guard_журналирует_чужой_сброс_до_ответа_один_раз \
        --locked --offline
    printf '\nПроверка передачи события runtime Rust\n'
    r2o_run_timed 'передача RST-CUT в общий журнал Rust' cargo +1.98.0 test \
        -p r2o-datapath --bin r2o-datapath \
        app::tests::r2o_передаёт_снятый_чужой_rst_из_runtime_в_общий_журнал \
        --locked --offline
    printf '\nПолная длительность набора: %s с\n' "$(( $(date +%s) - r2o_started_at ))"
} >"$r2o_log" 2>&1

grep -q 'сессия: все проверки прошли' "$r2o_log"
grep -q 'rst_alien_guard_журналирует_чужой_сброс_до_ответа_один_раз .*ok' "$r2o_log"
grep -q 'r2o_передаёт_снятый_чужой_rst_из_runtime_в_общий_журнал .*ok' "$r2o_log"
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
