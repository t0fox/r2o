#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_core="${R2O_DONOR_CORE:-${r2o_script_dir%/*}/d2o/core}"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-discovery-active-lifetime-$(date +%Y%m%d-%H%M%S).log"
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

if [ ! -d "$r2o_donor_core" ]; then
    printf 'Каталог C-эталона не найден: %s\n' "$r2o_donor_core" >&2
    exit 2
fi
mkdir -p "$r2o_log_dir"
{
    printf 'Проверка срока жизни активного поиска R2O: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники C: %s\n' "$r2o_donor_core"
    printf '\nSHA-256 исходников C\n'
    sha256sum "$r2o_donor_core/sched.c" "$r2o_donor_core/test_sched.c"
    printf '\nREA Evidence донора C, повторный анализ не требуется\n'
    printf 'd2k_sched_tick: ev_6b7ca72b0f54798a1acf229b959f38478a2c0e4ee381a32ae9ff924e12d2f166\n'
    printf '\nAST Clang 18: срок активной задачи\n'
    clang-18 -std=gnu11 -pthread \
        -I"$r2o_donor_core/include" \
        -I"$r2o_donor_core/../datapath/include" \
        -DD2K_RELEASE_ID='"dev"' \
        -fsyntax-only -Xclang -ast-dump "$r2o_donor_core/sched.c" 2>/dev/null \
        | grep -E 'FunctionDecl.*d2k_sched_tick'
    printf '\nСценарий срока активного поиска C-эталона\n'
    r2o_run_timed 'сборка планировщика C' make -C "$r2o_donor_core" test_sched CC=clang-18
    r2o_run_timed 'жизненный цикл планировщика C' \
        "$r2o_donor_core/test_sched" --lifecycle-only
    printf '\nСценарий отмены и срока Discovery R2O\n'
    r2o_run_timed 'истечение срока активного поиска' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller \
        r2o_активный_поиск_отменяется_по_сроку_жизни --locked --offline
    r2o_run_timed 'остановка worker при работающем поиске' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller \
        остановка_контроллера_прерывает_поиск_без_метки_таймаута --locked --offline
    r2o_run_timed 'снятие цели и повтор через 10 минут' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller \
        r2o_таймаут_активного_поиска_освобождает_цель_для_нового_поколения --locked --offline
    printf '\nПолная длительность набора: %s с\n' "$(( $(date +%s) - r2o_started_at ))"
} >"$r2o_log" 2>&1

grep -q 'планировщик: все проверки прошли' "$r2o_log"
grep -q 'r2o_активный_поиск_отменяется_по_сроку_жизни .*ok' "$r2o_log"
grep -q 'остановка_контроллера_прерывает_поиск_без_метки_таймаута .*ok' "$r2o_log"
grep -q 'r2o_таймаут_активного_поиска_освобождает_цель_для_нового_поколения .*ok' "$r2o_log"
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
