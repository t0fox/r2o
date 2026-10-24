#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_repo_root=$r2o_script_dir
r2o_donor_core="${R2O_DONOR_CORE:-${r2o_repo_root%/*}/d2o/core}"
r2o_log_dir="$r2o_repo_root/.rea"
r2o_log="$r2o_log_dir/r2o-scheduler-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_started_at="$(date +%s)"

r2o_run_timed() {
    r2o_label=$1
    shift
    r2o_started=$(date +%s)
    if "$@"; then
        r2o_status=0
    else
        r2o_status=$?
    fi
    r2o_elapsed=$(( $(date +%s) - r2o_started ))
    printf '\nВремя %s: %s с (код %s)\n' "$r2o_label" "$r2o_elapsed" "$r2o_status"
    return "$r2o_status"
}

r2o_show_log_on_error() {
    r2o_status=$?
    if [ "$r2o_status" -ne 0 ] && [ -f "$r2o_log" ]; then
        cat "$r2o_log"
    fi
    exit "$r2o_status"
}
trap r2o_show_log_on_error EXIT

if [ ! -d "$r2o_donor_core" ]; then
    printf 'Каталог C-эталона не найден: %s\n' "$r2o_donor_core" >&2
    exit 2
fi
mkdir -p "$r2o_log_dir"
{
    printf 'Проверка планировщика R2O и C-эталона: %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники C: %s\n' "$r2o_donor_core"
    printf '\nSHA-256 исходников C\n'
    sha256sum "$r2o_donor_core/sched.c" "$r2o_donor_core/test_sched.c"
    printf '\nAST Clang 18: адресные пробы, очередь и уступка QUIC\n'
    clang-18 -std=c99 -pthread \
        -I"$r2o_donor_core/include" \
        -I"$r2o_donor_core/../datapath/include" \
        -DD2K_RELEASE_ID='"dev"' \
        -fsyntax-only -Xclang -ast-dump \
        "$r2o_donor_core/test_sched_quic_yield.c" 2>/dev/null \
        | grep -E 'FunctionDecl.*(quic_yield_tick|launch_or_queue|scenario)'
    clang-18 -std=gnu11 -pthread \
        -I"$r2o_donor_core/include" \
        -I"$r2o_donor_core/../datapath/include" \
        -DD2K_RELEASE_ID='"dev"' \
        -fsyntax-only -Xclang -ast-dump \
        "$r2o_donor_core/sched.c" 2>/dev/null \
        | grep -E 'FunctionDecl.*(addr_probe_remove|candidate_retire|task_fail|launch_or_queue|d2k_sched_tick)'
    printf '\nТесты планировщика C-эталона\n'
    if [ "${R2O_SKIP_FULL_C_SCHEDULER:-0}" = 1 ]; then
        r2o_run_timed 'сборка теста уступки C' make -B -C "$r2o_donor_core" test_sched_quic_yield CC=clang-18
    else
        r2o_run_timed 'сборка тестов планировщика C' make -B -C "$r2o_donor_core" \
            test_sched_quic_yield test_sched CC=clang-18
    fi
    r2o_run_timed 'тест уступки C' sh -c 'cd "$1" && ./test_sched_quic_yield' sh "$r2o_donor_core"
    if [ "${R2O_SKIP_FULL_C_SCHEDULER:-0}" = 1 ]; then
        r2o_sched_sha256=$(sha256sum "$r2o_donor_core/sched.c" | awk '{print $1}')
        r2o_test_sched_sha256=$(sha256sum "$r2o_donor_core/test_sched.c" | awk '{print $1}')
        if [ "$r2o_sched_sha256" != cc533a9c39c364104ae12d281c10dfffaee1aa8948c523f0bf15603915f88a32 ] \
            || [ "$r2o_test_sched_sha256" != 837b2d4e7d3a87ff7feb4e087613964376963d2e32c108da3551b6d2aedf99b3 ]; then
            printf 'Ускоренный режим запрещён: SHA-256 C-эталона отличаются от полностью проверенных.\n' >&2
            exit 2
        fi
        printf 'Полный набор test_sched пропущен: оба SHA-256 совпали с полностью проверенным C-эталоном.\n'
    else
        r2o_run_timed 'сценарии планировщика C' sh -c \
            "cd \"\$1\" && ./test_sched" sh "$r2o_donor_core"
        printf 'Полный test_sched включает lifecycle очереди и параллельные адресные пробы.\n'
    fi
    printf '\nПроверка срока ожидания в R2O\n'
    r2o_run_timed 'срок очереди R2O' cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
        --locked r2o_discovery_queued_target_expires
    r2o_run_timed 'жизнь worker после очистки очереди' cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
        --locked r2o_discovery_expiration_releases_target_and_keeps_worker_alive
    printf '\nСценарий QUIC worker и приёма TCP в R2O\n'
    r2o_run_timed 'сценарий QUIC worker' cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
        --locked r2o_quic_подбор -- --nocapture
    printf '\nРазделение APPLIED по идентификатору пробы в R2O\n'
    r2o_run_timed 'разделение APPLIED' cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
        --locked r2o_quic_applied_collection -- --nocapture
    printf '\nСохранение подтверждённого QUIC-плана в R2O\n'
    r2o_run_timed 'сохранение QUIC-плана' cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
        --locked r2o_quic_ech_подтверждение_сохраняет_адресную_привязку -- --nocapture
    r2o_run_timed 'параллельные адресные опыты QUIC' cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
        --locked r2o_quic_worker_одновременно_изолирует_два_адресных_опыта -- --nocapture
    printf '\nТесты QUIC-логики и уступки слота в R2O\n'
    r2o_run_timed 'тесты QUIC' cargo +1.98.0 test -p r2o-controller --lib --locked r2o_quic -- --nocapture
    printf '\nПолная длительность набора: %s с\n' "$(( $(date +%s) - r2o_started_at ))"
} >"$r2o_log" 2>&1

grep -q 'QUIC question yield: 0 failures' "$r2o_log"
grep -q 'r2o_quic_подбор_удаляет_все_пробы_без_двух_доказательств .*ok' "$r2o_log"
grep -q 'r2o_quic_applied_collection_keeps_events_for_other_trials .*ok' "$r2o_log"
grep -q 'r2o_quic_ech_подтверждение_сохраняет_адресную_привязку .*ok' "$r2o_log"
grep -q 'r2o_quic_worker_одновременно_изолирует_два_адресных_опыта .*ok' "$r2o_log"
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
