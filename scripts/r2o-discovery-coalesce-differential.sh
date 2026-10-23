#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_core="${R2O_DONOR_CORE:-${r2o_script_dir%/*}/d2o/core}"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-discovery-coalesce-differential-$(date +%Y%m%d-%H%M%S).log"
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
    printf 'Сопоставление C и Rust для объединения задач Discovery: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники C: %s\n' "$r2o_donor_core"
    printf '\nSHA-256 источников сценария\n'
    sha256sum \
        "$r2o_donor_core/sched.c" \
        "$r2o_donor_core/test_sched.c" \
        "$r2o_script_dir/crates/r2o-controller/src/main.rs"
    printf '\nREA-досье донора\n'
    printf 'on_suspect: ev_900fc34ded606784d81e0618b916b7a8357c409f538e48f9a4ddf75be264bcba\n'
    printf 'cooldown_blocks: ev_49c6a51306558aa30e25ae5f8082ef339e5bab99768d9ad04d929e914ec2fa93\n'
    printf 'cooldown_find_endpoint: ev_5d7c7057c481d8179105690580428a58f37e6acdb7f45755e681056700a753be\n'
    printf 'DiscoveryWorker::queue: ev_b58bde809a5c0081970352452a6214cf9f323595feee5323f988bb3678a8ef52\n'
    printf '\nСборка и приёмочные проверки планировщика C\n'
    r2o_run_timed 'сборка планировщика C' make -C "$r2o_donor_core" test_sched CC=clang-18
    r2o_run_timed 'приёмочные проверки планировщика C' "$r2o_donor_core/test_sched" --admission-only
    printf '\nПроверка слияния активных задач Rust\n'
    r2o_run_timed 'слияние очереди Discovery Rust' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller \
        r2o_discovery_сливает_endpoint_до_исхода_задачи_имени --locked --offline
    printf '\nРаздельное ведение TCP- и QUIC-задач C/Rust\n'
    r2o_run_timed 'разделение транспорта Discovery Rust' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller \
        r2o_discovery_keeps_tcp_and_quic_tasks_for_the_same_name_separate --locked --offline
    printf '\nУдержание подтверждённой задачи до повторного отказа\n'
    r2o_run_timed 'повтор успешной задачи Discovery Rust' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller \
        r2o_discovery_success_suppresses_other_endpoints_for_same_name_and_transport --locked --offline
    printf '\nПроверка ограничения повторов конечной точки в Rust\n'
    r2o_run_timed 'повтор конечной точки Discovery Rust' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller \
        r2o_discovery_failure_cooldown_ключует_endpoint_без_shape --locked --offline
    printf '\nПолная длительность набора: %s с\n' "$(( $(date +%s) - r2o_started_at ))"
} >"$r2o_log" 2>&1

grep -q 'measurement admission: all checks passed' "$r2o_log"
grep -q 'r2o_discovery_сливает_endpoint_до_исхода_задачи_имени .*ok' "$r2o_log"
grep -q 'r2o_discovery_keeps_tcp_and_quic_tasks_for_the_same_name_separate .*ok' "$r2o_log"
grep -q 'r2o_discovery_success_suppresses_other_endpoints_for_same_name_and_transport .*ok' "$r2o_log"
grep -q 'r2o_discovery_failure_cooldown_ключует_endpoint_без_shape .*ok' "$r2o_log"
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
