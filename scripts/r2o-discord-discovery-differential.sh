#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_core="${R2O_DONOR_CORE:-${r2o_script_dir%/*}/d2o/core}"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-discord-discovery-differential-$(date +%Y%m%d-%H%M%S).log"
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
    printf 'Дифференциальная проверка Discord Discovery: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники C: %s\n' "$r2o_donor_core"
    printf '\nSHA-256 исходников C\n'
    sha256sum "$r2o_donor_core/sched.c" \
        "$r2o_donor_core/test_sched.c" \
        "$r2o_donor_core/voice_discovery.c" \
        "$r2o_donor_core/test_voice_discovery.c" \
        "$r2o_donor_core/stun.c"
    printf '\nAST Clang 18: поиск и проверка Discovery\n'
    clang-18 -std=gnu11 -pthread \
        -I"$r2o_donor_core/include" \
        -I"$r2o_donor_core/../datapath/include" \
        -fsyntax-only -Xclang -ast-dump \
        "$r2o_donor_core/voice_discovery.c" 2>/dev/null \
        | grep -E 'FunctionDecl.*(d2k_discovery_response|d2k_voice_discovery_search|discovery_probe)'
    clang-18 -std=gnu11 -pthread \
        -I"$r2o_donor_core/include" \
        -I"$r2o_donor_core/../datapath/include" \
        -DD2K_RELEASE_ID='"dev"' \
        -fsyntax-only -Xclang -ast-dump \
        "$r2o_donor_core/sched.c" 2>/dev/null \
        | grep -E 'FunctionDecl.*(voice_trial_send|voice_trial_same_context|voice_confirm|voice_pending_dispatch|d2k_sched_event|d2k_sched_tick)'
    printf '\nСборка тестов C\n'
    r2o_run_timed 'сборка тестов голоса C' make -C "$r2o_donor_core" \
        test_voice_discovery test_sched CC=clang-18
    printf '\nФункциональные тесты C\n'
    r2o_run_timed 'тест Discord Discovery C' sh -c \
        "cd \"\$1\" && ./test_voice_discovery" sh "$r2o_donor_core"
    r2o_run_timed 'сценарии Discord в планировщике C' sh -c \
        "cd \"\$1\" && ./test_sched --voice-only" sh "$r2o_donor_core"
    printf '\nФункциональные тесты Rust\n'
    r2o_run_timed 'подтверждение адресного опыта Rust' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller --locked --offline \
        r2o_установка_voice_опыта_проверяет_ack_и_trial_id
    r2o_run_timed 'продление Discord Discovery Rust' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller --locked --offline \
        r2o_voice_discovery_продлевает_пробу_тем_же_id_до_срока_задачи
    r2o_run_timed 'алгоритм Discord Discovery Rust' cargo +1.98.0 test \
        -p r2o-controller --lib --locked --offline voice_discovery
    r2o_run_timed 'пакетное состояние Discord Rust' cargo +1.98.0 test \
        -p r2o-datapath --lib --locked --offline r2o_voice
    printf '\nПолная длительность набора: %s с\n' "$(( $(date +%s) - r2o_started_at ))"
} >"$r2o_log" 2>&1

grep -q 'voice scheduler: all checks passed' "$r2o_log"
grep -q 'r2o_установка_voice_опыта_проверяет_ack_и_trial_id .*ok' "$r2o_log"
grep -q 'r2o_voice_discovery_продлевает_пробу_тем_же_id_до_срока_задачи .*ok' "$r2o_log"
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
