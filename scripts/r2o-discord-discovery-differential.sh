#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_core="${R2O_DONOR_CORE:-${r2o_script_dir%/*}/d2o/core}"
r2o_expected_donor_sha=${R2O_EXPECTED_DONOR_SHA:-304ba893dd37197128ac8799c0495b035f6a38c0}
r2o_actual_donor_sha=$(git -C "${r2o_donor_core%/core}" rev-parse HEAD)
if [ "$r2o_actual_donor_sha" != "$r2o_expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$r2o_expected_donor_sha" "$r2o_actual_donor_sha" >&2
    exit 2
fi
r2o_log_dir="${R2O_LOG_DIR:-$r2o_script_dir/.rea}"
r2o_log="$r2o_log_dir/r2o-discord-discovery-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-discord-discovery.XXXXXX")
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
    rm -rf -- "$r2o_tmp_dir"
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
        "$r2o_donor_core/voice.c" \
        "$r2o_donor_core/test_voice.c" \
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
        | grep -E 'FunctionDecl.*(voice_trial_send|voice_trial_same_context|voice_confirm|voice_pending_dispatch|on_applied|on_suspect|voice_fail|task_fail|d2k_sched_event|d2k_sched_tick)'
    printf '\nСборка тестов C\n'
    r2o_run_timed 'сборка тестов голоса C' make -C "$r2o_donor_core" \
        test_voice test_voice_discovery test_sched CC=clang-18
    printf '\nФункциональные тесты C\n'
    r2o_run_timed 'измерение голосового потока C' sh -c \
        "cd \"\$1\" && ./test_voice" sh "$r2o_donor_core"
    printf '\nТочное происхождение сохранённого Discord Discovery-префикса\n'
    if ! grep -Eq 'b->verified_by[[:space:]]*!=[[:space:]]*D2K_VERBY_VOICE_DISCOVERY' \
        "$r2o_donor_core/sched.c"; then
        printf 'Проверка известного префикса в C scheduler изменилась; обновите дифференциальный fixture.\n' >&2
        exit 2
    fi
    clang-18 -std=c99 -O2 -Wall -Wextra -Werror \
        -I"$r2o_donor_core/include" \
        "$r2o_script_dir/crates/r2o-controller/tests/d2o_voice_known_prefix_differential.c" \
        -o "$r2o_tmp_dir/d2o-voice-known-prefix"
    "$r2o_tmp_dir/d2o-voice-known-prefix" >"$r2o_tmp_dir/c-voice-known-prefix.out"
    if R2O_VOICE_KNOWN_PREFIX_DIFF_OUTPUT="$r2o_tmp_dir/rust-voice-known-prefix.out" \
        cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline \
            известный_voice_discovery_prefix_принимает_только_подтверждение_discovery \
            >"$r2o_tmp_dir/rust-voice-known-prefix.log" 2>&1; then
        cat "$r2o_tmp_dir/rust-voice-known-prefix.log"
    else
        cat "$r2o_tmp_dir/rust-voice-known-prefix.log"
        exit 1
    fi
    diff -u "$r2o_tmp_dir/c-voice-known-prefix.out" \
        "$r2o_tmp_dir/rust-voice-known-prefix.out"
    printf 'C/Rust сохранённый Discord Discovery-префикс совпадает с d2o %s.\n' \
        "$r2o_actual_donor_sha"
    r2o_run_timed 'тест Discord Discovery C' sh -c \
        "cd \"\$1\" && ./test_voice_discovery" sh "$r2o_donor_core"
    r2o_run_timed 'сценарии Discord в планировщике C' sh -c \
        "cd \"\$1\" && ./test_sched --voice-only" sh "$r2o_donor_core"
    r2o_voice_eintr_fixture="$r2o_script_dir/crates/r2o-controller/tests/fixtures/d2o_voice_poll_eintr.tsv"
    r2o_run_timed 'сборка voice poll EINTR fixture C' clang-18 -std=c99 -O2 \
        -Wall -Wextra -Werror -pthread -I"$r2o_donor_core/include" \
        "$r2o_script_dir/crates/r2o-controller/tests/d2o_voice_poll_eintr.c" \
        "$r2o_donor_core/voice.o" "$r2o_donor_core/voice_discovery.o" \
        "$r2o_donor_core/stun.o" "$r2o_donor_core/net4.o" \
        "$r2o_donor_core/tls13core.o" "$r2o_donor_core/crypto.o" \
        "$r2o_donor_core/x25519.o" "$r2o_donor_core/meas.o" \
        "$r2o_donor_core/libd2k_udp.a" -o "$r2o_tmp_dir/d2o-voice-poll-eintr"
    r2o_c_voice_eintr=$("$r2o_tmp_dir/d2o-voice-poll-eintr" "$r2o_voice_eintr_fixture")
    printf '%s\n' "$r2o_c_voice_eintr"
    printf '%s\n' "$r2o_c_voice_eintr" >"$r2o_tmp_dir/c-voice-eintr.out"
    printf '\nФункциональные тесты Rust\n'
    r2o_run_timed 'подтверждение адресного опыта Rust' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller --locked --offline \
        r2o_установка_voice_опыта_проверяет_ack_и_trial_id
    r2o_run_timed 'повтор после локального NAK голосового опыта Rust' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller --locked --offline \
        местный_voice_nak_не_блокирует_повтор_по_следующему_потоку
    r2o_run_timed 'продление Discord Discovery Rust' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller --locked --offline \
        r2o_voice_discovery_снимает_пробу_при_точном_nak_продления
    r2o_run_timed 'освобождение ожидающей voice-цели Rust' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller --locked --offline \
        ожидающая_voice_цель_освобождается_через_две_минуты
    r2o_run_timed 'отказ после молчания точного voice-потока Rust' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller --locked --offline \
        r2o_voice_watch_связывает_applied_с_точным_потоком_пробы
    r2o_run_timed 'алгоритм Discord Discovery Rust' cargo +1.98.0 test \
        -p r2o-controller --lib --locked --offline voice_discovery
    if R2O_VOICE_EINTR_OUTPUT="$r2o_tmp_dir/rust-voice-eintr.out" \
        CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/r2o-target}" \
        cargo +1.98.0 test -p r2o-controller --lib --locked --offline \
            voice_poll_interruption_matches_d2o_timeout -- --nocapture \
            >"$r2o_tmp_dir/rust-voice-eintr.log" 2>&1; then
        r2o_rust_voice_eintr_status=0
    else
        r2o_rust_voice_eintr_status=$?
    fi
    cat "$r2o_tmp_dir/rust-voice-eintr.log"
    if [ -f "$r2o_tmp_dir/rust-voice-eintr.out" ]; then
        diff -u "$r2o_tmp_dir/c-voice-eintr.out" "$r2o_tmp_dir/rust-voice-eintr.out"
    else
        printf 'Rust voice EINTR fixture produced no normalized result.\n' >&2
        exit 1
    fi
    [ "$r2o_rust_voice_eintr_status" -eq 0 ]
    printf 'C/Rust voice UDP poll EINTR result matches d2o %s.\n' \
        "$r2o_actual_donor_sha"
    r2o_run_timed 'измерение голосового потока Rust' cargo +1.98.0 test \
        -p r2o-controller --lib --locked --offline voice_measure
    r2o_run_timed 'fallback голоса после прямого Discovery Rust' cargo +1.98.0 test \
        -p r2o-controller --bin r2o-controller --locked --offline \
        discord_voice_после_continue_запускает_live_flow_fallback
    r2o_run_timed 'план измеренного voice-arm Rust' cargo +1.98.0 test \
        -p r2o-controller --lib --locked --offline measured_voice_arm_plan
    r2o_run_timed 'пакетное состояние Discord Rust' cargo +1.98.0 test \
        -p r2o-datapath --lib --locked --offline r2o_voice
    printf '\nПолная длительность набора: %s с\n' "$(( $(date +%s) - r2o_started_at ))"
} >"$r2o_log" 2>&1

grep -q 'voice scheduler: all checks passed' "$r2o_log"
grep -q 'голосовой путь: все проверки прошли' "$r2o_log"
grep -q 'C/Rust voice UDP poll EINTR result matches d2o' "$r2o_log"
grep -q 'r2o_установка_voice_опыта_проверяет_ack_и_trial_id .*ok' "$r2o_log"
grep -q 'выбирает_самый_нагруженный_поток_кроме_контрольного_сервера .*ok' "$r2o_log"
grep -q 'местный_voice_nak_не_блокирует_повтор_по_следующему_потоку .*ok' "$r2o_log"
grep -q 'r2o_voice_discovery_снимает_пробу_при_точном_nak_продления .*ok' "$r2o_log"
grep -q 'ожидающая_voice_цель_освобождается_через_две_минуты .*ok' "$r2o_log"
grep -q 'r2o_voice_watch_связывает_applied_с_точным_потоком_пробы .*ok' "$r2o_log"
grep -q 'discord_voice_после_continue_запускает_live_flow_fallback .*ok' "$r2o_log"
grep -q 'measured_voice_arm_plan_preserves_payload_copy_count_and_voice_shape .*ok' "$r2o_log"
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
rm -rf -- "$r2o_tmp_dir"
trap - EXIT
