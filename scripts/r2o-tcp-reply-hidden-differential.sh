#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath="${R2O_DONOR_DATAPATH:-${r2o_script_dir%/*}/d2o/datapath}"
r2o_donor_test="$r2o_donor_datapath/test_session"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-tcp-reply-hidden-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_started_at=$(date +%s)
r2o_upstream_sha=a378e230947ebfd011439e1cac0f1e994d883aae

r2o_show_log_on_error() {
    r2o_status=$?
    if [ "$r2o_status" -ne 0 ] && [ -f "$r2o_log" ]; then
        cat "$r2o_log"
    fi
}
trap r2o_show_log_on_error EXIT

if [ "${R2O_EXPECTED_DONOR_SHA:-}" != "$r2o_upstream_sha" ]; then
    printf 'TCP reply-visibility differential requires pinned upstream donor %s\n' \
        "$r2o_upstream_sha" >&2
    exit 2
fi

r2o_actual_donor_sha=$(git -C "$r2o_donor_datapath" rev-parse HEAD)
if [ "$r2o_actual_donor_sha" != "$r2o_upstream_sha" ]; then
    printf 'TCP reply-visibility requires donor checkout %s, got %s\n' \
        "$r2o_upstream_sha" "$r2o_actual_donor_sha" >&2
    exit 2
fi
if ! git -C "$r2o_donor_datapath" diff --quiet HEAD -- || \
    ! git -C "$r2o_donor_datapath" diff --cached --quiet HEAD --; then
    printf 'Donor worktree has tracked changes; refusing unpinned C sources\n' >&2
    exit 2
fi

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

if ! grep -q 'test_reply_hidden_by_accelerator' "$r2o_donor_datapath/test_session.c"; then
    printf 'В контрольном исходнике донора нет теста скрытого ответа\n' >&2
    exit 2
fi

mkdir -p "$r2o_log_dir"
{
    printf 'Сверка видимости TCP-ответа: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники донора: %s\n' "$r2o_donor_datapath"
    printf '\nSHA-256 закреплённых C-исходников и Rust-реализации\n'
    sha256sum \
        "$r2o_donor_datapath/session.c" \
        "$r2o_donor_datapath/test_session.c" \
        "$r2o_script_dir/crates/r2o-datapath/src/engine.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/main.rs"
    r2o_session_sha256=$(sed 's/\r$//' "$r2o_donor_datapath/session.c" | sha256sum | awk '{print $1}')
    r2o_test_sha256=$(sed 's/\r$//' "$r2o_donor_datapath/test_session.c" | sha256sum | awk '{print $1}')
    if [ "$r2o_session_sha256" != \
        '30def3c2ed70900d6ce9ab6bacafa781553b5edfa5a699083284281c3a11c154' ] || \
        [ "$r2o_test_sha256" != \
        '8fcf2f4d1e0aa908e65b051b18f6fde2e1899f060ccda9463e66c184dae23996' ]; then
        printf 'Исходники донора отличаются от проверенного снимка\n' >&2
        exit 1
    fi
    printf '\nСборка C-контроля из закреплённого donor commit\n'
    r2o_run_timed 'сборка C test_session' make -B -C "$r2o_donor_datapath" \
        test_session CC=clang-18
    sha256sum "$r2o_donor_test"
    printf '\nЗапуск C-контроля донора\n'
    r2o_run_timed 'контрольная сессия донора' "$r2o_donor_test"
    printf '\nДифференциальные тесты состояния Rust\n'
    r2o_run_timed 'счётчик невидимого ответа и TCP-состояние Rust' cargo +1.98.0 test \
        -p r2o-datapath --lib r2o_tcp_ --locked --offline -- --nocapture
    r2o_run_timed 'исключение зондов по метке в runtime Rust' cargo +1.98.0 test \
        -p r2o-datapath --bin r2o-datapath \
        r2o_метка_контроллера_исключает_зондовые_пакеты_из_состояния_datapath \
        --locked --offline -- --nocapture
    printf '\nПолная длительность набора: %s с\n' \
        "$(( $(date +%s) - r2o_started_at ))"
} >"$r2o_log" 2>&1

grep -q 'сессия: все проверки прошли' "$r2o_log"
grep -Fq 'r2o_tcp_учитывает_невидимый_ответ_один_раз_по_продвинутому_ack' "$r2o_log"
grep -Fq 'r2o_tcp_не_считает_видимый_ответ_и_повтор_hello_невидимыми' "$r2o_log"
grep -Fq 'r2o_tcp_сравнивает_ack_с_переполнением_серийного_номера' "$r2o_log"
grep -Fq 'r2o_метка_контроллера_исключает_зондовые_пакеты_из_состояния_datapath' "$r2o_log"
printf 'Журнал сверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
