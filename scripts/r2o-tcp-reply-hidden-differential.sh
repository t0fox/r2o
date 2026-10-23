#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath="${R2O_DONOR_DATAPATH:-${r2o_script_dir%/*}/d2o/datapath}"
r2o_donor_test="$r2o_donor_datapath/test_session"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-tcp-reply-hidden-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_started_at=$(date +%s)
r2o_upstream_sha=86b05b96457fccdec6b7ddc0e8478508f80f0bab

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

if [ ! -x "$r2o_donor_test" ]; then
    printf 'Готовый контрольный тест донора не найден: %s\n' "$r2o_donor_test" >&2
    exit 2
fi
if ! grep -q 'test_reply_hidden_by_accelerator' "$r2o_donor_datapath/test_session.c"; then
    printf 'В контрольном исходнике донора нет теста скрытого ответа\n' >&2
    exit 2
fi

mkdir -p "$r2o_log_dir"
{
    printf 'Сверка видимости TCP-ответа: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники донора: %s\n' "$r2o_donor_datapath"
    printf '\nSHA-256 C-эталона, теста, бинарника и Rust-реализации\n'
    sha256sum \
        "$r2o_donor_datapath/session.c" \
        "$r2o_donor_datapath/test_session.c" \
        "$r2o_donor_test" \
        "$r2o_script_dir/crates/r2o-datapath/src/engine.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/main.rs"
    r2o_session_sha256=$(sha256sum "$r2o_donor_datapath/session.c" | awk '{print $1}')
    r2o_test_sha256=$(sha256sum "$r2o_donor_datapath/test_session.c" | awk '{print $1}')
    r2o_test_binary_sha256=$(sha256sum "$r2o_donor_test" | awk '{print $1}')
    if [ "$r2o_session_sha256" != \
        'f3bc8c4ddd334a189c63dc1bbf868eff258c2fdff3199e285d4a098d2ad3fe1f' ] || \
        [ "$r2o_test_sha256" != \
        'daf5b11d04ddc9ade28d7b5acde94fe1ec629bea2bbc49a2d98cf726ee8cbdd9' ] || \
        [ "$r2o_test_binary_sha256" != \
        '5a768352dacbe5a92ca8739842778719bf63973eaef05cfd6f3fd5f019d46174' ]; then
        printf 'Исходники или тестовый бинарник донора отличаются от проверенного снимка\n' >&2
        exit 1
    fi
    printf '\nПроверочный тест донора без пересборки C\n'
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
grep -q 'r2o_tcp_учитывает_невидимый_ответ_один_раз_по_продвинутому_ack .*ok' "$r2o_log"
grep -q 'r2o_tcp_не_считает_видимый_ответ_и_повтор_hello_невидимыми .*ok' "$r2o_log"
grep -q 'r2o_tcp_сравнивает_ack_с_переполнением_серийного_номера .*ok' "$r2o_log"
grep -q 'r2o_метка_контроллера_исключает_зондовые_пакеты_из_состояния_datapath .*ok' "$r2o_log"
printf 'Журнал сверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
