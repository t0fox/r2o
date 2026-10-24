#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath="${R2O_DONOR_DATAPATH:-${r2o_script_dir%/*}/d2o/datapath}"
r2o_donor_test="$r2o_donor_datapath/test_session"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-tcp-reply-hidden-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_started_at=$(date +%s)
r2o_upstream_sha=783aa75ce44dd6192cd1f4f1d98e4fe909ef3045

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
        'a7446b416481674b9a6332dad97430c903f6a3c7d53b45e8794a86eee2f127ea' ] || \
        [ "$r2o_test_sha256" != \
        '2fcad959cdb7086312ae1b8a7d2c0b168fe9c5cfd8038b2aa87f75a6c3ce3561' ] || \
        [ "$r2o_test_binary_sha256" != \
        '10dec3a27f557c9973b7d2b2e060329702e222fa420a35095081959790b0aacb' ]; then
        printf 'Исходники или тестовый бинарник донора отличаются от проверенного снимка\n' >&2
        exit 1
    fi
    printf '\nПроверочный тест донора без пересборки C\n'
    if readelf -h "$r2o_donor_test" | grep -q 'Machine:.*AArch64'; then
        r2o_qemu_aarch64=${R2O_QEMU_AARCH64:-qemu-aarch64}
        r2o_aarch64_sysroot=${R2O_AARCH64_SYSROOT:-/usr/aarch64-linux-gnu}
        if ! command -v "$r2o_qemu_aarch64" >/dev/null 2>&1; then
            printf 'Для ARM64-бинарника нужен QEMU: %s\n' "$r2o_qemu_aarch64" >&2
            exit 2
        fi
        if [ ! -d "$r2o_aarch64_sysroot" ]; then
            printf 'Не найден sysroot для QEMU ARM64: %s\n' "$r2o_aarch64_sysroot" >&2
            exit 2
        fi
        r2o_run_timed 'контрольная сессия донора через QEMU ARM64' \
            "$r2o_qemu_aarch64" -L "$r2o_aarch64_sysroot" "$r2o_donor_test"
    else
        r2o_run_timed 'контрольная сессия донора' "$r2o_donor_test"
    fi
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
