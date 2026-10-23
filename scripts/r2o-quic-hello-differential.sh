#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath="${R2O_DONOR_DATAPATH:-${r2o_script_dir%/*}/d2o/datapath}"
r2o_donor_test="$r2o_donor_datapath/test_quic_session"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-quic-hello-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_started_at=$(date +%s)

r2o_show_log_on_error() {
    r2o_status=$?
    if [ "$r2o_status" -ne 0 ] && [ -f "$r2o_log" ]; then
        cat "$r2o_log"
    fi
}
trap r2o_show_log_on_error EXIT

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
    printf 'Готовый QUIC-тест донора не найден: %s\n' "$r2o_donor_test" >&2
    exit 2
fi
if ! grep -Fq 'first_hello = named && !fl->saw_hello' "$r2o_donor_datapath/session.c" || \
    ! grep -Fq 'test_quic_snapshot_is_every_initial' "$r2o_donor_datapath/test_quic_session.c"; then
    printf 'Исходник донора больше не содержит закреплённый сценарий QUIC\n' >&2
    exit 2
fi

mkdir -p "$r2o_log_dir"
{
    printf 'Дифференциальная проверка QUIC ClientHello: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники донора: %s\n' "$r2o_donor_datapath"
    printf 'REA Evidence: ev_0fc0d328089313aa03f9c4a5b4c8eeb2fbedd01804194dbaba7a261d2c995e80, ev_7aafc101282414d722918c6de7cc77fd657416987daffe55d620b1822c25820c, ev_8dfd376f9d501c0515ba212806894f2c893049f76dfbfae5874b2a22a650bbc7\n'
    printf '\nSHA-256 донорских исходников, готового контрольного бинарника и Rust-кода\n'
    sha256sum \
        "$r2o_donor_datapath/session.c" \
        "$r2o_donor_datapath/test_quic_session.c" \
        "$r2o_donor_test" \
        "$r2o_script_dir/crates/r2o-datapath/src/r2o_quic.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/main.rs"
    r2o_session_sha256=$(sha256sum "$r2o_donor_datapath/session.c" | awk '{print $1}')
    r2o_test_sha256=$(sha256sum "$r2o_donor_datapath/test_quic_session.c" | awk '{print $1}')
    r2o_test_binary_sha256=$(sha256sum "$r2o_donor_test" | awk '{print $1}')
    if [ "$r2o_session_sha256" != \
        '39dada3d4fbdaf943bf7b2a788090ab3d16a71065a58c16d39901575247f7187' ] || \
        [ "$r2o_test_sha256" != \
        'fbf47889b8d6d7c712b02f5643d37ae937723d004368e20d5f4e0c2e58493c0a' ] || \
        [ "$r2o_test_binary_sha256" != \
        'd1fc01f88f90710cf1bd541dcab68ff97ab2e384242ff3cf0e8a9dd843b3f1e8' ]; then
        printf 'Исходники или бинарник донора отличаются от проверенного снимка\n' >&2
        exit 1
    fi
    printf '\nЗапуск готового контроля донора без пересборки C\n'
    r2o_run_timed 'контрольный тест QUIC донора' "$r2o_donor_test"
    printf '\nПроверка повторного полного ClientHello и нового потока на Rust\n'
    r2o_run_timed 'повтор полного ClientHello и истечение кэша Rust' \
        cargo +1.98.0 test -p r2o-datapath --lib собирает_событие_из_проверенного_initial \
            --locked --offline -- --nocapture
    printf '\nПроверка сборки ClientHello из нескольких датаграмм на Rust\n'
    r2o_run_timed 'сборка ClientHello из нескольких Initial Rust' \
        cargo +1.98.0 test -p r2o-datapath --lib собирает_событие_из_двух_initial_только_одного_потока \
            --locked --offline -- --nocapture
    printf '\nПолная длительность дифференциального набора: %s с\n' \
        "$(( $(date +%s) - r2o_started_at ))"
} >"$r2o_log" 2>&1

grep -q 'QUIC/UDP: все проверки прошли' "$r2o_log"
grep -q 'собирает_событие_из_проверенного_initial .*ok' "$r2o_log"
grep -q 'собирает_событие_из_двух_initial_только_одного_потока .*ok' "$r2o_log"
printf 'Журнал дифференциальной проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
