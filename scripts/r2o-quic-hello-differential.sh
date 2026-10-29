#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath="${R2O_DONOR_DATAPATH:-${r2o_script_dir%/*}/d2o/datapath}"
r2o_donor_test="$r2o_donor_datapath/test_quic_session"
r2o_log_dir=${R2O_LOG_DIR:-"$r2o_script_dir/.rea"}
r2o_log="$r2o_log_dir/r2o-quic-hello-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_started_at=$(date +%s)
r2o_upstream_sha=304ba893dd37197128ac8799c0495b035f6a38c0

if [ "${R2O_EXPECTED_DONOR_SHA:-}" != "$r2o_upstream_sha" ]; then
    printf 'QUIC differential requires pinned upstream donor %s\n' "$r2o_upstream_sha" >&2
    exit 2
fi

r2o_actual_donor_sha=$(git -C "$r2o_donor_datapath" rev-parse HEAD)
if [ "$r2o_actual_donor_sha" != "$r2o_upstream_sha" ]; then
    printf 'QUIC differential requires donor checkout %s, got %s\n' \
        "$r2o_upstream_sha" "$r2o_actual_donor_sha" >&2
    exit 2
fi
if ! git -c core.autocrlf=true -C "${r2o_donor_datapath%/datapath}" \
    diff --quiet HEAD -- datapath/session.c datapath/test_quic_session.c || \
    ! git -c core.autocrlf=true -C "${r2o_donor_datapath%/datapath}" \
    diff --cached --quiet HEAD -- datapath/session.c datapath/test_quic_session.c; then
    printf 'Pinned donor QUIC session sources have tracked changes; refusing unpinned C sources\n' >&2
    exit 2
fi

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
    printf '\nSHA-256 закреплённых донорских исходников и Rust-кода\n'
    sha256sum \
        "$r2o_donor_datapath/session.c" \
        "$r2o_donor_datapath/test_quic_session.c" \
        "$r2o_script_dir/crates/r2o-datapath/src/r2o_quic.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/main.rs"
    r2o_session_blob=$(git -C "${r2o_donor_datapath%/datapath}" \
        rev-parse HEAD:datapath/session.c)
    r2o_test_blob=$(git -C "${r2o_donor_datapath%/datapath}" \
        rev-parse HEAD:datapath/test_quic_session.c)
    if [ "$r2o_session_blob" != '061c98f61e1faea5178c379e94e83e17c21be7da' ] || \
        [ "$r2o_test_blob" != 'dc3af4d5aafb9423622ab2d5df202b4be8e1e823' ]; then
        printf 'Исходники донора отличаются от проверенного снимка\n' >&2
        exit 1
    fi
    printf '\nСборка C-контроля из закреплённого donor commit\n'
    r2o_run_timed 'сборка C test_quic_session' make -B -C "$r2o_donor_datapath" \
        test_quic_session CC=clang-18
    sha256sum "$r2o_donor_test"
    printf '\nЗапуск C-контроля донора\n'
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
