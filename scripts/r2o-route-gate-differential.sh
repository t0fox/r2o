#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath=${R2O_DONOR_DATAPATH:-${r2o_script_dir%/*}/d2o/datapath}
r2o_route_test="$r2o_donor_datapath/test_routemark"
r2o_session_test="$r2o_donor_datapath/test_session"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-route-gate-differential-$(date +%Y%m%d-%H%M%S).log"
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

for r2o_test in "$r2o_route_test" "$r2o_session_test"; do
    if [ ! -x "$r2o_test" ]; then
        printf 'Готовый тест донора не найден: %s\n' "$r2o_test" >&2
        exit 2
    fi
done

mkdir -p "$r2o_log_dir"
{
    printf 'Дифференциальная проверка шлюза маршрутизации R2O: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники-эталоны: %s\n' "$r2o_donor_datapath"
    printf 'REA Evidence: ev_397dbcdcc48e8067509367712bb6ff500528c41c90fb7f881dea3b8bf76cb4d1\n'
    printf '\nSHA-256 C-эталона, его готовых тестов и Rust-реализации\n'
    sha256sum \
        "$r2o_donor_datapath/routemark.c" \
        "$r2o_donor_datapath/routemark_nl.c" \
        "$r2o_donor_datapath/include/d2k_routemark.h" \
        "$r2o_donor_datapath/test_routemark.c" \
        "$r2o_route_test" \
        "$r2o_donor_datapath/session.c" \
        "$r2o_donor_datapath/test_session.c" \
        "$r2o_session_test" \
        "$r2o_script_dir/crates/r2o-datapath/src/r2o_route.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/main.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/nfqueue.rs" \
        "$r2o_script_dir/router/S99r2o"
    r2o_hashes=$(sha256sum \
        "$r2o_donor_datapath/routemark.c" \
        "$r2o_donor_datapath/routemark_nl.c" \
        "$r2o_donor_datapath/include/d2k_routemark.h" \
        "$r2o_donor_datapath/test_routemark.c" \
        "$r2o_route_test" \
        "$r2o_donor_datapath/session.c" \
        "$r2o_donor_datapath/test_session.c" \
        "$r2o_session_test")
    printf '%s\n' "$r2o_hashes" | grep -q '53fdb658a6dadce23273ffda1d187a427cf5ae129c5284922c2d24584e6d398e'
    printf '%s\n' "$r2o_hashes" | grep -q '03be99b80fa5f1fdff16af9cfef183a0c670e34c36113bdde0b0a397242b8eb2'
    printf '%s\n' "$r2o_hashes" | grep -q '969b16e8f86da0fe651654d28a8ac627b46e9cae3e8b2a61f271f3d1ca9cf89a'
    printf '%s\n' "$r2o_hashes" | grep -q '9e7e2ec357aaace34768991d736906e36ff8da64fdd8e72a1c8becdaf166aee8'
    printf '%s\n' "$r2o_hashes" | grep -q '4936142dcc67c9fb14d6cfa4e87ffca2b20bdd97cd9f4018183de5561b7874ac'
    printf '%s\n' "$r2o_hashes" | grep -q '39dada3d4fbdaf943bf7b2a788090ab3d16a71065a58c16d39901575247f7187'
    printf '%s\n' "$r2o_hashes" | grep -q 'd9f4bd539d35dc8bd7684b64959bd333769fd5a284ec9832247ef2fbf382736c'
    printf '%s\n' "$r2o_hashes" | grep -q '34fbfe639cf712b27e5a4f50dc0240451081e8c393aa4dfcbcd57f6c3c433ff5'

    printf '\nЗапуск готовых тестов C-донора без компиляции C\n'
    r2o_run_timed 'проверки шлюза маршрутизации донора' "$r2o_route_test"
    r2o_run_timed 'проверки сессий TCP/UDP донора' "$r2o_session_test"

    printf '\nПроверка маршрутов, fwmark и памяти потоков в Rust\n'
    r2o_run_timed 'модуль шлюза маршрутизации Rust' \
        cargo +1.98.0 test -p r2o-datapath --lib r2o_route::tests --locked --offline -- --nocapture
    r2o_run_timed 'runtime-пропуск двунаправленного UDP-потока Rust' \
        cargo +1.98.0 test -p r2o-datapath --bin r2o-datapath \
        r2o_runtime_оставляет_весь_маршрутный_udp_поток_ядру --locked --offline -- --nocapture
    r2o_run_timed 'CLI-политика и метки Rust' \
        cargo +1.98.0 test -p r2o-datapath --bin r2o-datapath \
        r2o_параметры_route_gate_принимают_шестнадцатеричные_метки_и_none --locked --offline -- --nocapture

    printf '\nПолная длительность набора: %s с\n' \
        "$(( $(date +%s) - r2o_started_at ))"
} >"$r2o_log" 2>&1

grep -q 'routemark: selectors, matcher and refresh passed' "$r2o_log"
grep -q 'сессия: все проверки прошли' "$r2o_log"
grep -q 'r2o_монитор_читает_правила_и_маршрут_текущего_ядра .*ok' "$r2o_log"
grep -q 'r2o_runtime_оставляет_весь_маршрутный_udp_поток_ядру .*ok' "$r2o_log"
grep -q 'r2o_параметры_route_gate_принимают_шестнадцатеричные_метки_и_none .*ok' "$r2o_log"
printf 'Журнал дифференциальной проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
