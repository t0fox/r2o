#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath=${R2O_DONOR_DATAPATH:-${r2o_script_dir%/*}/d2o/datapath}
r2o_route_test="$r2o_donor_datapath/test_routemark"
r2o_session_test="$r2o_donor_datapath/test_session"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-route-gate-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_started_at=$(date +%s)
r2o_upstream_sha=783aa75ce44dd6192cd1f4f1d98e4fe909ef3045

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

if [ "${R2O_EXPECTED_DONOR_SHA:-}" != "$r2o_upstream_sha" ]; then
    printf 'Route-gate differential requires pinned upstream donor %s\n' "$r2o_upstream_sha" >&2
    exit 2
fi

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
    printf '%s\n' "$r2o_hashes" | grep -q '3e5f0ea6bf53e2b8a542446b30b8d0178453f61881755db547c088c3169e6845'
    printf '%s\n' "$r2o_hashes" | grep -q '8695849a779e5e1a6f554ce5599900b146092eb8806e42df11f8e667a28ba8d6'
    printf '%s\n' "$r2o_hashes" | grep -q 'fa46df3ecbb2b33777a447de17bbc5c7ae96d0993f39d0de79297288de3478b0'
    printf '%s\n' "$r2o_hashes" | grep -q 'f2863fbf294fc185568a6b500286e3c36d18485d4302417403301cbeef69d45d'
    printf '%s\n' "$r2o_hashes" | grep -q 'd6e987d1080a7a20492c0d6f721fea687eefcd7cc33e966221c22e1b1e33eb59'
    printf '%s\n' "$r2o_hashes" | grep -q 'f3bc8c4ddd334a189c63dc1bbf868eff258c2fdff3199e285d4a098d2ad3fe1f'
    printf '%s\n' "$r2o_hashes" | grep -q 'daf5b11d04ddc9ade28d7b5acde94fe1ec629bea2bbc49a2d98cf726ee8cbdd9'
    printf '%s\n' "$r2o_hashes" | grep -q 'e1720cfc80b9d707a41363f145e7d0dcaea01013ea7470b972974bde3e43db27'

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
