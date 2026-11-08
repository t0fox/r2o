#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath=${R2O_DONOR_DATAPATH:-${r2o_script_dir%/*}/d2o/datapath}
r2o_route_test="$r2o_donor_datapath/test_routemark"
r2o_session_test="$r2o_donor_datapath/test_session"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-route-gate-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_started_at=$(date +%s)
r2o_upstream_sha=a378e230947ebfd011439e1cac0f1e994d883aae

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

r2o_actual_donor_sha=$(git -C "$r2o_donor_datapath" rev-parse HEAD)
if [ "$r2o_actual_donor_sha" != "$r2o_upstream_sha" ]; then
    printf 'Route-gate requires donor checkout %s, got %s\n' \
        "$r2o_upstream_sha" "$r2o_actual_donor_sha" >&2
    exit 2
fi
if ! git -C "$r2o_donor_datapath" diff --quiet HEAD -- || \
    ! git -C "$r2o_donor_datapath" diff --cached --quiet HEAD --; then
    printf 'Donor worktree has tracked changes; refusing unpinned C sources\n' >&2
    exit 2
fi

mkdir -p "$r2o_log_dir"
{
    printf 'Дифференциальная проверка шлюза маршрутизации R2O: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники-эталоны: %s\n' "$r2o_donor_datapath"
    printf 'REA Evidence: ev_397dbcdcc48e8067509367712bb6ff500528c41c90fb7f881dea3b8bf76cb4d1\n'
    printf '\nSHA-256 закреплённых C-исходников и Rust-реализации\n'
    sha256sum \
        "$r2o_donor_datapath/routemark.c" \
        "$r2o_donor_datapath/routemark_nl.c" \
        "$r2o_donor_datapath/include/d2k_routemark.h" \
        "$r2o_donor_datapath/test_routemark.c" \
        "$r2o_donor_datapath/session.c" \
        "$r2o_donor_datapath/test_session.c" \
        "$r2o_script_dir/crates/r2o-datapath/src/r2o_route.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/main.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/nfqueue.rs" \
        "$r2o_script_dir/router/S99r2o"
    r2o_hashes=$(sha256sum \
        "$r2o_donor_datapath/routemark.c" \
        "$r2o_donor_datapath/routemark_nl.c" \
        "$r2o_donor_datapath/include/d2k_routemark.h" \
        "$r2o_donor_datapath/test_routemark.c" \
        "$r2o_donor_datapath/session.c" \
        "$r2o_donor_datapath/test_session.c")
    printf '%s\n' "$r2o_hashes" | grep -q '53fdb658a6dadce23273ffda1d187a427cf5ae129c5284922c2d24584e6d398e'
    printf '%s\n' "$r2o_hashes" | grep -q '03be99b80fa5f1fdff16af9cfef183a0c670e34c36113bdde0b0a397242b8eb2'
    printf '%s\n' "$r2o_hashes" | grep -q '969b16e8f86da0fe651654d28a8ac627b46e9cae3e8b2a61f271f3d1ca9cf89a'
    printf '%s\n' "$r2o_hashes" | grep -q '9e7e2ec357aaace34768991d736906e36ff8da64fdd8e72a1c8becdaf166aee8'
    printf '%s\n' "$r2o_hashes" | grep -q '7a610ea7f9651391ea4768028d1abb65e7eeee2279f20c139167dfd05af1ab35'
    printf '%s\n' "$r2o_hashes" | grep -q '84d980e5f4e8850b7ba3a638987021e96eba5e1721a63a3cdfd30b224817ec43'

    printf '\nСборка C-контролей из закреплённого donor commit\n'
    r2o_run_timed 'сборка test_routemark и test_session' \
        make -B -C "$r2o_donor_datapath" test_routemark test_session CC=clang-18
    sha256sum "$r2o_route_test" "$r2o_session_test"

    printf '\nЗапуск C-контролей донора\n'
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
