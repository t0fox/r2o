#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath="${R2O_DONOR_DATAPATH:-${r2o_script_dir%/*}/d2o/datapath}"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-tcp-rst-observation-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_started_at=$(date +%s)
r2o_temp_dir=$(mktemp -d)

r2o_cleanup() {
    r2o_status=$?
    rm -rf "$r2o_temp_dir"
    if [ "$r2o_status" -ne 0 ] && [ -f "$r2o_log" ]; then
        cat "$r2o_log"
    fi
}
trap r2o_cleanup EXIT

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

if [ ! -d "$r2o_donor_datapath" ]; then
    printf 'Каталог C-эталона не найден: %s\n' "$r2o_donor_datapath" >&2
    exit 2
fi
mkdir -p "$r2o_log_dir"
{
    printf 'Дифференциальная проверка раннего TCP RST: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники C: %s\n' "$r2o_donor_datapath"
    printf '\nSHA-256 исходников сценария\n'
    sha256sum \
        "$r2o_donor_datapath/session.c" \
        "$r2o_donor_datapath/include/d2k_journal.h" \
        "$r2o_script_dir/scripts/r2o-c-tcp-rst-observation.c" \
        "$r2o_script_dir/crates/r2o-datapath/src/engine.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/flow_journal.rs" \
        "$r2o_script_dir/crates/r2o-datapath/src/main.rs"
    printf '\nСборка C-сценария\n'
    r2o_run_timed 'сборка объектов C-сессии' make -C "$r2o_donor_datapath" \
        test_session CC=clang-18
    r2o_run_timed 'сборка проверочного C-сценария' clang-18 \
        -std=c99 -O2 -Wall -Wextra -Werror \
        -I"$r2o_donor_datapath/include" \
        -I"$r2o_donor_datapath/../core/include" \
        -DD2K_RELEASE_ID='"dev"' \
        "$r2o_script_dir/scripts/r2o-c-tcp-rst-observation.c" \
        "$r2o_donor_datapath/session.o" \
        "$r2o_donor_datapath/http80.o" \
        "$r2o_donor_datapath/hold.o" \
        "$r2o_donor_datapath/capture.o" \
        "$r2o_donor_datapath/nat.o" \
        "$r2o_donor_datapath/ctq.o" \
        "$r2o_donor_datapath/nl.o" \
        "$r2o_donor_datapath/track.o" \
        "$r2o_donor_datapath/tls.o" \
        "$r2o_donor_datapath/wire.o" \
        "$r2o_donor_datapath/wire_udp.o" \
        "$r2o_donor_datapath/journal.o" \
        "$r2o_donor_datapath/plans.o" \
        "$r2o_donor_datapath/plan_parse.o" \
        "$r2o_donor_datapath/plan_apply.o" \
        "$r2o_donor_datapath/core_quic.o" \
        "$r2o_donor_datapath/core_quicwire.o" \
        "$r2o_donor_datapath/core_quicsnap.o" \
        "$r2o_donor_datapath/core_crypto.o" \
        "$r2o_donor_datapath/core_ipfrag.o" \
        "$r2o_donor_datapath/core_httpup_logic.o" \
        -o "$r2o_temp_dir/r2o-c-tcp-rst-observation"
    printf '\nСценарий C-эталона\n'
    r2o_run_timed 'пакеты и отпечаток C' "$r2o_temp_dir/r2o-c-tcp-rst-observation"
    printf '\nСценарий состояния TCP Rust\n'
    r2o_run_timed 'учёт раннего RST Rust' cargo +1.98.0 test \
        -p r2o-datapath --lib tcp_ранний_rst_создаёт_отдельное_наблюдение \
        --locked --offline -- --nocapture
    printf '\nСценарий runtime Rust\n'
    r2o_run_timed 'журналирование раннего RST Rust' cargo +1.98.0 test \
        -p r2o-datapath --bin r2o-datapath r2o_передаёт_ранний_rst_в_общий_журнал \
        --locked --offline -- --nocapture
} >"$r2o_log" 2>&1

r2o_c_result=$(grep '^R2O_DIFF ' "$r2o_log" | sed -n '1p')
r2o_rust_result=$(grep '^R2O_DIFF ' "$r2o_log" | tail -n 1)
{
    printf '\nСравнение отпечатков\nC:    %s\nRust: %s\n' \
        "$r2o_c_result" "$r2o_rust_result"
    if [ "$r2o_c_result" != "$r2o_rust_result" ]; then
        printf 'Отпечатки раннего RST различаются\n' >&2
        exit 1
    fi
    printf '\nПолная длительность набора: %s с\n' \
        "$(( $(date +%s) - r2o_started_at ))"
} >>"$r2o_log" 2>&1

grep -q 'tcp_ранний_rst_создаёт_отдельное_наблюдение .*ok' "$r2o_log"
grep -q 'r2o_передаёт_ранний_rst_в_общий_журнал .*ok' "$r2o_log"
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
