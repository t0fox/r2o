#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath=${R2O_DONOR_DATAPATH:?set R2O_DONOR_DATAPATH to a pinned d2o/datapath snapshot}
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-hold-differential-$(date +%Y%m%d-%H%M%S).log"
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

if [ ! -d "$r2o_donor_datapath" ]; then
    printf 'Каталог C-эталона не найден: %s\n' "$r2o_donor_datapath" >&2
    exit 2
fi
mkdir -p "$r2o_log_dir"
{
    printf 'Дифференциальная проверка TCP hold: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники C: %s\n' "$r2o_donor_datapath"
    printf '\nSHA-256 C hold/test и Rust hold\n'
    sha256sum "$r2o_donor_datapath/hold.c" \
        "$r2o_donor_datapath/test_hold.c" \
        "$r2o_script_dir/crates/r2o-datapath/src/hold.rs"
    r2o_run_timed 'сборка C test_hold' \
        make -B -C "$r2o_donor_datapath" test_hold CC=clang-18
    r2o_run_timed 'проверки владения пакетами C' "$r2o_donor_datapath/test_hold"
    r2o_run_timed 'проверки удержания Rust' cargo +1.98.0 test \
        -p r2o-datapath --lib hold::tests --locked --offline
    printf '\nПолная длительность набора: %s с\n' "$(( $(date +%s) - r2o_started_at ))"
} >"$r2o_log" 2>&1

grep -q 'hold: ownership, bounds and release checks passed' "$r2o_log"
grep -q 'split_hello_returns_synthetic_head_and_all_original_ids .*ok' "$r2o_log"
grep -q 'out_of_order_tail_uses_syn_anchor_and_real_head_header .*ok' "$r2o_log"
grep -q 'timeout_and_revision_change_fail_open_all_held_ids .*ok' "$r2o_log"
grep -q 'passive_client_hello_observation_never_holds_original_packets .*ok' "$r2o_log"
grep -q 'fast_single_segment_portal_offers_a_https_redirect .*ok' "$r2o_log"
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
