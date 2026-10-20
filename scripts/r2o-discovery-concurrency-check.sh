#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-discovery-concurrency-rust-$(date +%Y%m%d-%H%M%S).log"
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

mkdir -p "$r2o_log_dir"
{
    printf 'Проверка параллельных задач Discovery на Rust: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf '\nSHA-256 исходника Rust\n'
    sha256sum "$r2o_script_dir/crates/r2o-controller/src/main.rs"
    printf '\nПараллельная очередь Discovery в пределах общих слотов\n'
    r2o_run_timed 'две задачи в пределах двух доступных слотов' cargo +1.98.0 test \
        --locked --offline -p r2o-controller --bin r2o-controller \
        r2o_discovery_запускает_параллельные_задачи_в_пределах_общих_слотов \
        -- --nocapture
    printf '\nПолная длительность набора: %s с\n' "$(( $(date +%s) - r2o_started_at ))"
} >"$r2o_log" 2>&1

grep -q 'r2o_discovery_запускает_параллельные_задачи_в_пределах_общих_слотов .*ok' "$r2o_log"
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
