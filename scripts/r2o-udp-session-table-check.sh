#!/bin/sh
set -eu

r2o_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_workspace_parent=$(dirname "$r2o_root")
r2o_donor_datapath=${R2O_DONOR_DATAPATH:-$r2o_workspace_parent/d2o/datapath}
r2o_log_dir="$r2o_root/.rea"
r2o_log="$r2o_log_dir/r2o-udp-session-table-check-$(date +%Y%m%d-%H%M%S).log"
r2o_cleanup() {
    r2o_status=$?
    if [ "$r2o_status" -ne 0 ] && [ -f "$r2o_log" ]; then
        cat "$r2o_log"
    fi
}
trap r2o_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$r2o_log_dir"

if [ ! -d "$r2o_donor_datapath" ]; then
    printf 'Каталог исходников-эталона не найден: %s\n' "$r2o_donor_datapath" >&2
    exit 2
fi

r2o_run() {
    r2o_started_at=$(date +%s)
    printf 'Проверка таблицы UDP-потоков R2O по тестам донора: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники донора для контрольных тестов: %s\n' "$r2o_donor_datapath"
    printf '\nSHA-256 исходников и целевой реализации\n'
    sha256sum "$r2o_donor_datapath/session.c" \
        "$r2o_donor_datapath/track.c" \
        "$r2o_donor_datapath/test_track.c" \
        "$r2o_donor_datapath/test_quic_session.c" \
        "$r2o_donor_datapath/include/d2k_session.h" \
        "$r2o_root/crates/r2o-datapath/src/r2o_udp_sessions.rs"

    printf '\nAST Clang 18: обработчик UDP\n'
    clang-18 -std=c99 \
        -I"$r2o_donor_datapath/include" \
        -I"$r2o_donor_datapath/../core/include" \
        -DD2K_RELEASE_ID='"diff"' \
        -fsyntax-only -Xclang -ast-dump "$r2o_donor_datapath/session.c" 2>/dev/null \
        | grep -E 'FunctionDecl.*handle_udp'

    printf '\nC-проверки сценариев таблиц и UDP в доноре\n'
    make -B -C "$r2o_donor_datapath" test-track test-quic-session CC=clang-18

    printf '\nСценарии UDP-таблицы Rust\n'
    cargo +1.98.0 test -p r2o-datapath --test udp_sessions \
        --locked --offline -- --nocapture
    printf '\nПолная длительность: %s с\n' "$(( $(date +%s) - r2o_started_at ))"
}

r2o_run >"$r2o_log" 2>&1

printf 'ПРОЙДЕНО: Rust-сценарии R2O и контрольные тесты донора прошли.\n'
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
