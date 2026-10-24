#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_core="${R2O_DONOR_CORE:-${r2o_script_dir%/*}/d2o/core}"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-fetch-cli-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_temp_dir=$(mktemp -d)

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

r2o_capture_status() {
    r2o_stdout=$1
    r2o_stderr=$2
    r2o_status_file=$3
    shift 3
    if "$@" >"$r2o_stdout" 2>"$r2o_stderr"; then
        r2o_status=0
    else
        r2o_status=$?
    fi
    printf '%s\n' "$r2o_status" >"$r2o_status_file"
}

r2o_show_log_on_error() {
    r2o_status=$?
    if [ "$r2o_status" -ne 0 ] && [ -f "$r2o_log" ]; then
        cat "$r2o_log"
    fi
    rm -rf -- "$r2o_temp_dir"
}
trap r2o_show_log_on_error EXIT

if [ ! -d "$r2o_donor_core" ]; then
    printf 'Каталог C-эталона не найден: %s\n' "$r2o_donor_core" >&2
    exit 2
fi
mkdir -p "$r2o_log_dir"
{
    printf 'Дифференциальная проверка Fetch CLI: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники C core: %s\n' "$r2o_donor_core"
    if [ -n "${R2O_EXPECTED_DONOR_SHA:-}" ]; then
        printf 'SHA C snapshot: %s\n' "$R2O_EXPECTED_DONOR_SHA"
    fi
    printf '\nSHA-256 исходника C\n'
    sha256sum "$r2o_donor_core/d2kfetch.c"
    printf '\nСборка C и Rust CLI\n'
    r2o_run_timed 'сборка d2kfetch C' make -C "$r2o_donor_core" \
        d2kfetch CC=clang-18
    r2o_run_timed 'сборка r2o-fetch Rust' cargo +1.98.0 build \
        --locked --offline --package r2o-controller --bin r2o-fetch
    printf '\nОдинаковый сценарий: пустой --ip, localhost, QUIC к закрытому loopback-порту\n'
    r2o_run_timed 'запуск d2kfetch C' r2o_capture_status \
        "$r2o_temp_dir/c.stdout" "$r2o_temp_dir/c.stderr" \
        "$r2o_temp_dir/c.status" \
        sh -c 'cd "$1" && exec ./d2kfetch --name localhost --ip "" --port 1 --deadline 100 --quic' \
        sh "$r2o_donor_core"
    r2o_run_timed 'запуск r2o-fetch Rust' r2o_capture_status \
        "$r2o_temp_dir/rust.stdout" "$r2o_temp_dir/rust.stderr" \
        "$r2o_temp_dir/rust.status" \
        "$r2o_script_dir/../target/debug/r2o-fetch" \
        --name localhost --ip '' --port 1 --deadline 100 --quic --json
    python3 - "$r2o_temp_dir/c.stdout" "$r2o_temp_dir/rust.stdout" \
        "$r2o_temp_dir/c.status" "$r2o_temp_dir/rust.status" <<'PY'
import ipaddress
import json
import pathlib
import re
import sys

c_output = pathlib.Path(sys.argv[1]).read_text()
rust_output = pathlib.Path(sys.argv[2]).read_text()
c_status = int(pathlib.Path(sys.argv[3]).read_text())
rust_status = int(pathlib.Path(sys.argv[4]).read_text())
c_match = re.search(r"цель:\s+localhost \((.+):1\), путь", c_output)
if not c_match:
    raise SystemExit(f"d2kfetch did not resolve empty --ip:\n{c_output}")
c_ip = ipaddress.ip_address(c_match.group(1))
rust_result = json.loads(rust_output)
if rust_result.get("shape") != "quic":
    raise SystemExit(f"r2o-fetch did not run the requested QUIC check: {rust_result}")
rust_ip = ipaddress.ip_address(rust_result["ip"])
if not c_ip.is_loopback or not rust_ip.is_loopback:
    raise SystemExit(f"empty --ip did not resolve to loopback: C={c_ip}, Rust={rust_ip}")
if c_status not in (0, 1) or rust_status not in (0, 1):
    raise SystemExit(f"unexpected CLI status: C={c_status}, Rust={rust_status}")
print(f"Fetch CLI parity: C resolved {c_ip}; Rust resolved {rust_ip}; both ran QUIC")
PY
    printf 'C stdout:\n'
    cat "$r2o_temp_dir/c.stdout"
    printf '\nRust JSON:\n'
    cat "$r2o_temp_dir/rust.stdout"
} >"$r2o_log" 2>&1

grep -q 'Fetch CLI parity: C resolved .*; Rust resolved .*; both ran QUIC' "$r2o_log"
printf 'Журнал проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
rm -rf -- "$r2o_temp_dir"
