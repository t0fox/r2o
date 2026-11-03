#!/bin/sh
set -eu

r2o_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_datapath=${R2O_DONOR_DATAPATH:-${r2o_root%/*}/d2o/datapath}
r2o_tmp=$(mktemp -d "${TMPDIR:-/tmp}/r2o-ct-retry.XXXXXX")
r2o_namespace="r2o-ct-retry-$$"
r2o_d2o_pidfile=$r2o_tmp/d2o.pid
r2o_r2o_pidfile=$r2o_tmp/r2o.pid
r2o_d2o_launcher=
r2o_r2o_launcher=

if [ "$(id -u)" -eq 0 ]; then
    r2o_root_command=''
elif command -v sudo >/dev/null 2>&1; then
    r2o_root_command=sudo
else
    echo 'run as root or install sudo to create the test network namespace' >&2
    exit 77
fi

root() {
    if [ -n "$r2o_root_command" ]; then
        "$r2o_root_command" "$@"
    else
        "$@"
    fi
}

stop_process() {
    pidfile=$1
    if [ -s "$pidfile" ]; then
        pid=$(cat "$pidfile")
        root kill -TERM "$pid" 2>/dev/null || true
        attempt=0
        while [ "$attempt" -lt 20 ]; do
            if ! root kill -0 "$pid" 2>/dev/null; then
                return
            fi
            sleep 0.1
            attempt=$((attempt + 1))
        done
        root kill -KILL "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    stop_process "$r2o_d2o_pidfile"
    stop_process "$r2o_r2o_pidfile"
    if [ -n "$r2o_d2o_launcher" ]; then wait "$r2o_d2o_launcher" 2>/dev/null || true; fi
    if [ -n "$r2o_r2o_launcher" ]; then wait "$r2o_r2o_launcher" 2>/dev/null || true; fi
    root ip netns del "$r2o_namespace" >/dev/null 2>&1 || true
    rm -rf "$r2o_tmp"
}
trap cleanup EXIT HUP INT TERM

: > "$r2o_tmp/d2o.trace"
: > "$r2o_tmp/r2o.trace"

wait_for() {
    file=$1
    pattern=$2
    attempt=0
    while [ "$attempt" -lt 50 ]; do
        if grep -q "$pattern" "$file" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        attempt=$((attempt + 1))
    done
    return 1
}

show_logs() {
    for file in "$r2o_tmp"/*.log "$r2o_tmp"/*.trace; do
        if [ -f "$file" ]; then
            printf '\n--- %s ---\n' "$file" >&2
            cat "$file" >&2
        fi
    done
}

make -C "$r2o_donor_datapath" d2kd
cargo +1.98.0 build --locked -p r2o-datapath --bin r2o-datapath
gcc -shared -fPIC -O2 -Wall -Wextra -Werror \
    "$r2o_root/crates/r2o-datapath/tests/ct_retry_socket_shim.c" \
    -ldl -o "$r2o_tmp/ct-retry-shim.so"

root ip netns add "$r2o_namespace"
root ip -n "$r2o_namespace" link set lo up

root ip netns exec "$r2o_namespace" sh -c "echo \$\$ > \"\$1\"; shift; exec env \"\$@\"" sh \
    "$r2o_d2o_pidfile" \
    "LD_PRELOAD=$r2o_tmp/ct-retry-shim.so" \
    "R2O_CT_RETRY_TRACE=$r2o_tmp/d2o.trace" \
    "$r2o_donor_datapath/d2kd" --queue 1988 --mode observe --stats 0 \
    >"$r2o_tmp/d2o.log" 2>&1 &
r2o_d2o_launcher=$!
root ip netns exec "$r2o_namespace" sh -c "echo \$\$ > \"\$1\"; shift; exec env \"\$@\"" sh \
    "$r2o_r2o_pidfile" \
    "LD_PRELOAD=$r2o_tmp/ct-retry-shim.so" \
    "R2O_CT_RETRY_TRACE=$r2o_tmp/r2o.trace" \
    "$r2o_root/target/debug/r2o-datapath" --queue 1987 --mode observe --stats 0 \
    >"$r2o_tmp/r2o.log" 2>&1 &
r2o_r2o_launcher=$!

if ! wait_for "$r2o_tmp/d2o.trace" 'attempt 2' || ! wait_for "$r2o_tmp/r2o.trace" 'attempt 2'; then
    echo 'datapaths did not reach their initial ctnetlink probe' >&2
    show_logs
    exit 1
fi
if ! wait_for "$r2o_tmp/d2o.log" 'режим observe' || \
    ! wait_for "$r2o_tmp/r2o.log" 'режим observe'; then
    echo 'datapaths did not finish startup' >&2
    show_logs
    exit 1
fi

for priority in 1000 1001 1002; do
    root ip netns exec "$r2o_namespace" ip rule add pref "$priority" fwmark 0x66/0xffffffff table 100
    sleep 0.15
    root ip netns exec "$r2o_namespace" ip rule del pref "$priority" fwmark 0x66/0xffffffff table 100
    sleep 0.15
done

if ! wait_for "$r2o_tmp/d2o.log" 'ctnetlink появился' || \
    ! wait_for "$r2o_tmp/r2o.log" 'ctnetlink восстановлен'; then
    echo 'C/Rust conntrack recovery differed after route refresh' >&2
    show_logs
    exit 1
fi

wait_for "$r2o_tmp/d2o.trace" 'attempt 3'
wait_for "$r2o_tmp/r2o.trace" 'attempt 3'
echo 'D2O and R2O both recovered ctnetlink after the startup socket failure.'
