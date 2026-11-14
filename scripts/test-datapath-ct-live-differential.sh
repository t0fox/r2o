#!/bin/sh
# C/Rust differential: живой ctnetlink (open/probe 200 мс/query) в netns.
#
# Дополнительно создаются две реальные conntrack-записи через veth/вложенный
# netns: flow1 при nf_conntrack_acct=0 (запись без счётчиков, rc=2), flow2 при
# acct=1 (rc=0 со счётчиками). Без root скрипт переисполняется через
# `unshare -Urn`.
#
# ВАЖНО: все C/Rust бинарники собираются ДО создания conntrack-записей.
# Иначе cargo test --no-run занимает десятки секунд, UDP-записи истекают
# (nf_conntrack_udp_timeout=30) и Rust видит ENOENT вместо NoCounters/Info.
set -eu

if [ -z "${R2O_IN_USERNS:-}" ] && [ "$(id -u)" -ne 0 ]; then
    R2O_IN_USERNS=1 exec unshare -Urn sh "$0" "$@"
fi

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
DONOR_DATAPATH=${R2O_DONOR_DATAPATH:-"$D2O_ROOT/datapath"}
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}
# Уникальные порты на прогон: при запуске от root старые записи в общем netns
# не должны переиспользоваться новым flow.
PORT_BASE=${R2O_CT_LIVE_PORT_BASE:-$((40000 + (($$ % 4000) / 4) * 4))}
CHILD_PID=
CHILD_NS=
FLOW1=
FLOW2=
ACCT_SAVED=
UDP_TIMEOUT_SAVED=
UDP_STREAM_SAVED=

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

ip link set lo up 2>/dev/null || true
mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-ct-live.XXXXXX")
cleanup() {
    if [ -n "$CHILD_PID" ]; then
        kill "$CHILD_PID" 2>/dev/null || true
        wait "$CHILD_PID" 2>/dev/null || true
    fi
    nft delete table ip r2oct 2>/dev/null || true
    ip link del v0 2>/dev/null || true
    restore_sysctl /proc/sys/net/netfilter/nf_conntrack_acct "$ACCT_SAVED"
    restore_sysctl /proc/sys/net/netfilter/nf_conntrack_udp_timeout "$UDP_TIMEOUT_SAVED"
    restore_sysctl /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream "$UDP_STREAM_SAVED"
    rm -rf -- "$TEMP"
}
trap cleanup EXIT HUP INT TERM

restore_sysctl() {
    file=$1
    value=$2
    if [ -n "$value" ]; then
        printf '%s\n' "$value" >"$file" 2>/dev/null || true
    fi
}

save_sysctl() {
    file=$1
    if [ -r "$file" ]; then
        cat "$file" 2>/dev/null || true
    fi
}

# 1. Собрать ВСЕ бинарники до создания conntrack-записей.
cd "$ROOT"
"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$DONOR_DATAPATH/include" \
    -o "$TEMP/d2o-ct-live" \
    "$ROOT/crates/r2o-datapath/tests/d2o_ct_live_differential.c" \
    "$DONOR_DATAPATH/ctq.c" "$DONOR_DATAPATH/nl.c"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --test d2o_conntrack --no-run >"$TEMP/build.log" 2>&1
RUST_BIN=$(sed -n 's/.*Executable tests\/d2o_conntrack.rs (\(.*\))/\1/p' \
    "$TEMP/build.log" | tail -1)
if [ -z "$RUST_BIN" ]; then
    echo "не найден тестовый бинарник d2o_conntrack" >&2
    cat "$TEMP/build.log" >&2
    exit 2
fi
case "$RUST_BIN" in
    /*) ;;
    *) RUST_BIN="$ROOT/$RUST_BIN" ;;
esac
[ -x "$RUST_BIN" ] || {
    echo "тестовый бинарник не исполняется: $RUST_BIN" >&2
    exit 2
}

create_flow() {
    port_rx=$1
    port_tx=$2
    timeout 5 nsenter -t "$CHILD_NS" -n python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.1.1.2", int(sys.argv[1])))
print("ready", flush=True)
s.recv(64)
' "$port_rx" >"$TEMP/recv-$port_rx.out" 2>&1 &
    recv_pid=$!
    attempt=0
    while ! grep -q ready "$TEMP/recv-$port_rx.out" 2>/dev/null; do
        sleep 0.05
        attempt=$((attempt + 1))
        if [ "$attempt" -gt 200 ]; then return 1; fi
    done
    python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.1.1.1", int(sys.argv[1])))
s.sendto(b"ct-live", ("10.1.1.2", int(sys.argv[2])))
' "$port_tx" "$port_rx"
    wait "$recv_pid" 2>/dev/null || true
}

setup_flows() {
    command -v nsenter >/dev/null 2>&1 || return 1
    command -v nft >/dev/null 2>&1 || return 1
    nft delete table ip r2oct 2>/dev/null || true
    ip link add v0 type veth peer name v1 || return 1
    pidfile="$TEMP/child.pid"
    unshare -n sh -c 'echo $$ > "$1"; exec sleep 60' sh "$pidfile" &
    CHILD_PID=$!
    attempt=0
    while [ ! -s "$pidfile" ]; do
        sleep 0.05
        attempt=$((attempt + 1))
        if [ "$attempt" -gt 200 ]; then return 1; fi
    done
    CHILD_NS=$(cat "$pidfile")
    ip link set v1 netns "$CHILD_NS" || return 1
    ip addr add 10.1.1.1/24 dev v0
    ip link set v0 up
    nsenter -t "$CHILD_NS" -n ip link set lo up
    nsenter -t "$CHILD_NS" -n ip link set v1 up
    nsenter -t "$CHILD_NS" -n ip addr add 10.1.1.2/24 dev v1
    nft add table ip r2oct
    nft add chain ip r2oct out "{ type filter hook output priority -200 ; }"
    nft add rule ip r2oct out ct state new accept

    # 2. Записи не должны истечь между C и Rust (по умолчанию 30/120 с).
    ACCT_SAVED=$(save_sysctl /proc/sys/net/netfilter/nf_conntrack_acct)
    UDP_TIMEOUT_SAVED=$(save_sysctl /proc/sys/net/netfilter/nf_conntrack_udp_timeout)
    UDP_STREAM_SAVED=$(save_sysctl /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream)
    if [ -w /proc/sys/net/netfilter/nf_conntrack_udp_timeout ]; then
        echo 300 >/proc/sys/net/netfilter/nf_conntrack_udp_timeout
    fi
    if [ -w /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream ]; then
        echo 300 >/proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream
    fi

    echo 0 > /proc/sys/net/netfilter/nf_conntrack_acct
    create_flow "$((PORT_BASE + 0))" "$((PORT_BASE + 1))" || return 1
    echo 1 > /proc/sys/net/netfilter/nf_conntrack_acct
    create_flow "$((PORT_BASE + 2))" "$((PORT_BASE + 3))" || return 1
    FLOW1="10.1.1.1 $((PORT_BASE + 1)) 10.1.1.2 $((PORT_BASE + 0))"
    FLOW2="10.1.1.1 $((PORT_BASE + 3)) 10.1.1.2 $((PORT_BASE + 2))"
    return 0
}

if setup_flows; then
    export R2O_CT_LIVE_FLOW1="$FLOW1"
    export R2O_CT_LIVE_FLOW2="$FLOW2"
else
    echo "live flow phase skipped: veth/nsenter/nft unavailable" >&2
fi

# 3. C и Rust запускаются сразу друг за другом, без компиляции между ними.
"$TEMP/d2o-ct-live" >"$TEMP/c.out"
R2O_CT_LIVE_DIFF_OUTPUT="$TEMP/rust.out" \
    "$RUST_BIN" --ignored --exact ct_live_probe_and_query_match_d2o \
    >"$TEMP/rust.log" 2>&1

if [ "${R2O_SHOW_OUTPUT:-0}" = 1 ]; then
    cat "$TEMP/c.out"
fi
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: live ctnetlink C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
