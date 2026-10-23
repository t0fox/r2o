#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT/target"}
TEST_BIN=
NS="r2o-raw-mtu-$$"

for candidate in "$TARGET_DIR"/debug/deps/raw_egress_mtu-*; do
    case "$candidate" in
        *.d) continue ;;
    esac
    if [ -x "$candidate" ]; then
        if [ -n "$TEST_BIN" ]; then
            echo "найдено несколько исполняемых тестов raw_egress_mtu" >&2
            exit 2
        fi
        TEST_BIN=$candidate
    fi
done
if [ -z "$TEST_BIN" ]; then
    echo "сначала соберите тест: cargo test --no-run --locked --package r2o-datapath --test raw_egress_mtu" >&2
    exit 2
fi

cleanup() {
    if ip netns list | awk '{print $1}' | grep -Fxq "$NS"; then
        ip netns pids "$NS" | xargs -r kill 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

if [ "$(id -u)" -ne 0 ]; then
    echo "запустите от root, например: sudo sh scripts/test-raw-egress-mtu-netns.sh" >&2
    exit 1
fi
command -v ip >/dev/null 2>&1 || {
    echo "не найдена обязательная команда: ip" >&2
    exit 1
}

ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link add d2klow type dummy
ip netns exec "$NS" ip link set d2klow mtu 1280 up
ip netns exec "$NS" ip link add d2kout type dummy
ip netns exec "$NS" ip link set d2kout mtu 1500 up
ip netns exec "$NS" "$TEST_BIN" raw_socket_tracks_egress_mtu_and_respects_explicit_interface \
    --exact --ignored --nocapture
echo "raw egress MTU namespace test: ok"
