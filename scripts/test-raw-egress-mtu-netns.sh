#!/bin/sh
# Живая проверка egress MTU/adopt в изолированном netns.
#
# Без root переисполняется через `unshare -Urn` (user+network namespace).
set -eu

if [ -z "${R2O_IN_USERNS:-}" ] && [ "$(id -u)" -ne 0 ]; then
    R2O_IN_USERNS=1 exec unshare -Urn sh "$0" "$@"
fi

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

command -v ip >/dev/null 2>&1 || {
    echo "не найдена обязательная команда: ip" >&2
    exit 1
}

cleanup_direct() {
    ip link del d2klow 2>/dev/null || true
    ip link del d2kout 2>/dev/null || true
}
cleanup_named() {
    if ip netns list | awk '{print $1}' | grep -Fxq "$NS"; then
        ip netns pids "$NS" | xargs -r kill 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
}

if [ "${R2O_IN_USERNS:-0}" = 1 ] || [ "${R2O_NO_NAMED_NETNS:-0}" = 1 ]; then
    # В user namespace `ip netns add` требует записи в /run/netns (недоступно);
    # создаём dummy-интерфейсы прямо в текущем netns.
    trap cleanup_direct EXIT HUP INT TERM
    ip link set lo up 2>/dev/null || true
    ip link add d2klow type dummy
    ip link set d2klow mtu 1280 up
    ip link add d2kout type dummy
    ip link set d2kout mtu 1500 up
    "$TEST_BIN" raw_socket_tracks_egress_mtu_and_respects_explicit_interface \
        --exact --ignored --nocapture
else
    trap cleanup_named EXIT HUP INT TERM
    ip netns add "$NS"
    ip netns exec "$NS" ip link set lo up
    ip netns exec "$NS" ip link add d2klow type dummy
    ip netns exec "$NS" ip link set d2klow mtu 1280 up
    ip netns exec "$NS" ip link add d2kout type dummy
    ip netns exec "$NS" ip link set d2kout mtu 1500 up
    ip netns exec "$NS" "$TEST_BIN" raw_socket_tracks_egress_mtu_and_respects_explicit_interface \
        --exact --ignored --nocapture
fi
echo "raw egress MTU namespace test: ok"
