#!/bin/sh
# B40: uninstall без shim/активного адаптера продолжает аварийную очистку.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    [ -z "${sleep_pid:-}" ] || kill "$sleep_pid" 2>/dev/null || true
    rm -rf "$TEMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

install_root=$TEMP/r2o
mkdir -p "$install_root/releases/test/router" "$install_root/run" "$TEMP/init" "$TEMP/openwrt-init"
printf 'R2O-RELEASE-SLOTS-1\ntest\n' > "$install_root/release-slots"
/bin/sleep 30 &
sleep_pid=$!
printf '%s\n' "$sleep_pid" > "$install_root/run/r2o-datapath4.pid"

env R2O_INIT_DIR="$TEMP/init" R2O_OPENWRT_INIT_DIR="$TEMP/openwrt-init" \
    R2O_OPENWRT_RELEASE="$TEMP/missing-openwrt-release" \
    R2O_RUNTIME_DIR="$TEMP/r2o-runtime" R2O_NDM_DIR="$TEMP/ndm" \
    sh "$ROOT/router/uninstall.sh" --root "$install_root" --yes

[ ! -e "$install_root" ] || { echo "uninstall оставил каталог установки" >&2; exit 1; }
if kill -0 "$sleep_pid" 2>/dev/null; then
    echo "uninstall не остановил процесс из PID-файла" >&2
    exit 1
fi
sleep_pid=
echo "uninstall без адаптера выполнил аварийную остановку и удалил установку"
