#!/bin/bash
set -euo pipefail

ROOT=$(cd -P "$(dirname "$0")/.." && pwd)
TEMP_ROOT=$(dirname "$ROOT")/r2o-tooling/tests
mkdir -p "$TEMP_ROOT"
TEMP=$(mktemp -d "$TEMP_ROOT/r2o-openwrt-init.XXXXXX")
case "$TEMP" in "$TEMP_ROOT"/r2o-openwrt-init.*) ;; *) exit 2 ;; esac
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

TEST_INIT=$TEMP/openwrt-init
SERVICE=$TEMP/S99r2o
MANAGER=$TEMP/r2o-manager
CONFIG=$TEMP/config
CALLS=$TEMP/calls
export CALLS
sed \
    -e "s#/opt/etc/init.d/S99r2o#$SERVICE#g" \
    -e "s#/opt/r2o/r2o-manager#$MANAGER#g" \
    -e "s#/opt/r2o/config#$CONFIG#g" \
    "$ROOT/router/openwrt-init" > "$TEST_INIT"

EXTRA_COMMANDS=
extra_command() {
    EXTRA_COMMANDS="${EXTRA_COMMANDS:+$EXTRA_COMMANDS }$1"
}
procd_open_instance() { printf 'open:%s\n' "$1" >> "$CALLS"; }
procd_set_param() { printf 'param:%s\n' "$*" >> "$CALLS"; }
procd_close_instance() { printf 'close\n' >> "$CALLS"; }
procd_kill() { printf 'kill:%s/%s\n' "$1" "${2:-}" >> "$CALLS"; }
fail() { printf 'openwrt-init: %s\n' "$*" >&2; exit 1; }

# shellcheck source=../router/openwrt-init
. "$TEST_INIT"
case " $EXTRA_COMMANDS " in
    *" boot_wait "*) ;;
    *) fail "rc.common does not register boot_wait as an allowed action" ;;
esac

start_service
grep -q '^param:command /bin/sh /etc/rc.common /etc/init.d/r2o boot_wait$' "$CALLS" ||
    fail "procd boot worker does not dispatch boot_wait"
if grep -q 'respawn' "$CALLS"; then
    fail "one-shot boot worker unexpectedly requests procd respawn"
fi

TEST_PATH=$PATH
sleep() {
    [ ! -e "/proc/$$/fd/1000" ] || fail "boot worker inherited the procd lock"
    [ -z "${LD_PRELOAD+x}" ] || fail "boot worker inherited LD_PRELOAD"
    printf '#!/bin/sh\nprintf "service-%%s\\n" "$1" >> "$CALLS"\n' > "$SERVICE"
    chmod 0755 "$SERVICE"
    printf '#!/bin/sh\nexit 0\n' > "$MANAGER"
    chmod 0755 "$MANAGER"
    : > "$CONFIG"
}
exec 1000>"$TEMP/procd.lock"
export LD_PRELOAD=must-be-cleared
boot_wait
PATH=$TEST_PATH
unset LD_PRELOAD

grep -qx 'service-start' "$CALLS" || fail "boot_wait did not start R2O after files appeared"
: > "$CALLS"
stop_service
grep -qx 'kill:r2o/boot' "$CALLS" || fail "stop_service did not cancel the boot worker first"
grep -qx 'service-stop' "$CALLS" || fail "stop_service did not stop R2O"
printf '%s\n' 'R2O OpenWrt boot bridge: command registration, delayed /opt, lock/preload isolation, and stop: PASS'
