#!/bin/sh
# Periodically restore the R2O firewall when NDM misses its netfilter event.
set -u

ROOT=${R2O_DIR:-/opt/r2o}
CONF=${R2O_CONFIG:-$ROOT/config}
# shellcheck disable=SC1090  # конфигурация owner-managed, путь задаётся выше
[ ! -r "$CONF" ] || . "$CONF"
INIT=${R2O_INIT:-/opt/etc/init.d/S99r2o}
INTERVAL=${HEAL_EVERY:-60}
case "$INTERVAL" in ''|*[!0-9]*) INTERVAL=60 ;; esac
while [ "${INTERVAL#0}" != "$INTERVAL" ]; do INTERVAL=${INTERVAL#0}; done
[ -n "$INTERVAL" ] || INTERVAL=0
[ "$INTERVAL" -ge 1 ] && [ "$INTERVAL" -le 3600 ] || INTERVAL=60

tick() {
    "$INIT" firewall-heal >/dev/null 2>&1 || true
}

stop_watchdog() {
    if [ -n "$sleep_pid" ]; then
        kill "$sleep_pid" 2>/dev/null || true
        wait "$sleep_pid" 2>/dev/null || true
    fi
    exit 0
}

case "${1:-}" in
    tick) tick ;;
    run)
        sleep_pid=
        trap stop_watchdog HUP INT TERM
        while :; do
            tick
            sleep "$INTERVAL" &
            sleep_pid=$!
            wait "$sleep_pid" || true
            sleep_pid=
        done
        ;;
    *) echo "usage: $0 {tick|run}" >&2; exit 2 ;;
esac
