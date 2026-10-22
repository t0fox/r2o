#!/bin/sh
# Keep the local Rust Telegram listener and its firewall rules healthy.
set -u
umask 077

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

ROOT=${R2O_DIR:-/opt/r2o}
CONF=${R2O_CONFIG:-$ROOT/config}
# shellcheck disable=SC1090  # конфигурация owner-managed, путь задаётся выше
[ ! -r "$CONF" ] || . "$CONF"
RUN=${R2O_RUN_DIR:-$ROOT/run}
STATE_DIR=${STATE_DIR:-$ROOT/state}
INIT=${R2O_INIT:-/opt/etc/init.d/S99r2o}
MANAGER=${R2O_MANAGER:-$ROOT/r2o-manager}
PROC=${R2O_PROC:-/proc}
TG_ENABLED=${TG_ENABLED:-0}
TG_MODE=${TG_MODE:-local}
TG_PID=$RUN/r2o-telegram.pid
TG_STATS_SOCKET=${TG_STATS_SOCKET:-$STATE_DIR/telegram.stats.sock}
TG_FIREWALL=${R2O_TG_FIREWALL:-$SCRIPT_DIR/r2o-tg-firewall.sh}
FAILURES=$STATE_DIR/telegram-health.failures
RESTARTS=$STATE_DIR/telegram-health.restarts
LIMITED=$STATE_DIR/telegram-health.restart-limited

bounded_setting() {
    setting_value=$1
    setting_default=$2
    setting_max=$3
    case "$setting_value" in ''|*[!0-9]*) setting_value=$setting_default ;; esac
    while [ "${setting_value#0}" != "$setting_value" ]; do setting_value=${setting_value#0}; done
    [ -n "$setting_value" ] || setting_value=0
    if [ "${#setting_value}" -gt "${#setting_max}" ] ||
       { [ "${#setting_value}" -eq "${#setting_max}" ] && [ "$setting_value" -gt "$setting_max" ]; }; then
        setting_value=$setting_max
    fi
    printf '%s\n' "$setting_value"
}

INTERVAL=$(bounded_setting "${TG_WATCHDOG_INTERVAL:-60}" 60 3600)
FAILURE_LIMIT=$(bounded_setting "${TG_WATCHDOG_FAILURE_LIMIT:-3}" 3 10)
RESTART_WINDOW=$(bounded_setting "${TG_WATCHDOG_RESTART_WINDOW:-900}" 900 86400)
MAX_RESTARTS=$(bounded_setting "${TG_WATCHDOG_MAX_RESTARTS:-3}" 3 10)
BACKOFF_BASE=$(bounded_setting "${TG_WATCHDOG_BACKOFF_BASE:-60}" 60 3600)
BACKOFF_MAX=$(bounded_setting "${TG_WATCHDOG_BACKOFF_MAX:-300}" 300 3600)
[ "$INTERVAL" -ge 1 ] || INTERVAL=60
[ "$FAILURE_LIMIT" -ge 1 ] || FAILURE_LIMIT=3
[ "$RESTART_WINDOW" -ge 1 ] || RESTART_WINDOW=900
[ "$MAX_RESTARTS" -ge 1 ] || MAX_RESTARTS=3
[ "$BACKOFF_BASE" -ge 1 ] || BACKOFF_BASE=60
[ "$BACKOFF_MAX" -ge "$BACKOFF_BASE" ] || BACKOFF_MAX=$BACKOFF_BASE

is_uint() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
}

watchdog_log() {
    if command -v logger >/dev/null 2>&1; then
        logger -t r2o-telegram-watchdog "$1" 2>/dev/null || true
    fi
}

telegram_configured() {
    case "$TG_ENABLED" in 1|yes) ;; *) return 1 ;; esac
    [ "$TG_MODE" = local ]
}

telegram_ready() {
    telegram_configured || return 1
    [ -r "$TG_PID" ] || return 1
    tg_pid=$(cat "$TG_PID" 2>/dev/null) || return 1
    is_uint "$tg_pid" && [ "$tg_pid" -gt 1 ] || return 1
    kill -0 "$tg_pid" 2>/dev/null || return 1
    tg_exe=$(readlink "$PROC/$tg_pid/exe" 2>/dev/null) || return 1
    case "$tg_exe" in "$ROOT"/releases/*/builds/r2o-telegram-linux-*) ;; *) return 1 ;; esac
    tg_snapshot=$("$MANAGER" exec --root "$ROOT" --component r2o-telegram -- \
        --stats --stats-socket-path "$TG_STATS_SOCKET" 2>/dev/null) || return 1
    case "$tg_snapshot" in *'"listener_ready":true'*) return 0 ;; *) return 1 ;; esac
}

reserve_restart_slot() {
    now=$(date +%s 2>/dev/null) || return 1
    is_uint "$now" || return 1
    mkdir -p "$STATE_DIR" || return 1
    temporary=$(mktemp "$RESTARTS.tmp.XXXXXX") || return 1
    recent=0
    if [ -r "$RESTARTS" ]; then
        while IFS= read -r stamp; do
            is_uint "$stamp" || continue
            [ "${#stamp}" -le 12 ] || continue
            while [ "${stamp#0}" != "$stamp" ]; do stamp=${stamp#0}; done
            [ -n "$stamp" ] || stamp=0
            age=$((now - stamp))
            if [ "$age" -ge 0 ] && [ "$age" -lt "$RESTART_WINDOW" ]; then
                printf '%s\n' "$stamp" >> "$temporary" || { rm -f "$temporary"; return 1; }
                recent=$((recent + 1))
            fi
        done < "$RESTARTS"
    fi
    if [ "$recent" -ge "$MAX_RESTARTS" ]; then
        mv -f "$temporary" "$RESTARTS" || { rm -f "$temporary"; return 1; }
        RESTART_COUNT=$recent
        return 2
    fi
    printf '%s\n' "$now" >> "$temporary" || { rm -f "$temporary"; return 1; }
    mv -f "$temporary" "$RESTARTS" || { rm -f "$temporary"; return 1; }
    RESTART_COUNT=$((recent + 1))
    return 0
}

write_failures() {
    temporary=$(mktemp "$FAILURES.tmp.XXXXXX") || return 1
    printf '%s\n' "$failures" > "$temporary" || { rm -f "$temporary"; return 1; }
    mv -f "$temporary" "$FAILURES"
}

tick() {
    telegram_configured || { failures=0; rm -f "$FAILURES" "$LIMITED"; return 0; }
    if [ -x "$TG_FIREWALL" ]; then
        "$TG_FIREWALL" heal >/dev/null 2>&1 || true
    fi
    if telegram_ready; then
        failures=0
        rm -f "$FAILURES" "$LIMITED"
        return 0
    fi

    [ "$failures" -ge "$FAILURE_LIMIT" ] || failures=$((failures + 1))
    write_failures || return 1
    [ "$failures" -ge "$FAILURE_LIMIT" ] || return 0

    reserve_restart_slot
    slot_status=$?
    if [ "$slot_status" -eq 0 ]; then
        watchdog_log "listener Telegram не отвечает; восстановление $RESTART_COUNT/$MAX_RESTARTS"
        "$INIT" telegram-reapply >/dev/null 2>&1 || watchdog_log "восстановление Telegram завершилось ошибкой"
        failures=0
        rm -f "$FAILURES"
        backoff=$BACKOFF_BASE
        step=1
        while [ "$step" -lt "$RESTART_COUNT" ] && [ "$backoff" -lt "$BACKOFF_MAX" ]; do
            backoff=$((backoff * 2))
            [ "$backoff" -le "$BACKOFF_MAX" ] || backoff=$BACKOFF_MAX
            step=$((step + 1))
        done
        sleep "$backoff"
    elif [ "$slot_status" -eq 2 ] && [ ! -e "$LIMITED" ]; then
        watchdog_log "достигнут лимит перезапусков Telegram; новые попытки отложены"
        : > "$LIMITED"
    fi
}

stop_watchdog() {
    if [ -n "$sleep_pid" ]; then
        kill "$sleep_pid" 2>/dev/null || true
        wait "$sleep_pid" 2>/dev/null || true
    fi
    exit 0
}

failures=0
if [ -r "$FAILURES" ]; then
    read -r failures < "$FAILURES" || failures=0
    failures=$(bounded_setting "$failures" 0 "$FAILURE_LIMIT")
fi
mkdir -p "$STATE_DIR" 2>/dev/null || exit 1

case "${1:-}" in
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
    *) echo "usage: $0 run" >&2; exit 2 ;;
esac
