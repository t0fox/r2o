#!/bin/sh
# Проверка подписанных релизов раз в сутки в окне 03:00–04:59 роутера.
set -eu

ROOT=${R2O_DIR:-/opt/r2o}
CONF=${R2O_CONFIG:-$ROOT/config}
STATE_DIR=${STATE_DIR:-$ROOT/state}
MANAGER=${R2O_MANAGER:-$ROOT/r2o-manager}
INIT=${R2O_INIT:-/opt/etc/init.d/S99r2o}
DATE_BIN=${R2O_UPDATE_DATE:-date}
SLEEP_BIN=${R2O_SLEEP:-sleep}
START_STOP_DAEMON=${R2O_START_STOP_DAEMON:-start-stop-daemon}
TICK=${R2O_UPDATE_TICK:-60}
MARKER=$STATE_DIR/update-night
LOG=$ROOT/log/update-scheduler.log

case "$TICK" in ''|*[!0-9]*) echo "неверный интервал планировщика обновлений" >&2; exit 2 ;; esac
# shellcheck disable=SC2015 # reject values outside the inclusive interval range
[ "$TICK" -ge 1 ] && [ "$TICK" -le 3600 ] || { echo "неверный интервал планировщика обновлений" >&2; exit 2; }

log() {
    mkdir -p "$ROOT/log" 2>/dev/null || return 0
    printf '[%s] %s\n' "$("$DATE_BIN" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo неизвестно)" "$1" >> "$LOG"
}

auto_update_enabled() {
    AUTOUPDATE=1
    # shellcheck disable=SC1090 # the config path is selected by the runtime environment
    [ ! -r "$CONF" ] || . "$CONF"
    case "${AUTOUPDATE:-1}" in
        1|yes) AUTOUPDATE=1 ;;
        0|no) AUTOUPDATE=0 ;;
        *) AUTOUPDATE=0; log "AUTOUPDATE должен быть 0, 1, yes или no" ;;
    esac
}

tick() {
    hour=$("$DATE_BIN" +%H) || return 1
    case "$hour" in 03|04) ;; *) return 0 ;; esac
    day=$("$DATE_BIN" +%Y%m%d) || return 1
    case "$day" in ????????) ;; *) log "неверная дата системных часов"; return 1 ;; esac
    case "$day" in *[!0-9]*) log "неверная дата системных часов"; return 1 ;; esac
    mkdir -p "$STATE_DIR" "$ROOT/log" || return 1
    previous=$(cat "$MARKER" 2>/dev/null || true)
    [ "$previous" != "$day" ] || return 0
    temporary=$MARKER.new.$$
    (umask 077; printf '%s\n' "$day" > "$temporary") || return 1
    mv -f "$temporary" "$MARKER" || { rm -f "$temporary"; return 1; }

    if ! result=$("$MANAGER" update-check --root "$ROOT" 2>>"$LOG"); then
        log "ночная проверка обновлений не удалась"
        return 0
    fi
    case "$result" in
        *'"update_available":true'*) ;;
        *) log "нового релиза нет"; return 0 ;;
    esac
    auto_update_enabled
    if [ "$AUTOUPDATE" = 1 ]; then
        case "$result" in
            *'"auto_retry_blocked":true'*) log "ночной повтор релиза после отказа runtime-проверки пропущен"; return 0 ;;
        esac
        "$START_STOP_DAEMON" -S -b -x "$INIT" -- update-install-auto >>"$LOG" 2>&1 ||
            log "не удалось запустить ночную установку обновления"
    else
        log "доступен новый релиз; ночная установка выключена"
    fi
}

case "${1:-run}" in
    tick) tick ;;
    run)
        sleep_pid=
        stop_scheduler() {
            if [ -n "$sleep_pid" ]; then
                kill "$sleep_pid" 2>/dev/null || true
                wait "$sleep_pid" 2>/dev/null || true
            fi
            exit 0
        }
        trap 'stop_scheduler' INT TERM HUP
        while :; do
            tick || log "ошибка ночной проверки расписания"
            "$SLEEP_BIN" "$TICK" &
            sleep_pid=$!
            wait "$sleep_pid" || true
            sleep_pid=
        done
        ;;
    *) echo "использование: $0 {run|tick}" >&2; exit 2 ;;
esac
