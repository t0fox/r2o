#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
fail() { echo "ОШИБКА: $*" >&2; exit 1; }

D2O_UPDATE=$D2O_ROOT/files/d2k-update.sh
R2O_INIT=$ROOT/router/S99r2o
[ -f "$D2O_UPDATE" ] || fail "не найден D2O updater $D2O_UPDATE"

tr -d '\r' < "$D2O_UPDATE" | sed -n '/^healthy() {/,$p' | sed '/^do_install() {/,$d' > "$TEMP/d2o-healthy.sh"
tr -d '\r' < "$R2O_INIT" | sed -n '/^wait_health() {/,$p' | sed '/^update_install() {/,$d' > "$TEMP/r2o-wait-health.sh"
tr -d '\r' < "$R2O_INIT" | sed -n '/^panel_start() {/,$p' | sed '/^start() {/,$d' > "$TEMP/r2o-panel-start.sh"
R2O_PANEL_DEFAULT=$(tr -d '\r' < "$R2O_INIT" | sed -n 's/^\(PANEL_LISTEN=.*\)$/\1/p' | tail -n 1)
[ -n "$R2O_PANEL_DEFAULT" ] || fail "не найдена инициализация PANEL_LISTEN в R2O"
. "$TEMP/d2o-healthy.sh"
. "$TEMP/r2o-wait-health.sh"
. "$TEMP/r2o-panel-start.sh"

sleep() { :; }
kill() { [ "${2:-}" = 101 ] || [ "${2:-}" = 102 ] || [ "${2:-}" = 103 ]; }
component_running() { return 0; }
queue_bound() { return 0; }
prepare_dirs() { :; }
log_maintenance_start() { :; }

mkdir -p "$TEMP/d2o/run" "$TEMP/r2o/runtime"
printf '101\n' > "$TEMP/d2o/run/d2kd.pid"
printf '102\n' > "$TEMP/d2o/run/d2k.pid"
DIR=$TEMP/d2o
HEALTH_WAIT=0
printf 'PANEL_LISTEN=\n' > "$DIR/config"
if ! healthy; then fail "D2O should accept a healthy datapath when PANEL_LISTEN is empty"; fi

printf 'PANEL_LISTEN=127.0.0.1:8090\n' > "$DIR/config"
if healthy; then fail "D2O should require the panel process when PANEL_LISTEN is configured"; fi
printf '103\n' > "$DIR/run/d2k-panel.pid"
healthy || fail "D2O rejected a configured, running panel"

# Evaluate the production default assignment after the sourced config.
unset PANEL_LISTEN
eval "$R2O_PANEL_DEFAULT"
[ "$PANEL_LISTEN" = 127.0.0.1:8090 ] || fail "R2O lost the default panel address when no value is configured"
PANEL_LISTEN=
eval "$R2O_PANEL_DEFAULT"
[ -z "$PANEL_LISTEN" ] || fail "R2O overwrote an explicitly empty PANEL_LISTEN with its default"
component_running() { return 1; }
spawn_component() { : > "$TEMP/panel-spawned"; }
panel_start || fail "R2O treated a disabled panel as a service start failure"
[ ! -e "$TEMP/panel-spawned" ] || fail "R2O attempted to spawn a disabled panel"
component_running() { return 0; }
RUNTIME=$TEMP/r2o/runtime
QUEUE4=2000
IPV6_ENABLED=0
DP4_PID=$TEMP/r2o/dp.pid
CT4_PID=$TEMP/r2o/ct.pid
wait_health || fail "R2O rejected a healthy datapath when PANEL_LISTEN is empty"

PANEL_LISTEN=127.0.0.1:8090
if wait_health; then fail "R2O accepted an enabled panel without panel health"; fi
printf 'healthy\n' > "$RUNTIME/r2o-panel.health"
wait_health || fail "R2O rejected a configured, healthy panel"

echo "D2O и R2O одинаково трактуют выключенную панель при проверке health обновления"
