#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-telegram-stop.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

sed -n '/^telegram_stop() {/,/^}/p' "$D2O_ROOT/files/S99d2k" | sed 's/\r$//' > "$TEMP/d2o-function.sh"
sed -n '/^telegram_stop() {/,/^}/p' "$ROOT/router/S99r2o" | sed 's/\r$//' > "$TEMP/r2o-function.sh"
[ -s "$TEMP/d2o-function.sh" ] && [ -s "$TEMP/r2o-function.sh" ] || {
    echo 'telegram_stop function extraction failed' >&2
    exit 2
}
cat > "$TEMP/firewall" <<'FIREWALL'
#!/bin/sh
printf 'firewall_stop\n' >> "$TRACE"
exit 1
FIREWALL
chmod 700 "$TEMP/firewall"

cat > "$TEMP/driver" <<'DRIVER'
#!/bin/sh
set -eu
function_file=$1
trace=$2
export TRACE=$trace
TG_WD_PID=watchdog.pid
TG_PID=telegram.pid
TG_FIREWALL=$FIREWALL_PATH
TG_STATUS=status.path
TG_STATS_SOCKET=stats.sock
stop_pidfile() {
    case "$1" in
        "$TG_WD_PID") printf 'watchdog_stop\n' >> "$TRACE" ;;
        "$TG_PID") printf 'telegram_stop\n' >> "$TRACE" ;;
        *) printf 'unknown_stop:%s\n' "$1" >> "$TRACE"; return 2 ;;
    esac
}
telegram_watchdog_stop() { printf 'watchdog_stop\n' >> "$TRACE"; }
stop_component() {
    [ "$1" = r2o-telegram ] || return 2
    printf 'telegram_stop\n' >> "$TRACE"
}
write_telegram_status() { printf 'status_%s\n' "$1" >> "$TRACE"; }
say() { :; }
. "$function_file"
if telegram_stop; then result=0; else result=$?; fi
printf 'result_%s\n' "$result" >> "$TRACE"
DRIVER
chmod 700 "$TEMP/driver"

FIREWALL_PATH="$TEMP/firewall" "$TEMP/driver" \
    "$TEMP/d2o-function.sh" "$TEMP/d2o.trace"
FIREWALL_PATH="$TEMP/firewall" "$TEMP/driver" \
    "$TEMP/r2o-function.sh" "$TEMP/r2o.trace"

if ! cmp -s "$TEMP/d2o.trace" "$TEMP/r2o.trace"; then
    printf '%s\n' 'D2O telegram_stop:' >&2
    cat "$TEMP/d2o.trace" >&2
    printf '%s\n' 'R2O telegram_stop:' >&2
    cat "$TEMP/r2o.trace" >&2
    diff -u "$TEMP/d2o.trace" "$TEMP/r2o.trace" >&2 || true
    exit 1
fi

printf 'D2O/R2O Telegram stop behavior matches %s.\n' "$ACTUAL_D2O_SHA"
