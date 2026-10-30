#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TG_BIN=${R2O_TG_TEST_BINARY:-$ROOT/target/release/r2o-telegram}
[ -x "$TG_BIN" ] || { echo "требуется release-бинарный файл r2o-telegram: $TG_BIN" >&2; exit 2; }
fail() { echo "ОШИБКА: $*" >&2; exit 1; }
TEMP=$(mktemp -d)
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    env R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/root/config" \
        R2O_MANAGER="$TEMP/manager" R2O_TG_TEST_BINARY="$TEMP/root/releases/test/builds/r2o-telegram-linux-test" \
        R2O_TG_FIREWALL="$TEMP/tg-firewall" R2O_INIT="$TEMP/init-wrapper" \
        R2O_PROC=/proc R2O_RUNTIME_DIR="$TEMP/runtime" \
        sh "$ROOT/router/S99r2o" telegram-disable >/dev/null 2>&1 || true
    if [ "$result" -ne 0 ] && [ -f "$TEMP/root/log/telegram.log" ]; then
        cat "$TEMP/root/log/telegram.log" >&2
    fi
    rm -rf "$TEMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM
cat > "$TEMP/init-wrapper" <<EOF
#!/bin/sh
exec sh "$ROOT/router/S99r2o" "\$@"
EOF
chmod 0755 "$TEMP/init-wrapper"
mkdir -p "$TEMP/root/releases/test/builds" "$TEMP/root/state"
cp "$TG_BIN" "$TEMP/root/releases/test/builds/r2o-telegram-linux-test"
printf 'TG_ENABLED=0\nTG_MODE=local\nTG_PORT=30443\nSTATE_DIR=%s\n' \
    "$TEMP/root/state" > "$TEMP/root/config"

cat > "$TEMP/manager" <<'EOF'
#!/bin/sh
case "${1:-}" in
    exec)
        shift
        component=
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --component) component=$2; shift 2 ;;
                --) shift; break ;;
                *) shift ;;
            esac
        done
        [ "$component" = r2o-telegram ] || exit 2
        case "$*" in
            *--check*)
                printf '%s\n' '{"checked_at":1800000000,"state":"partial","data_centers":[{"dc":1,"state":"healthy","routes":[]},{"dc":2,"state":"healthy","routes":[]},{"dc":3,"state":"unavailable","routes":[]},{"dc":4,"state":"healthy","routes":[]},{"dc":5,"state":"healthy","routes":[]}]}'
                exit 2 ;;
            *--stats*)
                if [ -n "${R2O_TG_MANAGER_FAIL:-}" ] && [ -e "$R2O_TG_MANAGER_FAIL" ]; then exit 1; fi
                ;;
        esac
        if [ -n "${R2O_TG_ENV_CAPTURE:-}" ]; then
            printf '%s|%s\n' "${R2O_TG_DC_MAP_SYNC:-}" "${R2O_TG_DC_MAP_ENDPOINTS_PATH:-}" >> "$R2O_TG_ENV_CAPTURE"
        fi
        exec "$R2O_TG_TEST_BINARY" "$@" ;;
    *) echo "неподдерживаемое действие тестового менеджера" >&2; exit 2 ;;
esac
EOF
cat > "$TEMP/tg-firewall" <<'EOF'
#!/bin/sh
printf '%s\n' "$1" >> "$TG_FW_CALLS"
[ "$1" != stop ] || [ -z "${R2O_TG_FIREWALL_FAIL:-}" ] || [ ! -e "$R2O_TG_FIREWALL_FAIL" ] || exit 1
exit 0
EOF
chmod 0755 "$TEMP/manager" "$TEMP/tg-firewall"

run_service() {
    env R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/root/config" \
        R2O_MANAGER="$TEMP/manager" R2O_TG_TEST_BINARY="$TEMP/root/releases/test/builds/r2o-telegram-linux-test" \
        R2O_TG_FIREWALL="$TEMP/tg-firewall" R2O_PROC=/proc \
        R2O_INIT="$TEMP/init-wrapper" \
        R2O_TG_MANAGER_FAIL="$TEMP/manager-fail" \
        R2O_TG_FIREWALL_FAIL="$TEMP/firewall-fail" \
        TG_WATCHDOG_INTERVAL=1 TG_WATCHDOG_FAILURE_LIMIT=1 \
        TG_WATCHDOG_RESTART_WINDOW=60 TG_WATCHDOG_MAX_RESTARTS=2 \
        TG_WATCHDOG_BACKOFF_BASE=1 TG_WATCHDOG_BACKOFF_MAX=1 \
        R2O_RUNTIME_DIR="$TEMP/runtime" R2O_TG_ENV_CAPTURE="$TEMP/tg-env-capture" \
        R2O_NFQUEUE_STATUS=/dev/null TG_FW_CALLS="$TEMP/firewall-calls" \
        sh "$ROOT/router/S99r2o" "$1"
}

run_service telegram-enable
grep -q '^TG_ENABLED=1$' "$TEMP/root/config"
grep -q '^local$' "$TEMP/root/state/telegram.status"
[ -s "$TEMP/root/run/r2o-telegram.pid" ]
[ -s "$TEMP/root/run/r2o-telegram-watchdog.pid" ]
run_service telegram-check
python3 - "$TEMP/root/state/telegram-diagnostics.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as report_file:
    report = json.load(report_file)
assert report["state"] == "partial"
assert [center["dc"] for center in report["data_centers"]] == [1, 2, 3, 4, 5]
PY
python3 - 30443 <<'PY'
import socket
import sys

with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2):
    pass
PY
snapshot=$(env R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/root/config" \
    R2O_MANAGER="$TEMP/manager" R2O_TG_TEST_BINARY="$TEMP/root/releases/test/builds/r2o-telegram-linux-test" \
    "$TEMP/manager" exec --component r2o-telegram -- --stats \
        --stats-socket-path "$TEMP/root/state/telegram.stats.sock")
printf '%s\n' "$snapshot" | grep -q '"listener_ready":true'
printf '%s\n' "$snapshot" | grep -q '"cf_domain_pool":{"domains":\["' || \
    fail "S99r2o не включил встроенный пул доменов Cloudflare для WSS fallback"
grep -q '^start$' "$TEMP/firewall-calls"
grep -q '^sync-dc-map$' "$TEMP/firewall-calls" || fail "служба не синхронизировала карту DC после запуска firewall"
grep -qF "$TEMP/tg-firewall|$TEMP/root/state/telegram-dc-endpoints.tsv" "$TEMP/tg-env-capture" || fail "служба не передала прокси путь адаптера и манифеста"

old_pid=$(cat "$TEMP/root/run/r2o-telegram.pid")
kill -KILL "$old_pid"
attempt=0
recovered=
while [ "$attempt" -lt 300 ]; do
    new_pid=$(cat "$TEMP/root/run/r2o-telegram.pid" 2>/dev/null || true)
    if [ -n "$new_pid" ] && [ "$new_pid" != "$old_pid" ] && kill -0 "$new_pid" 2>/dev/null; then
        snapshot=$(env R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/root/config" \
            R2O_MANAGER="$TEMP/manager" R2O_TG_TEST_BINARY="$TEMP/root/releases/test/builds/r2o-telegram-linux-test" \
            "$TEMP/manager" exec --component r2o-telegram -- --stats \
                --stats-socket-path "$TEMP/root/state/telegram.stats.sock" 2>/dev/null || true)
        case "$snapshot" in *'"listener_ready":true'*) recovered=yes; break ;; esac
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
if [ "$recovered" != yes ]; then
    watchdog_pid=$(cat "$TEMP/root/run/r2o-telegram-watchdog.pid" 2>/dev/null || true)
    telegram_pid=$(cat "$TEMP/root/run/r2o-telegram.pid" 2>/dev/null || true)
    echo "сторож: pid=$watchdog_pid cmdline=$(tr '\000' ' ' < "/proc/$watchdog_pid/cmdline" 2>/dev/null || true)" >&2
    echo "listener: pid=$telegram_pid exe=$(readlink "/proc/$telegram_pid/exe" 2>/dev/null || true)" >&2
    for state in telegram-health.failures telegram-health.restarts telegram-health.restart-limited; do
        if [ -e "$TEMP/root/state/$state" ]; then
            echo "$state: $(cat "$TEMP/root/state/$state" 2>/dev/null || true)" >&2
        else
            echo "$state: отсутствует" >&2
        fi
    done
fi
[ "$recovered" = yes ] || fail "сторож не восстановил завершившийся Rust Telegram listener"

: > "$TEMP/manager-fail"
attempt=0
while [ ! -e "$TEMP/root/state/telegram-health.restart-limited" ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 200 ] || fail "сторож не применил ограничение частоты перезапусков"
    sleep 0.1
done
[ "$(wc -l < "$TEMP/root/state/telegram-health.restarts")" -eq 2 ] || \
    fail "сторож превысил лимит двух перезапусков в окне"
sleep 2
[ "$(wc -l < "$TEMP/root/state/telegram-health.restarts")" -eq 2 ] || \
    fail "сторож продолжал перезапуски после достижения лимита"

touch "$TEMP/firewall-fail"
run_service telegram-disable
grep -q '^TG_ENABLED=0$' "$TEMP/root/config" || fail "ошибка firewall изменила сохранённое состояние отключения"
[ ! -e "$TEMP/root/run/r2o-telegram.pid" ] || fail "ошибка firewall оставила Telegram listener запущенным"
[ ! -e "$TEMP/root/run/r2o-telegram-watchdog.pid" ] || fail "ошибка firewall оставила сторож Telegram запущенным"
grep -q '^stopped$' "$TEMP/root/state/telegram.status" || fail "ошибка firewall не завершила остановку Telegram"
rm -f "$TEMP/firewall-fail"
run_service telegram-disable
grep -q '^TG_ENABLED=0$' "$TEMP/root/config"
grep -q '^stopped$' "$TEMP/root/state/telegram.status"
[ ! -e "$TEMP/root/run/r2o-telegram.pid" ]
[ ! -e "$TEMP/root/run/r2o-telegram-watchdog.pid" ]
[ ! -e "$TEMP/root/state/telegram.stats.sock" ]
grep -q '^stop$' "$TEMP/firewall-calls"

echo "Проверка запуска и готовности службы Telegram прошла"
