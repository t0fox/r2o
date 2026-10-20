#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TG_BIN=${R2O_TG_TEST_BINARY:-$ROOT/target/release/r2o-telegram}
[ -x "$TG_BIN" ] || { echo "требуется release-бинарный файл r2o-telegram: $TG_BIN" >&2; exit 2; }
TEMP=$(mktemp -d)
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    env R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/root/config" \
        R2O_MANAGER="$TEMP/manager" R2O_TG_TEST_BINARY="$TEMP/root/releases/test/builds/r2o-telegram-linux-test" \
        R2O_TG_FIREWALL="$TEMP/tg-firewall" R2O_PROC=/proc R2O_RUNTIME_DIR="$TEMP/runtime" \
        sh "$ROOT/router/S99r2o" telegram-disable >/dev/null 2>&1 || true
    if [ "$result" -ne 0 ] && [ -f "$TEMP/root/log/telegram.log" ]; then
        cat "$TEMP/root/log/telegram.log" >&2
    fi
    rm -rf "$TEMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM
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
exit 0
EOF
chmod 0755 "$TEMP/manager" "$TEMP/tg-firewall"

run_service() {
    env R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/root/config" \
        R2O_MANAGER="$TEMP/manager" R2O_TG_TEST_BINARY="$TEMP/root/releases/test/builds/r2o-telegram-linux-test" \
        R2O_TG_FIREWALL="$TEMP/tg-firewall" R2O_PROC=/proc \
        R2O_RUNTIME_DIR="$TEMP/runtime" R2O_TG_ENV_CAPTURE="$TEMP/tg-env-capture" \
        R2O_NFQUEUE_STATUS=/dev/null TG_FW_CALLS="$TEMP/firewall-calls" \
        sh "$ROOT/router/S99r2o" "$1"
}

run_service telegram-enable
grep -q '^TG_ENABLED=1$' "$TEMP/root/config"
grep -q '^local$' "$TEMP/root/state/telegram.status"
[ -s "$TEMP/root/run/r2o-telegram.pid" ]
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
grep -q '^start$' "$TEMP/firewall-calls"
grep -q '^sync-dc-map$' "$TEMP/firewall-calls" || fail "служба не синхронизировала карту DC после запуска firewall"
grep -qF "$TEMP/tg-firewall|$TEMP/root/state/telegram-dc-endpoints.tsv" "$TEMP/tg-env-capture" || fail "служба не передала прокси путь адаптера и манифеста"

run_service telegram-disable
grep -q '^TG_ENABLED=0$' "$TEMP/root/config"
grep -q '^stopped$' "$TEMP/root/state/telegram.status"
[ ! -e "$TEMP/root/run/r2o-telegram.pid" ]
[ ! -e "$TEMP/root/state/telegram.stats.sock" ]
grep -q '^stop$' "$TEMP/firewall-calls"

echo "Проверка запуска и готовности службы Telegram прошла"
