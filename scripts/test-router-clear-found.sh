#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
R2OC_BIN=${R2OC_TEST_BINARY:-$ROOT/target/release/r2o-controller}
[ -x "$R2OC_BIN" ] || { echo "нужен исполняемый файл r2o-controller из выпуска: $R2OC_BIN" >&2; exit 2; }
TEMP=$(mktemp -d)
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ "$result" -ne 0 ] && [ -f "$TEMP/events" ]; then cat "$TEMP/events" >&2; fi
    if [ -d "$TEMP/root/run" ]; then
        for pidfile in "$TEMP/root/run"/*.pid; do
            [ -f "$pidfile" ] || continue
            pid=$(cat "$pidfile" 2>/dev/null) || continue
            case "$pid" in ''|*[!0-9]*) continue ;; esac
            kill "$pid" 2>/dev/null || true
        done
    fi
    if [ -n "${initial_pid:-}" ]; then kill "$initial_pid" 2>/dev/null || true; fi
    if [ "${KEEP_TEST_WORK:-0}" = 1 ]; then
        echo "сохранены файлы проверки: $TEMP" >&2
    else
        rm -rf "$TEMP"
    fi
    exit "$result"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$TEMP/root/state" "$TEMP/root/run" "$TEMP/root/releases/test/builds" \
    "$TEMP/proc/net/netfilter" "$TEMP/runtime"
cp /bin/sleep "$TEMP/root/releases/test/builds/r2o-datapath-linux-test"
cp /bin/sleep "$TEMP/root/releases/test/builds/r2o-controller-linux-test"
chmod 0755 "$TEMP/root/releases/test/builds/r2o-datapath-linux-test" "$TEMP/root/releases/test/builds/r2o-controller-linux-test"
printf 'MODE=observe\nSTATE_DIR=%s\nFW_BACKEND=nft\n' "$TEMP/root/state" > "$TEMP/root/config"
printf '{"schema":1,"boxes":[{"id":"found"}]}\n' > "$TEMP/root/state/catalog.json"
printf '2000 1 128\n2001 1 128\n' > "$TEMP/proc/net/netfilter/nfnetlink_queue"
"$TEMP/root/releases/test/builds/r2o-datapath-linux-test" 30 &
initial_pid=$!
printf '%s\n' "$initial_pid" > "$TEMP/root/run/r2o-datapath4.pid"

cat > "$TEMP/manager" <<'EOF'
#!/bin/sh
printf 'manager:%s\n' "$*" >> "$EVENTS"
printf 'manager-fw:%s\n' "${R2O_FW:-unset}" >> "$EVENTS"
[ "${1:-}" = exec ] || exit 2
shift
component=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --component) component=$2; shift 2 ;;
        --) shift; break ;;
        *) shift ;;
    esac
done
case "$component" in r2o-datapath|r2o-controller) ;; *) exit 2 ;; esac
case "${1:-}" in
    --clear-catalog) exec "$R2OC_TEST_BINARY" "$@" ;;
esac
exec "$R2O_DIR/releases/test/builds/$component-linux-test" 30
EOF
cat > "$TEMP/firewall" <<'EOF'
#!/bin/sh
if [ "${1:-}" = ipv6-enabled ]; then printf '1\n'; exit 0; fi
printf 'firewall:%s\n' "$1" >> "$EVENTS"
EOF
chmod 0755 "$TEMP/manager" "$TEMP/firewall"

env EVENTS="$TEMP/events" R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/root/config" \
    R2O_MANAGER="$TEMP/manager" R2O_R2OC_TEST_BINARY="$R2OC_BIN" \
    R2O_FIREWALL="$TEMP/firewall" R2O_PROC=/proc \
    R2O_NFQUEUE_STATUS="$TEMP/proc/net/netfilter/nfnetlink_queue" \
    R2O_RUNTIME_DIR="$TEMP/runtime" \
    R2OC_TEST_BINARY="$R2OC_BIN" sh "$ROOT/router/S99r2o" clear-found

catalog_state=$("$R2OC_BIN" --check-catalog "$TEMP/root/state/catalog.json")
printf '%s\n' "$catalog_state" | grep -q '0 коробок'
grep -q '^firewall:down$' "$TEMP/events"
grep -q -- '--clear-catalog ' "$TEMP/events"
grep -q '^firewall:up$' "$TEMP/events"
grep -q '^manager-fw:nft$' "$TEMP/events"
[ -s "$TEMP/root/run/r2o-datapath4.pid" ] && [ -s "$TEMP/root/run/r2o-controller4.pid" ]
down_line=$(grep -n '^firewall:down$' "$TEMP/events" | head -n 1 | cut -d: -f1)
clear_line=$(grep -n -- '--clear-catalog ' "$TEMP/events" | head -n 1 | cut -d: -f1)
up_line=$(grep -n '^firewall:up$' "$TEMP/events" | head -n 1 | cut -d: -f1)
[ "$down_line" -lt "$clear_line" ] && [ "$clear_line" -lt "$up_line" ]
echo "Адаптер остановил runtime и атомарно очистил каталог"
