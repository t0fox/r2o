#!/bin/sh
# B42: telegram-reapply не запускает остановленный Telegram (как D2O).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ "$result" -ne 0 ] && [ -f "$TEMP/events" ]; then cat "$TEMP/events" >&2; fi
    rm -rf "$TEMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$TEMP/root/state" "$TEMP/root/run" "$TEMP/runtime"
printf 'TG_ENABLED=1\nTG_MODE=local\nIPV6_ENABLED=0\nSTATE_DIR=%s\n' "$TEMP/root/state" > "$TEMP/root/config"
cat > "$TEMP/manager" <<'EOF'
#!/bin/sh
printf 'manager:%s\n' "$*" >> "$EVENTS"
exit 3
EOF
cat > "$TEMP/firewall" <<'EOF'
#!/bin/sh
if [ "${1:-}" = ipv6-enabled ]; then printf '0\n'; exit 0; fi
printf 'firewall:%s\n' "$*" >> "$EVENTS"
exit 4
EOF
chmod 0755 "$TEMP/manager" "$TEMP/firewall"

env EVENTS="$TEMP/events" R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/root/config" \
    R2O_MANAGER="$TEMP/manager" R2O_FIREWALL="$TEMP/firewall" \
    R2O_TG_FIREWALL="$TEMP/firewall" R2O_PROC=/proc \
    R2O_RUNTIME_DIR="$TEMP/runtime" \
    sh "$ROOT/router/S99r2o" telegram-reapply

[ -f "$TEMP/events" ] && { echo "telegram-reapply запустил остановленный Telegram" >&2; cat "$TEMP/events" >&2; exit 1; }
echo "telegram-reapply не запускает остановленный процесс"
