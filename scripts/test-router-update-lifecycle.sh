#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
fail() { echo "ОШИБКА: $*" >&2; exit 1; }
mkdir -p "$TEMP/bin" "$TEMP/root" "$TEMP/proc/net/netfilter" "$TEMP/runtime"
printf 'MODE=off\nTG_ENABLED=0\n' > "$TEMP/config"

cat > "$TEMP/manager" <<'EOF'
#!/bin/sh
printf 'manager:%s\n' "$1" >> "$EVENTS"
exit 0
EOF
cat > "$TEMP/init" <<'EOF'
#!/bin/sh
printf 'init:%s\n' "$1" >> "$EVENTS"
[ "$1" != start ] || exit 1
exit 0
EOF
cat > "$TEMP/firewall" <<'EOF'
#!/bin/sh
if [ "${1:-}" = ipv6-enabled ]; then printf '1\n'; exit 0; fi
printf 'firewall:%s\n' "$1" >> "$EVENTS"
exit 0
EOF
cat > "$TEMP/tg-firewall" <<'EOF'
#!/bin/sh
printf 'telegram-firewall:%s\n' "$1" >> "$EVENTS"
exit 0
EOF
printf '#!/bin/sh\nexit 0\n' > "$TEMP/bin/sleep"
chmod 0755 "$TEMP/manager" "$TEMP/init" "$TEMP/firewall" "$TEMP/tg-firewall" "$TEMP/bin/sleep"

if env PATH="$TEMP/bin:/usr/bin:/bin" EVENTS="$TEMP/events" \
    R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/config" \
    R2O_MANAGER="$TEMP/manager" R2O_INIT="$TEMP/init" \
    R2O_FIREWALL="$TEMP/firewall" R2O_TG_FIREWALL="$TEMP/tg-firewall" \
    R2O_PROC="$TEMP/proc" R2O_NFQUEUE_STATUS="$TEMP/proc/net/netfilter/nfnetlink_queue" \
    R2O_RUNTIME_DIR="$TEMP/runtime" sh "$ROOT/router/S99r2o" update-install; then
    fail "an unhealthy test release unexpectedly passed runtime health"
fi

count() { grep -c "^$1$" "$TEMP/events" || true; }
[ "$(count 'init:start')" -eq 2 ] || fail "new and rolled-back adapters were not both started"
[ "$(count 'init:stop')" -eq 1 ] || fail "the failed release adapter was not stopped"

line() { grep -nF "$1" "$TEMP/events" | head -n 1 | cut -d: -f1; }
install_line=$(line manager:update-install)
stop_line=$(line firewall:down)
tg_stop_line=$(line telegram-firewall:stop)
first_start_line=$(line init:start)
stop_failed_line=$(line init:stop)
rollback_line=$(line manager:rollback)
[ "$tg_stop_line" -lt "$install_line" ] || fail "Telegram rules were stopped after activation"
[ "$stop_line" -lt "$install_line" ] || fail "datapath was stopped after activation"
[ "$install_line" -lt "$first_start_line" ] || fail "the new adapter was not started after activation"
[ "$first_start_line" -lt "$stop_failed_line" ] || fail "the unhealthy adapter was not checked before stop"
[ "$stop_failed_line" -lt "$rollback_line" ] || fail "rollback happened before the unhealthy adapter stopped"

echo "Проверены активация обновления роутера, перезапуск и порядок отката"
