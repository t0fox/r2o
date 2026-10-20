#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/root/state" "$TEMP/runtime"
printf 'MODE=off\nAUTOUPDATE=1\n' > "$TEMP/root/config"
cat > "$TEMP/manager" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$EVENTS"
EOF
chmod 0755 "$TEMP/manager"

run_action() {
    env EVENTS="$TEMP/events" R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/root/config" \
        R2O_MANAGER="$TEMP/manager" R2O_PROC=/proc R2O_RUNTIME_DIR="$TEMP/runtime" \
        sh "$ROOT/router/S99r2o" "$1"
}

run_action update-auto-off
grep -q '^AUTOUPDATE=0$' "$TEMP/root/config"
grep -q -- 'update-auto --root ' "$TEMP/events"
grep -q -- '--enabled 0$' "$TEMP/events"
run_action update-auto-on
grep -q '^AUTOUPDATE=1$' "$TEMP/root/config"
grep -q -- '--enabled 1$' "$TEMP/events"

echo "Проверено сохранение настройки автообновления роутера и состояния менеджера"
