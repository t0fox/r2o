#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
# Два слота и подменяемые службы проверяются через настоящий Rust CLI.
cargo test --locked -p r2o-manager --test cli router_update_recovers_after_kill_and_preserves_operator_data

TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
printf 'MODE=off\nTG_ENABLED=0\n' > "$TEMP/config"
# Панель может запустить адаптер с путями от выпуска, удалённого после активации.
slot_root=$TEMP/root/releases
pruned=$slot_root/r2o-pruned/router
active=$slot_root/r2o-active/router
mkdir -p "$active"
cp "$ROOT/router/S99r2o" "$active/"
cat > "$active/r2o-firewall.sh" <<'EOF'
#!/bin/sh
case "$1" in
    backend) echo nft ;;
    ipv6-enabled)
        printf '%s %s\n' "$R2O_FIREWALL" "$R2O_PPE_ADAPTER" >> "$EVENTS"
        echo 0
        ;;
esac
EOF
chmod 0755 "$active/r2o-firewall.sh"
env EVENTS="$TEMP/slot-events" R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/config" \
    R2O_RUNTIME_DIR="$TEMP/runtime" R2O_FIREWALL="$pruned/r2o-firewall.sh" \
    R2O_PPE_ADAPTER="$pruned/r2o-ppe-deoffload.sh" \
    sh "$active/S99r2o" status >/dev/null
grep -Fxq "$active/r2o-firewall.sh $active/r2o-ppe-deoffload.sh" "$TEMP/slot-events"

sed -n '/^service_pid_alive() {/,/^}/p' "$ROOT/router/S99r2o" > "$TEMP/service-pid.sh"
# Даже успешный kill -0 не означает, что процесс держит ресурсы.
PROC=$TEMP/proc
mkdir -p "$PROC/$$"
# shellcheck disable=SC1091
. "$TEMP/service-pid.sh"
printf '%s (тест) S 1\n' "$$" > "$PROC/$$/stat"
service_pid_alive "$$"
printf '%s (тест с ) в имени) Z 1\n' "$$" > "$PROC/$$/stat"
if service_pid_alive "$$"; then
    echo 'завершённый процесс ошибочно считается живым' >&2
    exit 1
fi

echo "Проверены активация, откат и запуск с путями удалённого выпуска"
