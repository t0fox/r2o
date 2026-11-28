#!/bin/sh
# Проверяет сохранение переключателя и то, что команды касаются только Meta.
set -eu

REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

ROOT=$TEMP/router
STATE=$ROOT/state
META_ENABLED=$STATE/meta-protection.enabled
META_DISABLED=$STATE/meta-protection.disabled
MANAGER=$TEMP/manager
TRACE=$TEMP/trace
export TRACE
mkdir -p "$STATE"
cat > "$MANAGER" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$TRACE"
case " $* " in
    *" --remove-meta-dns "*|*" --meta-protection-product instagram off "*) exit 0 ;;
    *) exit 2 ;;
esac
EOF
chmod 0755 "$MANAGER"

prepare_dirs() { mkdir -p "$STATE"; }
meta_dns_scheduler_start() { printf 'meta start\n' >> "$TRACE"; }
meta_dns_scheduler_stop() { printf 'meta stop\n' >> "$TRACE"; }

# Вызываем штатные обработчики команд, используя имитации запуска и backend.
eval "$(awk '/^meta_protection_(enabled|enable|disable|product)\(\) \{/ { print_block=1 }
    print_block { print }
    /^\}/ { print_block=0 }' "$REPO/router/S99r2o")"

if meta_protection_enabled; then exit 1; fi
meta_protection_disable
test "$(cat "$META_DISABLED")" = 0
test "$(sh -c 'cat "$1/meta-protection.disabled"' sh "$STATE")" = 0
test "$(awk 'NR == 1' "$TRACE")" = 'meta stop'
test "$(awk 'NR == 2' "$TRACE")" = "exec --root $ROOT --component r2o-telegram -- --remove-meta-dns"

printf '2026-11-28\n' > "$STATE/instagram-dns-last-success"
meta_protection_enable
meta_protection_enabled
test "$(cat "$META_ENABLED")" = 1
test ! -e "$META_DISABLED"
test ! -e "$STATE/instagram-dns-last-success"
test "$(tail -n 1 "$TRACE")" = 'meta start'
test "$(wc -l < "$TRACE")" -eq 3
if meta_protection_product malformed off; then exit 1; fi
meta_protection_product instagram off
test "$(awk 'NR == 4' "$TRACE")" = 'meta stop'
test "$(awk 'NR == 5' "$TRACE")" = "exec --root $ROOT --component r2o-telegram -- --meta-protection-product instagram off"
test "$(awk 'NR == 6' "$TRACE")" = 'meta start'
meta_protection_disable
if meta_protection_enabled; then exit 1; fi
test ! -e "$META_ENABLED"
test -f "$META_DISABLED"

# Новое включение запускает начальную проверку, повторная команда on сохраняет
# суточный ограничитель. Переопределённый путь совпадает с путём Rust scheduler.
R2O_INSTAGRAM_SCHED_STATE=$STATE/custom-meta-success
printf '2026-11-28\n' > "$R2O_INSTAGRAM_SCHED_STATE"
meta_protection_enable
test ! -e "$R2O_INSTAGRAM_SCHED_STATE"
printf '2026-11-28\n' > "$R2O_INSTAGRAM_SCHED_STATE"
meta_protection_enable
test "$(cat "$R2O_INSTAGRAM_SCHED_STATE")" = '2026-11-28'
printf '%s\n' 'Meta Protection ON/OFF, сохранение состояния и суточного расписания: OK'
