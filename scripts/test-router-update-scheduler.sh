#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SCHEDULER=$ROOT/router/r2o-update-scheduler.sh
[ -x "$SCHEDULER" ] || { echo "планировщик обновлений отсутствует или не исполняемый" >&2; exit 2; }
TEMP=$(mktemp -d)
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    rm -rf "$TEMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

cat > "$TEMP/date" <<'EOF'
#!/bin/sh
case "${1:-}" in
    +%H) printf '%s\n' "${R2O_TEST_HOUR:-03}" ;;
    +%Y%m%d) printf '%s\n' "${R2O_TEST_DAY:-20261018}" ;;
    *) exit 2 ;;
esac
EOF
cat > "$TEMP/manager" <<'EOF'
#!/bin/sh
case "${1:-}" in
    update-check)
        printf 'check\n' >> "$EVENTS"
        printf '{"checked":true,"update_available":%s}\n' "${R2O_TEST_AVAILABLE:-true}"
        ;;
    *) exit 2 ;;
esac
EOF
cat > "$TEMP/init" <<'EOF'
#!/bin/sh
printf 'init:%s\n' "$1" >> "$EVENTS"
EOF
cat > "$TEMP/start-stop" <<'EOF'
#!/bin/sh
init=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -x) init=$2; shift 2 ;;
        --) shift; break ;;
        *) shift ;;
    esac
done
printf 'launch:%s\n' "$*" >> "$EVENTS"
[ -n "$init" ] || exit 2
"$init" "$@"
EOF
chmod 0755 "$TEMP/date" "$TEMP/manager" "$TEMP/init" "$TEMP/start-stop"

run_tick() {
    env EVENTS="$1/events" R2O_DIR="$1/root" R2O_CONFIG="$1/root/config" \
        R2O_MANAGER="$TEMP/manager" R2O_INIT="$TEMP/init" \
        R2O_UPDATE_DATE="$TEMP/date" R2O_START_STOP_DAEMON="$TEMP/start-stop" \
        R2O_TEST_HOUR="${2:-03}" R2O_TEST_DAY=20261018 R2O_TEST_AVAILABLE="${3:-true}" \
        sh "$SCHEDULER" tick
}

mkdir -p "$TEMP/install/root/state"
printf 'AUTOUPDATE=1\n' > "$TEMP/install/root/config"
run_tick "$TEMP/install" 03 true
run_tick "$TEMP/install" 03 true
[ "$(grep -c '^check$' "$TEMP/install/events")" -eq 1 ]
grep -q '^launch:update-install$' "$TEMP/install/events"
grep -q '^init:update-install$' "$TEMP/install/events"

mkdir -p "$TEMP/manual/root/state"
printf 'AUTOUPDATE=0\n' > "$TEMP/manual/root/config"
run_tick "$TEMP/manual" 04 true
grep -q '^check$' "$TEMP/manual/events"
! grep -q '^launch:' "$TEMP/manual/events"

mkdir -p "$TEMP/outside/root/state"
printf 'AUTOUPDATE=1\n' > "$TEMP/outside/root/config"
run_tick "$TEMP/outside" 02 true
[ ! -f "$TEMP/outside/events" ]

echo "Планировщик проверяет обновления раз в сутки и устанавливает их только при включённой настройке"
