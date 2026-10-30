#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
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

D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
D2O_UPDATE=$D2O_ROOT/files/d2k-update.sh
[ -f "$D2O_UPDATE" ] || { echo "не найден D2O updater $D2O_UPDATE" >&2; exit 2; }
tr -d '\r' < "$D2O_UPDATE" | sed -n '/^install_release() {/,$p' | sed '/^run() {/,$d' > "$TEMP/d2o-install.sh"
grep -q '^install_release() {' "$TEMP/d2o-install.sh" || { echo "не удалось извлечь D2O update policy" >&2; exit 2; }
(
    WORK=$TEMP/d2o-work
    DOWNLOAD=https://example.test/download
    mkdir -p "$WORK"
    EVENTS=$TEMP/d2o-events
    : > "$EVENTS"
    now() { printf '1\n'; }
    check() { check_error=; return 0; }
    latest_id() { printf 'r2o-bad\n'; }
    arch() { printf 'mipsel\n'; }
    current_id() { printf 'r2o-good\n'; }
    field() { [ "${1:-}" != bad_release ] || printf 'r2o-bad\n'; }
    latest_sum() { printf '%064d\n' 0; }
    fetch() { printf 'download\n' >> "$EVENTS"; return 1; }
    finish() { printf 'finish:%s:%s\n' "$1" "$2" >> "$EVENTS"; }
    . "$TEMP/d2o-install.sh"
    if install_release auto; then
        echo "D2O unexpectedly retried a release that previously failed runtime health" >&2
        exit 1
    fi
    ! grep -q '^download$' "$EVENTS" || { echo "D2O downloaded a known-bad nightly release" >&2; exit 1; }
    if install_release manual; then
        echo "D2O download-failure fixture unexpectedly succeeded" >&2
        exit 1
    fi
    grep -q '^download$' "$EVENTS" || { echo "D2O manual mode did not bypass bad_release" >&2; exit 1; }
)

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
        printf '{"checked":true,"update_available":%s,"auto_retry_blocked":%s}\n' \
            "${R2O_TEST_AVAILABLE:-true}" "${R2O_TEST_BLOCKED:-false}"
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
        R2O_TEST_BLOCKED="${4:-false}" \
        sh "$SCHEDULER" tick
}

mkdir -p "$TEMP/install/root/state"
printf 'AUTOUPDATE=1\n' > "$TEMP/install/root/config"
run_tick "$TEMP/install" 03 true
run_tick "$TEMP/install" 03 true
[ "$(grep -c '^check$' "$TEMP/install/events")" -eq 1 ]
grep -q '^launch:update-install-auto$' "$TEMP/install/events"
grep -q '^init:update-install-auto$' "$TEMP/install/events"

mkdir -p "$TEMP/blocked/root/state"
printf 'AUTOUPDATE=1\n' > "$TEMP/blocked/root/config"
run_tick "$TEMP/blocked" 03 true true
grep -q '^check$' "$TEMP/blocked/events"
if grep -q '^launch:' "$TEMP/blocked/events"; then
    echo "ночной планировщик повторно запустил релиз с прежним отказом health-check" >&2
    exit 1
fi

mkdir -p "$TEMP/manual/root/state"
printf 'AUTOUPDATE=0\n' > "$TEMP/manual/root/config"
run_tick "$TEMP/manual" 04 true
grep -q '^check$' "$TEMP/manual/events"
if grep -q '^launch:' "$TEMP/manual/events"; then
    echo "запуск установки обновления при выключенной настройке недопустим" >&2
    exit 1
fi

mkdir -p "$TEMP/outside/root/state"
printf 'AUTOUPDATE=1\n' > "$TEMP/outside/root/config"
run_tick "$TEMP/outside" 02 true
[ ! -f "$TEMP/outside/events" ]

echo "Планировщик проверяет обновления раз в сутки и устанавливает их только при включённой настройке"
