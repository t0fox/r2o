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
    # shellcheck disable=SC2034 # sourced updater functions consume this fixture variable
    DOWNLOAD=https://example.test/download
    mkdir -p "$WORK"
    EVENTS=$TEMP/d2o-events
    : > "$EVENTS"
    now() { printf '1\n'; }
    check() {
        # shellcheck disable=SC2034 # sourced updater functions consume this fixture variable
        check_error=
        return 0
    }
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

cat > "$TEMP/manager" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$EVENTS"
EOF
chmod 0755 "$TEMP/manager"
EVENTS="$TEMP/events" R2O_DIR="$TEMP/root" R2O_MANAGER="$TEMP/manager" R2O_INIT="$TEMP/init" \
    sh "$SCHEDULER" 0
printf '%s\n' exec --root "$TEMP/root" --component r2o-manager -- \
    update-schedule --root "$TEMP/root" --service "$TEMP/init" --enabled 0 > "$TEMP/expected"
cmp "$TEMP/events" "$TEMP/expected"

cd "$ROOT"
cargo test --locked -p r2o-manager scheduler --lib
cargo test --locked -p r2o-manager automatic_retry_is_blocked_only_for_the_recorded_bad_release --lib
