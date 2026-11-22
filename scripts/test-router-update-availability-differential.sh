#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
fail() { echo "ОШИБКА: $*" >&2; exit 1; }

D2O_UPDATE=$D2O_ROOT/files/d2k-update.sh
R2O_DIR_FOR_TEST=$ROOT
[ -f "$D2O_UPDATE" ] || fail "не найден D2O updater $D2O_UPDATE"
tr -d '\r' < "$D2O_UPDATE" | sed -n '/^install_release() {/,$p' | sed '/^run() {/,$d' > "$TEMP/d2o-install.sh"
. "$TEMP/d2o-install.sh"

EVENTS=$TEMP/d2o-events
export EVENTS
D2O_SUM=$(printf '%064d' 0)
D2O_FAIL_DOWNLOAD=0
D2O_RELEASE=new
WORK=$TEMP/d2o-work
ROOT_D2O=$TEMP/d2o-root
ROOT=$ROOT_D2O
# shellcheck disable=SC2034 # sourced updater functions consume this fixture variable
DOWNLOAD=https://example.test/download
# shellcheck disable=SC2034 # sourced updater functions consume this fixture variable
LOG=$TEMP/d2o.log
mkdir -p "$WORK" "$ROOT_D2O/bin"
printf 'old release\n' > "$ROOT_D2O/bin/current"
now() { printf '1\n'; }
check() {
    # shellcheck disable=SC2034 # sourced updater functions consume this fixture variable
    check_error=
    return 0
}
latest_id() { printf '%s\n' "$D2O_RELEASE"; }
arch() { printf 'testarch\n'; }
current_id() { printf 'old\n'; }
field() { [ "${1:-}" != bad_release ] || printf '\n'; }
latest_sum() { printf '%s\n' "$D2O_SUM"; }
fetch() {
    printf 'download\n' >> "$EVENTS"
    [ "$D2O_FAIL_DOWNLOAD" = 0 ] || return 1
    : > "$2"
}
openssl() { printf '%s  archive\n' "$D2O_SUM"; }
tar() {
    case "${1:-}" in
        -cf|-xf) return 0 ;;
        -xzf) mkdir -p "$4/scripts"; return 0 ;;
        *) return 2 ;;
    esac
}
installed_paths() { printf 'bin/current\n'; }
sh() { printf 'stop\n' >> "$EVENTS"; return 0; }
healthy() { return 0; }
finish() { :; }
write_state() { :; }
log() { :; }

: > "$EVENTS"
D2O_RELEASE=old
install_release manual || fail "D2O current-release check unexpectedly failed"
[ ! -s "$EVENTS" ] || fail "D2O restarted services when the latest release was already current"

D2O_RELEASE=new
D2O_FAIL_DOWNLOAD=1
if install_release manual; then fail "D2O download-failure fixture unexpectedly succeeded"; fi
[ "$(cat "$EVENTS")" = download ] || fail "D2O stopped service before a failed download"

: > "$EVENTS"
D2O_FAIL_DOWNLOAD=0
install_release manual || fail "D2O prepared-release fixture unexpectedly failed"
[ "$(cat "$EVENTS")" = "$(printf 'download\nstop')" ] || \
    fail "D2O did not download the release before entering the installer stop phase"

cd "$R2O_DIR_FOR_TEST"
cargo test --locked -p r2o-manager --test cli router_update_
