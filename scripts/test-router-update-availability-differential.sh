#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
fail() { echo "ОШИБКА: $*" >&2; exit 1; }

D2O_UPDATE=$D2O_ROOT/files/d2k-update.sh
R2O_INIT=$ROOT/router/S99r2o
[ -f "$D2O_UPDATE" ] || fail "не найден D2O updater $D2O_UPDATE"
tr -d '\r' < "$D2O_UPDATE" | sed -n '/^install_release() {/,$p' | sed '/^run() {/,$d' > "$TEMP/d2o-install.sh"
tr -d '\r' < "$R2O_INIT" | sed -n '/^update_rollback() {/,$p' | sed '/^status() {/,$d' > "$TEMP/r2o-install.sh"
. "$TEMP/d2o-install.sh"
. "$TEMP/r2o-install.sh"

EVENTS=$TEMP/d2o-events
export EVENTS
D2O_SUM=$(printf '%064d' 0)
D2O_FAIL_DOWNLOAD=0
D2O_RELEASE=new
WORK=$TEMP/d2o-work
ROOT_D2O=$TEMP/d2o-root
ROOT=$ROOT_D2O
DOWNLOAD=https://example.test/download
LOG=$TEMP/d2o.log
mkdir -p "$WORK" "$ROOT_D2O/bin"
printf 'old release\n' > "$ROOT_D2O/bin/current"
now() { printf '1\n'; }
check() { check_error=; return 0; }
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

EVENTS=$TEMP/r2o-events
export EVENTS
ROOT=$TEMP/r2o
MANAGER=$TEMP/manager
INIT=$TEMP/init
R2O_SCENARIO=success
export R2O_SCENARIO
cat > "$MANAGER" <<'EOF'
#!/bin/sh
case "$1" in
    update-install*)
        printf 'download\n' >> "$EVENTS"
        case "$R2O_SCENARIO" in
            current) printf '{"activated":false,"already_current":true}\n' ;;
            failed) exit 1 ;;
            success)
                printf 'activate\n' >> "$EVENTS"
                printf '{"activated":true,"already_current":false}\n'
                ;;
            unknown) printf '{"ok":true}\n' ;;
            stop-failure)
                printf 'activate\n' >> "$EVENTS"
                printf '{"activated":true,"already_current":false}\n'
                ;;
            *) exit 2 ;;
        esac
        ;;
    rollback|update-mark-bad-previous) printf '%s\n' "$1" >> "$EVENTS" ;;
    *) exit 2 ;;
esac
EOF
cat > "$INIT" <<'EOF'
#!/bin/sh
printf 'init:%s\n' "$1" >> "$EVENTS"
EOF
chmod 700 "$MANAGER" "$INIT"
R2O_STOP_FAIL=0
stop() {
    printf 'stop\n' >> "$EVENTS"
    [ "$R2O_STOP_FAIL" = 0 ]
}
wait_health() { return 0; }
say() { :; }
die() { fail "unexpected fatal router action: $*"; }

: > "$EVENTS"
update_install manual >/dev/null
[ "$(cat "$EVENTS")" = "$(printf 'download\nactivate\nstop\ninit:start')" ] || \
    fail "R2O stopped its service before verified release activation"

: > "$EVENTS"
R2O_SCENARIO=current
update_install manual >/dev/null
[ "$(cat "$EVENTS")" = download ] || \
    fail "R2O restarted services even though the release was already current"

: > "$EVENTS"
R2O_SCENARIO=failed
if update_install manual >/dev/null 2>&1; then fail "R2O download-failure fixture unexpectedly succeeded"; fi
[ "$(cat "$EVENTS")" = download ] || \
    fail "R2O stopped or restarted services after a failed download"

: > "$EVENTS"
R2O_SCENARIO=unknown
if update_install manual >/dev/null 2>&1; then fail "R2O accepted an unrecognized manager result"; fi
[ "$(cat "$EVENTS")" = download ] || \
    fail "R2O stopped or restarted services without confirmed activation"

: > "$EVENTS"
R2O_SCENARIO=stop-failure
R2O_STOP_FAIL=1
if update_install manual >/dev/null; then fail "R2O stop-failure fixture unexpectedly succeeded"; fi
[ "$(cat "$EVENTS")" = "$(printf 'download\nactivate\nstop\ninit:stop\nrollback\nupdate-mark-bad-previous\ninit:start')" ] || \
    fail "R2O did not roll back an activated release when shutdown failed"

echo "D2O/R2O download failures and no-op updates preserve the running datapath; stop follows activation"
