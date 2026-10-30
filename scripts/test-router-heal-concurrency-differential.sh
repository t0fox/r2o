#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
[ "$ACTUAL_D2O_SHA" = "$EXPECTED_D2O_SHA" ] || {
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-heal-concurrency.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
sed 's/\r$//' "$D2O_ROOT/files/d2k-fw-heal.sh" > "$TEMP/d2o-fw-heal.sh"
sed 's/\r$//' "$D2O_ROOT/files/001-d2k.sh" > "$TEMP/d2o-hook.sh"
sed -n '/^reapply() {/,/^}/p; /^heal_reapply() {/,/^}/p; /^firewall_heal() {/,/^}/p; /^heal() {/,/^}/p' "$ROOT/router/S99r2o" |
    sed 's/\r$//' > "$TEMP/r2o-functions.sh"

cat > "$TEMP/d2o-service" <<'SERVICE'
#!/bin/sh
case "$1" in
    status)
        printf 'status\n' >> "$TRACE"
        printf '\320\264\320\260\321\202\320\260\320\277\320\260\321\202: \321\200\320\260\320\261\320\276\321\202\320\260\320\265\321\202\n'
        if [ "${RULES_INSTALLED:-0}" = 1 ]; then
            printf '\320\277\321\200\320\260\320\262\320\270\320\273\320\260: \321\201\321\202\320\276\321\217\321\202\n'
        fi
        ;;
    ppe-ensure|dns-ensure) printf '%s\n' "$1" >> "$TRACE" ;;
    reapply)
        printf 'up\n' >> "$TRACE"
        sleep 1
        exit "${UP_RC:-0}"
        ;;
esac
SERVICE

cat > "$TEMP/d2o-run" <<'RUNNER'
#!/bin/sh
table=$1
export table TRACE
HEAL=$D2O_HEAL
INIT_SCRIPT=$D2O_INIT
HEAL_LOCK=$D2O_LOCK
HEAL_LAST=$D2O_LAST
MIN_INTERVAL=15
LOCK_STALE=60
export HEAL INIT_SCRIPT HEAL_LOCK HEAL_LAST MIN_INTERVAL LOCK_STALE
exec sh "$D2O_HOOK"
RUNNER

cat > "$TEMP/r2o-firewall" <<'FIREWALL'
#!/bin/sh
case "$1" in
    status)
        printf 'status\n' >> "$TRACE"
        [ "${RULES_INSTALLED:-0}" = 1 ]
        ;;
    dns-ensure) printf 'dns-ensure\n' >> "$TRACE" ;;
    flowoffload-ensure) printf 'flowoffload-ensure\n' >> "$TRACE" ;;
    up)
        printf 'up\n' >> "$TRACE"
        sleep 1
        exit "${UP_RC:-0}"
        ;;
esac
FIREWALL

cat > "$TEMP/r2o-init" <<'SERVICE'
#!/bin/sh
TRACE=$TRACE
FIREWALL=$R2O_FIREWALL
DP4_PID=running
RUNTIME=$R2O_RUNTIME
component_running() { [ "$1" = r2o-datapath ]; }
ppe_ensure() { printf 'ppe-ensure\n' >> "$TRACE"; }
telegram_reapply() { :; }
say() { :; }
die() { exit 1; }
export TRACE
. "$R2O_FUNCTIONS"
heal
SERVICE
chmod 0700 "$TEMP/d2o-fw-heal.sh" "$TEMP/d2o-hook.sh" \
    "$TEMP/d2o-service" "$TEMP/d2o-run" "$TEMP/r2o-firewall" "$TEMP/r2o-init"

TRACE=$TEMP/d2o.trace
D2O_HEAL=$TEMP/d2o-fw-heal.sh
D2O_HOOK=$TEMP/d2o-hook.sh
D2O_INIT=$TEMP/d2o-service
D2O_LOCK=$TEMP/d2o.lock
D2O_LAST=$TEMP/d2o.last
export TRACE D2O_HEAL D2O_HOOK D2O_INIT D2O_LOCK D2O_LAST
table=nat sh "$TEMP/d2o-run" nat &
d2o_nat=$!
table=mangle sh "$TEMP/d2o-run" mangle &
d2o_mangle=$!
wait "$d2o_nat"
wait "$d2o_mangle"

TRACE=$TEMP/r2o.trace
R2O_FIREWALL=$TEMP/r2o-firewall
R2O_RUNTIME=$TEMP/r2o-runtime
R2O_FUNCTIONS=$TEMP/r2o-functions.sh
R2O_INIT=$TEMP/r2o-init
export TRACE R2O_FIREWALL R2O_RUNTIME R2O_FUNCTIONS R2O_INIT
mkdir -p "$R2O_RUNTIME"
table=nat sh "$ROOT/router/001-r2o.sh" &
r2o_nat=$!
table=mangle sh "$ROOT/router/001-r2o.sh" &
r2o_mangle=$!
wait "$r2o_nat"
wait "$r2o_mangle"

d2o_up=$(grep -c '^up$' "$TEMP/d2o.trace" || true)
r2o_up=$(grep -c '^up$' "$TEMP/r2o.trace" || true)
[ "$d2o_up" = 1 ] && [ "$r2o_up" = "$d2o_up" ] || {
    printf 'concurrent NDM heal count differs: D2O=%s R2O=%s\n' "$d2o_up" "$r2o_up" >&2
    printf 'D2O trace:\n' >&2; cat "$TEMP/d2o.trace" >&2
    printf 'R2O trace:\n' >&2; cat "$TEMP/r2o.trace" >&2
    exit 1
}

# When the datapath and rules already exist, both watchdog paths should keep
# the firewall intact, ensure PPE, and refresh dynamic DNS exclusions.
TRACE=$TEMP/d2o-existing.trace
RULES_INSTALLED=1
INIT_SCRIPT=$D2O_INIT
export TRACE RULES_INSTALLED INIT_SCRIPT
if sh "$TEMP/d2o-fw-heal.sh"; then :; else
    echo 'D2O healthy-firewall heal failed' >&2
    exit 1
fi

TRACE=$TEMP/r2o-existing.trace
R2O_RUNTIME=$TEMP/r2o-existing-runtime
export TRACE R2O_RUNTIME
mkdir -p "$R2O_RUNTIME"
if sh "$TEMP/r2o-init"; then :; else
    echo 'R2O healthy-firewall heal failed' >&2
    exit 1
fi
printf '%s\n' status ppe-ensure dns-ensure > "$TEMP/d2o-existing.expected"
printf '%s\n' status dns-ensure flowoffload-ensure ppe-ensure > "$TEMP/r2o-existing.expected"
cmp "$TEMP/d2o-existing.expected" "$TEMP/d2o-existing.trace" && \
    cmp "$TEMP/r2o-existing.expected" "$TEMP/r2o-existing.trace" || {
    printf 'healthy firewall heal actions differ from their intended traces\nD2O:\n' >&2
    cat "$TEMP/d2o-existing.expected" "$TEMP/d2o-existing.trace" >&2
    printf 'R2O:\n' >&2
    cat "$TEMP/r2o-existing.expected" "$TEMP/r2o-existing.trace" >&2
    exit 1
}

TRACE=$TEMP/d2o-fail.trace
RULES_INSTALLED=0
D2O_LOCK=$TEMP/d2o-fail.lock
D2O_LAST=$TEMP/d2o-fail.last
UP_RC=1
INIT_SCRIPT=$D2O_INIT
HEAL_LOCK=$D2O_LOCK
HEAL_LAST=$D2O_LAST
MIN_INTERVAL=15
LOCK_STALE=60
export TRACE D2O_LOCK D2O_LAST UP_RC INIT_SCRIPT HEAL_LOCK HEAL_LAST MIN_INTERVAL LOCK_STALE
if sh "$TEMP/d2o-fw-heal.sh"; then d2o_first_rc=0; else d2o_first_rc=$?; fi
if sh "$TEMP/d2o-fw-heal.sh"; then d2o_second_rc=0; else d2o_second_rc=$?; fi

TRACE=$TEMP/r2o-fail.trace
R2O_RUNTIME=$TEMP/r2o-fail-runtime
export TRACE R2O_RUNTIME
mkdir -p "$R2O_RUNTIME"
if sh "$TEMP/r2o-init"; then r2o_first_rc=0; else r2o_first_rc=$?; fi
if sh "$TEMP/r2o-init"; then r2o_second_rc=0; else r2o_second_rc=$?; fi
d2o_failed_up=$(grep -c up "$TEMP/d2o-fail.trace" || true)
r2o_failed_up=$(grep -c up "$TEMP/r2o-fail.trace" || true)
[ "$d2o_first_rc/$d2o_second_rc" = '1/0' ] &&
    [ "$r2o_first_rc/$r2o_second_rc" = '1/0' ] &&
    [ "$d2o_failed_up" = 1 ] && [ "$r2o_failed_up" = "$d2o_failed_up" ] || {
        printf 'failed-up cooldown differs: D2O rc=%s/%s up=%s; R2O rc=%s/%s up=%s\n' \
            "$d2o_first_rc" "$d2o_second_rc" "$d2o_failed_up" \
            "$r2o_first_rc" "$r2o_second_rc" "$r2o_failed_up" >&2
        printf 'D2O trace:\n' >&2; cat "$TEMP/d2o-fail.trace" >&2
        printf 'R2O trace:\n' >&2; cat "$TEMP/r2o-fail.trace" >&2
        exit 1
    }
printf 'D2O/R2O NDM heal serialization and failed-up cooldown match %s.\n' "$ACTUAL_D2O_SHA"
