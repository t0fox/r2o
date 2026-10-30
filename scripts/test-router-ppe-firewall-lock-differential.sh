#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-ppe-lock.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

sed 's/\r$//' "$D2O_ROOT/files/S99d2k" |
    sed -n '/^fw_lock_acquire() {/,/^}/p; /^fw_lock_release() {/,/^}/p; /^ppe_ensure() {/,/^}/p' \
        >"$TEMP/d2o-functions.sh"
sed -n '/^ppe_call() {/,/^}/p; /^ppe_ensure() {/,/^}/p' "$ROOT/router/S99r2o" \
    >"$TEMP/r2o-functions.sh"

cat >"$TEMP/run-d2o.sh" <<'D2O'
#!/bin/sh
set -eu
TRACE=$1
FW_LOCK=$2
DP_PID=datapath.pid
FW_BACKEND=iptables
running() { return 0; }
fw_lock_wait() { :; }
d2k_ppe_ensure() { printf 'ensure\n' >>"$TRACE"; }
. "$3"
ppe_ensure
D2O

cat >"$TEMP/run-r2o.sh" <<'R2O'
#!/bin/sh
set -eu
TRACE=$1
R2O_FIREWALL_LOCK=$2
R2O_RUN_DIR=${2%/*}
FIREWALL=$3
PPE_ADAPTER=$4
CONF=$2.conf
PORTS=0:65535
VOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344
HTTP_KEEPALIVE_PORTS=80
DP4_PID=datapath.pid
R2O_FW=iptables
R2O_PPE_DEOFFLOAD=1
component_running() { return 0; }
say() { :; }
export TRACE R2O_FIREWALL_LOCK R2O_RUN_DIR
. "$5"
ppe_ensure
R2O

cat >"$TEMP/ppe-adapter" <<'PPE'
#!/bin/sh
[ "$1" = ensure ] || exit 2
printf 'ensure\n' >>"$TRACE"
PPE
chmod 0755 "$TEMP/run-d2o.sh" "$TEMP/run-r2o.sh" "$TEMP/ppe-adapter"

check_locked_wait() {
    side=$1
    lock=$TEMP/$side.lock
    trace=$TEMP/$side.trace
    : >"$trace"
    mkdir "$lock"
    printf '%s\n' "$$" >"$lock/pid"
    if [ "$side" = d2o ]; then
        "$TEMP/run-d2o.sh" "$trace" "$lock" "$TEMP/d2o-functions.sh" >"$TEMP/$side.out" &
    else
        "$TEMP/run-r2o.sh" "$trace" "$lock" "$ROOT/router/r2o-firewall.sh" \
            "$TEMP/ppe-adapter" "$TEMP/r2o-functions.sh" >"$TEMP/$side.out" &
    fi
    child=$!
    sleep 0.4
    if [ -s "$trace" ]; then
        printf '%s inserted PPE while the firewall lock was held\n' "$side" >&2
        rm -f "$lock/pid"
        rmdir "$lock"
        wait "$child" || true
        return 1
    fi
    rm -f "$lock/pid"
    rmdir "$lock"
    wait "$child"
    [ "$(cat "$trace")" = ensure ]
}

check_locked_wait d2o
check_locked_wait r2o
cmp "$TEMP/d2o.trace" "$TEMP/r2o.trace"
printf 'D2O %s and R2O serialize PPE ensure with firewall transactions.\n' "$ACTUAL_D2O_SHA"
