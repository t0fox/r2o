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

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-ppe-backend.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
for side in d2o r2o; do
    mkdir -p "$TEMP/$side/state"
    : >"$TEMP/$side/state/d2k-ppe"
done

sed 's/\r$//' "$D2O_ROOT/files/S99d2k" |
    sed -n '/^fw_up() {/,/^}/p' >"$TEMP/d2o-fw-up.sh"
sed -n '/^ppe_call() {/,/^}/p; /^ppe_ensure() {/,/^}/p; /^ppe_remove() {/,/^}/p; /^reapply() {/,/^}/p' \
    "$ROOT/router/S99r2o" >"$TEMP/r2o-functions.sh"

cat >"$TEMP/run-d2o.sh" <<'D2O'
#!/bin/sh
set -eu
EVENTS=$1
PPE_STATE=$2
export EVENTS PPE_STATE
FW_BACKEND=nft
fw_lock_acquire() { :; }
fw_lock_release() { :; }
fw_iptables_down() {
    printf 'PPE:remove\n' >>"$EVENTS"
    rm -f "$PPE_STATE/d2k-ppe"
}
fw_nft_up() { printf 'FIREWALL:up\n' >>"$EVENTS"; }
fw_up_unlocked() { return 2; }
say() { :; }
. "$3"
fw_up
if [ -f "$PPE_STATE/d2k-ppe" ] || [ -f "$PPE_STATE/r2o-ppe" ]; then
    echo PPE_RULES:present
else
    echo PPE_RULES:absent
fi
cat "$EVENTS"
D2O
cat >"$TEMP/ppe-adapter" <<'PPE'
#!/bin/sh
case "$1" in
    remove)
        printf 'PPE:remove\n' >>"$EVENTS"
        rm -f "$PPE_STATE/d2k-ppe" "$PPE_STATE/r2o-ppe"
        ;;
    ensure)
        printf 'PPE:ensure\n' >>"$EVENTS"
        : >"$PPE_STATE/r2o-ppe"
        ;;
    *) exit 2 ;;
esac
PPE
cat >"$TEMP/firewall" <<'FIREWALL'
#!/bin/sh
[ "$1" = up ] || exit 2
printf 'FIREWALL:up\n' >>"$EVENTS"
FIREWALL
cat >"$TEMP/run-r2o.sh" <<'R2O'
#!/bin/sh
set -eu
EVENTS=$1
PPE_STATE=$2
PPE_ADAPTER=$3
FIREWALL=$4
CONF=$5
R2O_FW=nft
R2O_PPE_DEOFFLOAD=1
PORTS=0:65535
VOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344
HTTP_KEEPALIVE_PORTS=80
ROOT=$6
DP4_PID=datapath.pid
component_running() { return 0; }
die() { echo "$*" >&2; exit 1; }
say() { :; }
export EVENTS PPE_STATE
. "$7"
reapply
if [ -f "$PPE_STATE/d2k-ppe" ] || [ -f "$PPE_STATE/r2o-ppe" ]; then
    echo PPE_RULES:present
else
    echo PPE_RULES:absent
fi
cat "$EVENTS"
R2O
chmod 0755 "$TEMP/run-d2o.sh" "$TEMP/ppe-adapter" "$TEMP/firewall" "$TEMP/run-r2o.sh"

"$TEMP/run-d2o.sh" "$TEMP/d2o/events" "$TEMP/d2o/state" "$TEMP/d2o-fw-up.sh" >"$TEMP/d2o.out"
"$TEMP/run-r2o.sh" "$TEMP/r2o/events" "$TEMP/r2o/state" "$TEMP/ppe-adapter" \
    "$TEMP/firewall" "$TEMP/r2o/config" "$TEMP/r2o" "$TEMP/r2o-functions.sh" >"$TEMP/r2o.out"
cat "$TEMP/d2o.out" "$TEMP/r2o.out"
cmp "$TEMP/d2o.out" "$TEMP/r2o.out"
printf 'D2O %s and R2O agree on PPE cleanup for nft-backend reapply.\n' \
    "$ACTUAL_D2O_SHA"
