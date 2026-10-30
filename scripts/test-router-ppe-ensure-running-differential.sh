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

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-ppe-running.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

sed 's/\r$//' "$D2O_ROOT/files/S99d2k" |
    sed -n '/^ppe_ensure() {/,/^}/p' >"$TEMP/d2o-functions.sh"
sed -n '/^ppe_ensure() {/,/^}/p' "$ROOT/router/S99r2o" >"$TEMP/r2o-functions.sh"

cat >"$TEMP/run-d2o.sh" <<'D2O'
#!/bin/sh
set -eu
TRACE=$1
MOCK_RUNNING=$2
DP_PID=datapath.pid
FW_BACKEND=iptables
running() { [ "$MOCK_RUNNING" = 1 ]; }
fw_lock_acquire() { :; }
fw_lock_release() { :; }
d2k_ppe_ensure() { printf 'ensure\n' >>"$TRACE"; return 0; }
. "$3"
ppe_ensure
cat "$TRACE"
D2O

cat >"$TEMP/run-r2o.sh" <<'R2O'
#!/bin/sh
set -eu
TRACE=$1
MOCK_RUNNING=$2
R2O_FW=iptables
DP4_PID=datapath.pid
PPE_ADAPTER=$3
component_running() { [ "$MOCK_RUNNING" = 1 ]; }
ppe_call() { "$PPE_ADAPTER" "$@"; }
say() { :; }
. "$4"
ppe_ensure
cat "$TRACE"
R2O

cat >"$TEMP/ppe-adapter" <<'PPE'
#!/bin/sh
[ "$1" = ensure ] || exit 2
printf 'ensure\n' >>"$TRACE"
PPE
chmod 0755 "$TEMP/run-d2o.sh" "$TEMP/run-r2o.sh" "$TEMP/ppe-adapter"

for running in 0 1; do
    : >"$TEMP/d2o.trace"
    : >"$TEMP/r2o.trace"
    "$TEMP/run-d2o.sh" "$TEMP/d2o.trace" "$running" "$TEMP/d2o-functions.sh" >"$TEMP/d2o.out"
    TRACE="$TEMP/r2o.trace" "$TEMP/run-r2o.sh" "$TEMP/r2o.trace" "$running" \
        "$TEMP/ppe-adapter" "$TEMP/r2o-functions.sh" >"$TEMP/r2o.out"
    if ! cmp -s "$TEMP/d2o.out" "$TEMP/r2o.out"; then
        printf 'running=%s\nD2O:\n' "$running" >&2
        cat "$TEMP/d2o.out" >&2
        printf 'R2O:\n' >&2
        cat "$TEMP/r2o.out" >&2
        exit 1
    fi
done

printf 'D2O %s and R2O agree that PPE ensure runs only while the datapath is active.\n' \
    "$ACTUAL_D2O_SHA"
