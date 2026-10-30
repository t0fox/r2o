#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    echo "unexpected D2O revision" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-flowoffload.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin"

sed -n '/^flowoffload_saved() {/,/^prepare_runtime() {/p' "$D2O_ROOT/files/S99d2k" |
    sed '$d' | tr -d '\r' > "$TEMP/d2o.sh"
sed -n '/^flowoffload_saved() {/,/^engine_start() {/p' "$ROOT/router/S99r2o" |
    sed '$d' | tr -d '\r' > "$TEMP/r2o.sh"
[ -s "$TEMP/d2o.sh" ] || { echo "could not extract D2O flow-offload lifecycle" >&2; exit 2; }

cat > "$TEMP/bin/uci" <<'UCI'
#!/bin/sh
[ "${1:-}" = -q ] && shift
case "${1:-}" in
    get) cat "$FLOW_SETTING_FILE" ;;
    set)
        [ "${FAIL_UCI_SET:-0}" = 0 ] || exit 1
        printf '%s\n' "${2#*=}" > "$FLOW_SETTING_FILE"
        ;;
    commit) : ;;
    *) exit 2 ;;
esac
UCI
cat > "$TEMP/bin/fw4" <<'FW4'
#!/bin/sh
printf '%s\n' "$*" >> "$FW_TRACE"
FW4
chmod 0755 "$TEMP/bin/uci" "$TEMP/bin/fw4"

cat > "$TEMP/step.sh" <<'STEP'
#!/bin/sh
set -eu
functions=$1
step=$2
say() { :; }
. "$functions"
case "$step" in
    start|restart)
        if command -v flowoffload_off >/dev/null 2>&1; then flowoffload_off; fi
        ;;
    stop)
        if command -v flowoffload_restore >/dev/null 2>&1; then flowoffload_restore; fi
        ;;
esac
saved=absent
[ ! -f "$RUN/flow-offloading.saved" ] || saved=$(cat "$RUN/flow-offloading.saved")
reloads=$(wc -l < "$FW_TRACE" | tr -d ' ')
printf '%s setting=%s saved=%s reloads=%s\n' "$step" "$(cat "$FLOW_SETTING_FILE")" "$saved" "$reloads"
STEP
chmod 0755 "$TEMP/step.sh"

run_case() {
    implementation=$1
    initial=$2
    backend=${3:-nft}
    run="$TEMP/$implementation-$initial-$backend"
    mkdir -p "$run"
    printf '%s\n' "$initial" > "$run/flow-setting"
    : > "$run/fw.trace"
    : > "$run/empty.sh"
    functions=$TEMP/$implementation.sh
    [ "$implementation" != r2o ] || [ -s "$functions" ] || functions=$run/empty.sh
    for step in start restart stop; do
        RUN="$run" RUNTIME="$run" FW_BACKEND="$backend" R2O_FW="$backend" \
        FLOW_SETTING_FILE="$run/flow-setting" FW_TRACE="$run/fw.trace" \
        PATH="$TEMP/bin:$PATH" sh "$TEMP/step.sh" "$functions" "$step"
    done > "$run/output"
    cat "$run/output"
}

run_case d2o 1 > "$TEMP/d2o-enabled.out"
run_case r2o 1 > "$TEMP/r2o-enabled.out"
if ! cmp -s "$TEMP/d2o-enabled.out" "$TEMP/r2o-enabled.out"; then
    echo "D2O/R2O flow-offload lifecycle differs with fw4 acceleration enabled" >&2
    diff -u "$TEMP/d2o-enabled.out" "$TEMP/r2o-enabled.out" >&2 || true
    exit 1
fi

run_case d2o 0 > "$TEMP/d2o-disabled.out"
run_case r2o 0 > "$TEMP/r2o-disabled.out"
if ! cmp -s "$TEMP/d2o-disabled.out" "$TEMP/r2o-disabled.out"; then
    echo "D2O/R2O flow-offload lifecycle differs when fw4 acceleration is disabled" >&2
    diff -u "$TEMP/d2o-disabled.out" "$TEMP/r2o-disabled.out" >&2 || true
    exit 1
fi

grep -A 50 '^engine_start() {' "$ROOT/router/S99r2o" | grep -q 'flowoffload_off' || {
    echo "R2O engine_start does not disable configured fw4 flow offloading" >&2
    exit 1
}
grep -A 12 '^engine_stop() {' "$ROOT/router/S99r2o" | grep -q 'flowoffload_restore' || {
    echo "R2O engine_stop does not restore fw4 flow offloading" >&2
    exit 1
}

echo "test-router-flowoffload-lifecycle-differential: start/restart/stop state matches D2O"
