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
    get)
        case "${2:-}" in
            *flow_offloading_hw) cat "$FLOW_HW_SETTING_FILE" ;;
            *) cat "$FLOW_SETTING_FILE" ;;
        esac
        ;;
    set)
        [ "${FAIL_UCI_SET:-0}" = 0 ] || exit 1
        case "${2:-}" in
            *flow_offloading_hw=*) printf '%s\n' "${2#*=}" > "$FLOW_HW_SETTING_FILE" ;;
            *) printf '%s\n' "${2#*=}" > "$FLOW_SETTING_FILE" ;;
        esac
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
printf '%s setting=%s hw=%s saved=%s reloads=%s\n' "$step" "$(cat "$FLOW_SETTING_FILE")" "$(cat "$FLOW_HW_SETTING_FILE")" "$saved" "$reloads"
STEP
chmod 0755 "$TEMP/step.sh"

run_case() {
    implementation=$1
    initial=$2
    hw_initial=${3:-1}
    backend=${4:-nft}
    run="$TEMP/$implementation-$initial-$hw_initial-$backend"
    mkdir -p "$run"
    printf '%s\n' "$initial" > "$run/flow-setting"
    printf '%s\n' "$hw_initial" > "$run/flow-hw-setting"
    : > "$run/fw.trace"
    : > "$run/empty.sh"
    functions=$TEMP/$implementation.sh
    [ "$implementation" != r2o ] || [ -s "$functions" ] || functions=$run/empty.sh
    for step in start restart stop; do
        RUN="$run" RUNTIME="$run" FW_BACKEND="$backend" R2O_FW="$backend" \
        FLOW_SETTING_FILE="$run/flow-setting" FLOW_HW_SETTING_FILE="$run/flow-hw-setting" FW_TRACE="$run/fw.trace" \
        PATH="$TEMP/bin:$PATH" sh "$TEMP/step.sh" "$functions" "$step"
    done > "$run/output"
    cat "$run/output"
}

run_case d2o 1 > "$TEMP/d2o-enabled.out"
run_case r2o 1 > "$TEMP/r2o-enabled.out"
printf '%s\n' \
    'start setting=0 hw=1 saved=1 reloads=1' \
    'restart setting=0 hw=1 saved=1 reloads=1' \
    'stop setting=1 hw=1 saved=absent reloads=2' > "$TEMP/d2o-enabled.expected"
if ! cmp -s "$TEMP/d2o-enabled.expected" "$TEMP/d2o-enabled.out"; then
    echo "D2O flow-offload guard trace changed" >&2
    diff -u "$TEMP/d2o-enabled.expected" "$TEMP/d2o-enabled.out" >&2 || true
    exit 1
fi
printf '%s\n' \
    'start setting=1 hw=1 saved=absent reloads=0' \
    'restart setting=1 hw=1 saved=absent reloads=0' \
    'stop setting=1 hw=1 saved=absent reloads=0' > "$TEMP/r2o-enabled.expected"
if ! cmp -s "$TEMP/r2o-enabled.expected" "$TEMP/r2o-enabled.out"; then
    echo "R2O changed the configured native fw4 flow-offload state" >&2
    diff -u "$TEMP/r2o-enabled.expected" "$TEMP/r2o-enabled.out" >&2 || true
    exit 1
fi

run_case d2o 0 > "$TEMP/d2o-disabled.out"
run_case r2o 0 > "$TEMP/r2o-disabled.out"
run_case r2o 1 0 > "$TEMP/r2o-software-only.out"
printf '%s\n' \
    'start setting=0 hw=1 saved=absent reloads=0' \
    'restart setting=0 hw=1 saved=absent reloads=0' \
    'stop setting=0 hw=1 saved=absent reloads=0' > "$TEMP/d2o-disabled.expected"
if ! cmp -s "$TEMP/d2o-disabled.expected" "$TEMP/d2o-disabled.out"; then
    echo "D2O disabled flow-offload trace changed" >&2
    diff -u "$TEMP/d2o-disabled.expected" "$TEMP/d2o-disabled.out" >&2 || true
    exit 1
fi
printf '%s\n' \
    'start setting=0 hw=1 saved=absent reloads=0' \
    'restart setting=0 hw=1 saved=absent reloads=0' \
    'stop setting=0 hw=1 saved=absent reloads=0' > "$TEMP/r2o-disabled.expected"
if ! cmp -s "$TEMP/r2o-disabled.expected" "$TEMP/r2o-disabled.out"; then
    echo "R2O changed the disabled native fw4 flow-offload state" >&2
    diff -u "$TEMP/r2o-disabled.expected" "$TEMP/r2o-disabled.out" >&2 || true
    exit 1
fi
printf '%s\n' \
    'start setting=1 hw=0 saved=absent reloads=0' \
    'restart setting=1 hw=0 saved=absent reloads=0' \
    'stop setting=1 hw=0 saved=absent reloads=0' > "$TEMP/r2o-software-only.expected"
if ! cmp -s "$TEMP/r2o-software-only.expected" "$TEMP/r2o-software-only.out"; then
    echo "R2O changed the native fw4 hardware flow-offload state" >&2
    diff -u "$TEMP/r2o-software-only.expected" "$TEMP/r2o-software-only.out" >&2 || true
    exit 1
fi

if grep -Eq 'flowoffload_off|uci set firewall\.@defaults\[0\]\.flow_offloading=0|uci set firewall\.@defaults\[0\]\.flow_offloading_hw=' "$ROOT/router/S99r2o"; then
    echo "R2O must leave native fw4 flow-offload configuration untouched" >&2
    exit 1
fi

echo "test-router-flowoffload-lifecycle-differential: R2O preserves native fw4 state across start/restart/stop (intentionally differs from D2O)"
