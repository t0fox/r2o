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

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-reapply-differential.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

sed -n '/^reapply() {/,/^}/p' "$D2O_ROOT/files/S99d2k" | sed 's/\r$//' > "$TEMP/d2o-reapply.sh"
sed -n '/^    heal)/,/^    dns-tick)/{ /^    dns-tick)/d; p; }' "$D2O_ROOT/files/S99d2k" |
    sed 's/\r$//' | sed 's/^    heal) //' | sed 's/^[[:space:]]*//' | sed 's/ ;;$//' > "$TEMP/d2o-heal-body.sh"
sed -n '/^    reapply)/,/^    clear-found)/{ /^    clear-found)/d; p; }' "$D2O_ROOT/files/S99d2k" |
    sed 's/\r$//' > "$TEMP/d2o-reapply-case.sh"
sed -n '/^reapply() {/,/^}/p; /^heal_reapply() {/,/^}/p' "$ROOT/router/S99r2o" |
    sed 's/\r$//' > "$TEMP/r2o-reapply.sh"
sed -n '/^heal() {/,/^}/p' "$ROOT/router/S99r2o" | sed 's/\r$//' > "$TEMP/r2o-heal.sh"
sed -n '/^    reapply)/,/^    ppe-ensure)/{ /^    ppe-ensure)/d; p; }' "$ROOT/router/S99r2o" |
    sed 's/\r$//' > "$TEMP/r2o-reapply-case.sh"

[ -s "$TEMP/d2o-reapply.sh" ] && [ -s "$TEMP/d2o-heal-body.sh" ] &&
    [ -s "$TEMP/d2o-reapply-case.sh" ] && [ -s "$TEMP/r2o-heal.sh" ] &&
    [ -s "$TEMP/r2o-reapply-case.sh" ] || {
        echo 'could not extract current D2O/R2O reapply or heal behavior' >&2
        exit 2
    }

{
    cat "$TEMP/d2o-reapply.sh"
    printf '\nd2o_heal() {\n'
    cat "$TEMP/d2o-heal-body.sh"
    printf '\n}\n'
    cat <<'D2O_CASE'
d2o_cli() {
    case "$1" in
D2O_CASE
    cat "$TEMP/d2o-reapply-case.sh"
    cat <<'D2O_CASE'
    esac
}
D2O_CASE
} > "$TEMP/d2o-functions.sh"

{
    [ ! -s "$TEMP/r2o-reapply.sh" ] || cat "$TEMP/r2o-reapply.sh"
    cat "$TEMP/r2o-heal.sh"
    cat <<'R2O_CASE'
r2o_cli() {
    case "$1" in
R2O_CASE
    cat "$TEMP/r2o-reapply-case.sh"
    cat <<'R2O_CASE'
    esac
}
R2O_CASE
} > "$TEMP/r2o-functions.sh"

cat > "$TEMP/d2o-driver.sh" <<'DRIVER'
#!/bin/sh
set -u
TRACE=$1
SCENARIO=$2
DP_PID=running
FW_RC=$3
DATAPATH_RUNNING=$4
export TRACE
trace() { printf '%s\n' "$1" >> "$TRACE"; }
running() { [ "$DATAPATH_RUNNING" = 1 ]; }
fw_installed() { return 1; }
legacy_http_stop() { trace legacy_http_stop; }
load_modules() { trace load_modules; }
fw_up() { trace fw_up; return "$FW_RC"; }
fw_down() { trace fw_down; }
ppe_ensure() { trace ppe_ensure; return 0; }
telegram_reapply() { trace telegram_reapply; return 0; }
say() { :; }
die() { trace die; exit 1; }
. "$5"
case "$SCENARIO" in
    heal) d2o_heal ;;
    reapply) d2o_cli reapply ;;
esac
DRIVER

cat > "$TEMP/firewall" <<'FIREWALL'
#!/bin/sh
printf 'firewall_%s\n' "$1" >> "$TRACE"
case "$1" in
    status) exit 1 ;;
    up) exit "$FIREWALL_UP_RC" ;;
    *) exit 0 ;;
esac
FIREWALL
chmod 0700 "$TEMP/firewall"

cat > "$TEMP/r2o-driver.sh" <<'DRIVER'
#!/bin/sh
set -u
TRACE=$1
SCENARIO=$2
FIREWALL=$3
DP4_PID=running
RUNTIME=$TRACE.runtime
FIREWALL_UP_RC=$4
DATAPATH_RUNNING=$5
export TRACE FIREWALL_UP_RC DATAPATH_RUNNING
trace() { printf '%s\n' "$1" >> "$TRACE"; }
component_running() { [ "$DATAPATH_RUNNING" = 1 ] && [ "$1" = r2o-datapath ]; }
ppe_ensure() { trace ppe_ensure; return 0; }
telegram_reapply() { trace telegram_reapply; return 0; }
say() { :; }
die() { trace die; exit 1; }
. "$6"
case "$SCENARIO" in
    heal) heal ;;
    reapply) r2o_cli reapply ;;
esac
DRIVER

assert_event() {
    grep -Fxq "$2" "$1" || {
        printf 'missing event %s in %s\n' "$2" "$1" >&2
        cat "$1" >&2
        exit 1
    }
}

run_pair() {
    scenario=$1
    fw_rc=$2
    expected=$3
    datapath_running=${4:-1}
    d2o_trace=$TEMP/d2o-$scenario.trace
    r2o_trace=$TEMP/r2o-$scenario.trace
    : > "$d2o_trace"
    : > "$r2o_trace"
    if sh "$TEMP/d2o-driver.sh" "$d2o_trace" "$scenario" "$fw_rc" "$datapath_running" "$TEMP/d2o-functions.sh"; then
        d2o_rc=0
    else
        d2o_rc=$?
    fi
    if sh "$TEMP/r2o-driver.sh" "$r2o_trace" "$scenario" "$TEMP/firewall" "$fw_rc" "$datapath_running" "$TEMP/r2o-functions.sh" \
        2> "$TEMP/r2o-$scenario.stderr"; then
        r2o_rc=0
    else
        r2o_rc=$?
    fi
    [ "$d2o_rc" = "$expected" ] || {
        printf 'D2O %s returned %s, expected %s\n' "$scenario" "$d2o_rc" "$expected" >&2
        cat "$d2o_trace" >&2
        exit 1
    }
    [ "$r2o_rc" = "$d2o_rc" ] || {
        printf 'D2O/R2O %s return mismatch: %s/%s\n' "$scenario" "$d2o_rc" "$r2o_rc" >&2
        printf 'D2O trace:\n' >&2; cat "$d2o_trace" >&2
        printf 'R2O trace:\n' >&2; cat "$r2o_trace" >&2
        cat "$TEMP/r2o-$scenario.stderr" >&2
        exit 1
    }
    if [ "$datapath_running" = 0 ]; then
        if grep -Fxq fw_up "$d2o_trace" || grep -Fxq firewall_up "$r2o_trace"; then
            echo 'reapply touched firewall while datapath was stopped' >&2
            exit 1
        fi
    elif [ "$scenario" = heal ] || [ "$fw_rc" = 0 ]; then
        assert_event "$d2o_trace" fw_up
        assert_event "$r2o_trace" firewall_up
    else
        assert_event "$d2o_trace" fw_down
        assert_event "$r2o_trace" firewall_up
    fi
    if [ "$scenario" = heal ]; then
        assert_event "$d2o_trace" ppe_ensure
        assert_event "$d2o_trace" telegram_reapply
        assert_event "$r2o_trace" ppe_ensure
        assert_event "$r2o_trace" telegram_reapply
    fi
}

run_pair heal 0 0
run_pair reapply 1 1
run_pair reapply 0 0
run_pair reapply 0 1 0
printf 'D2O/R2O reapply return codes and selected heal transitions match %s.\n' "$ACTUAL_D2O_SHA"
