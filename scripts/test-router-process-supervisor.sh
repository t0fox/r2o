#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
TOOL_ROOT=$(dirname "$ROOT")/r2o-tooling
TEMP_BASE=$TOOL_ROOT/tests
mkdir -p "$TEMP_BASE"
TEMP=$(mktemp -d "$TEMP_BASE/r2o-process-supervisor.XXXXXX")
case "$TEMP" in "$TEMP_BASE"/r2o-process-supervisor.*) ;; *) exit 2 ;; esac
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

INIT=$ROOT/router/S99r2o
TEST_ROOT=$TEMP/root
CONFIG=$TEMP/config
RUNTIME=$TEMP/runtime
FIREWALL=$TEMP/firewall
mkdir -p "$TEST_ROOT" "$RUNTIME"
cat >"$CONFIG" <<EOF
MODE=observe
QUEUE_NUM=2000
QUEUE_NUM6=2001
MARK=45
PROBE_MARK=46
IPV6_ENABLED=0
PANEL_LISTEN=
AUTOUPDATE=0
TG_ENABLED=0
R2O_PPE_DEOFFLOAD=0
STATE_DIR=$TEMP/state
EOF
cat >"$FIREWALL" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "$FIREWALL"

run_init() {
    R2O_DIR=$TEST_ROOT \
    R2O_CONFIG=$CONFIG \
    R2O_RUNTIME_DIR=$RUNTIME \
    R2O_FIREWALL=$FIREWALL \
    R2O_MANAGER=$TEMP/missing-manager \
    R2O_LOG_MAINTENANCE=$TEMP/missing-log \
    R2O_FIREWALL_WATCHDOG=$TEMP/missing-watchdog \
    R2O_PPE_ADAPTER=$TEMP/missing-ppe \
        sh "$INIT" "$@"
}

run_init engine-stop >"$TEMP/stop.log" 2>&1 || {
    cat "$TEMP/stop.log" >&2
    exit 1
}
[ -f "$RUNTIME/supervisor-disabled" ] || {
    echo 'engine-stop did not suppress automatic recovery' >&2
    exit 1
}

run_init supervise >"$TEMP/supervise-stopped.log" 2>&1 || {
    cat "$TEMP/supervise-stopped.log" >&2
    exit 1
}
if grep -q 'release manager' "$TEMP/supervise-stopped.log"; then
    cat "$TEMP/supervise-stopped.log" >&2
    echo 'supervise ignored the intentional stop marker' >&2
    exit 1
fi

if run_init engine-start >"$TEMP/engine-start.log" 2>&1; then
    echo 'engine-start unexpectedly succeeded without a manager' >&2
    exit 1
fi
[ ! -e "$RUNTIME/supervisor-disabled" ] || {
    echo 'explicit engine-start did not re-enable automatic recovery' >&2
    exit 1
}

if run_init supervise >"$TEMP/supervise-enabled.log" 2>&1; then
    echo 'supervise did not attempt to recover an enabled service without its manager' >&2
    exit 1
fi
grep -q 'release manager' "$TEMP/supervise-enabled.log" || {
    cat "$TEMP/supervise-enabled.log" >&2
    echo 'supervise did not reach the expected missing-manager check' >&2
    exit 1
}

run_init stop >"$TEMP/stop.log" 2>&1 || {
    cat "$TEMP/stop.log" >&2
    exit 1
}
[ -f "$RUNTIME/supervisor-disabled" ] || {
    echo 'stop did not suppress automatic recovery' >&2
    exit 1
}

printf '%s\n' 'R2O process recovery respects explicit stop and retries an enabled failed service: PASS'
