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
            *flow_offloading) cat "$FLOW_SETTING_FILE" ;;
            firewall.r2o_flowoffload_hook)
                [ -f "$UCI_HOOK_FILE" ] || exit 1
                cat "$UCI_HOOK_FILE"
                ;;
            firewall.r2o_flowoffload_hook.*)
                [ -f "$UCI_HOOK_FILE" ] || exit 1
                key=${2##*.}
                value=$(sed -n "s/^$key=//p" "$UCI_HOOK_FILE")
                [ -n "$value" ] || exit 1
                printf '%s\n' "$value"
                ;;
            *) exit 1 ;;
        esac
        ;;
    set)
        [ "${FAIL_UCI_SET:-0}" = 0 ] || exit 1
        case "${2:-}" in
            *flow_offloading_hw=*) printf '%s\n' "${2#*=}" > "$FLOW_HW_SETTING_FILE" ;;
            *flow_offloading=*) printf '%s\n' "${2#*=}" > "$FLOW_SETTING_FILE" ;;
            firewall.r2o_flowoffload_hook=include) printf 'section=include\n' > "$UCI_HOOK_FILE" ;;
            firewall.r2o_flowoffload_hook.*=*)
                key=${2#firewall.r2o_flowoffload_hook.}
                key=${key%%=*}
                value=${2#*=}
                temporary=$UCI_HOOK_FILE.new.$$
                if [ -f "$UCI_HOOK_FILE" ]; then awk -F= -v key="$key" '$1 != key' "$UCI_HOOK_FILE" > "$temporary"; fi
                printf '%s=%s\n' "$key" "$value" >> "$temporary"
                mv -f "$temporary" "$UCI_HOOK_FILE"
                ;;
            *) exit 2 ;;
        esac
        ;;
    delete)
        [ "${2:-}" = firewall.r2o_flowoffload_hook ] || exit 2
        rm -f "$UCI_HOOK_FILE"
        ;;
    commit)
        [ -n "${UCI_COMMIT_FILE:-}" ] || exit 0
        printf '%s\n' "$(( $(cat "$UCI_COMMIT_FILE" 2>/dev/null || echo 0) + 1 ))" > "$UCI_COMMIT_FILE"
        ;;
    revert)
        case "${2:-}" in
            firewall)
                rm -f "$UCI_HOOK_FILE" "$FLOW_SETTING_PENDING_FILE" "$FLOW_HW_PENDING_FILE"
                ;;
            firewall.r2o_flowoffload_hook) rm -f "$UCI_HOOK_FILE" ;;
            *) exit 2 ;;
        esac
        ;;
    *) exit 2 ;;
esac
UCI
cat > "$TEMP/bin/fw4" <<'FW4'
#!/bin/sh
printf '%s\n' "$*" >> "$FW_TRACE"
FW4
chmod 0755 "$TEMP/bin/uci" "$TEMP/bin/fw4"
cat > "$TEMP/bin/fw3" <<'FW3'
#!/bin/sh
printf '%s\n' "$*" >> "$FW_TRACE"
FW3
chmod 0755 "$TEMP/bin/fw3"
cp "$ROOT/router/r2o-firewall-fw3-include.sh" "$TEMP/bin/r2o-firewall-fw3-include.sh"
chmod 0755 "$TEMP/bin/r2o-firewall-fw3-include.sh"
cat >"$TEMP/bin/r2o-firewall" <<'FIREWALL'
#!/bin/sh
if [ -n "${FIREWALL_TRACE:-}" ]; then printf '%s\n' "$1" >> "$FIREWALL_TRACE"; fi
case "${1:-}" in
    backend) echo "${R2O_TEST_BACKEND:-nft}" ;;
    ipv6-enabled) echo 1 ;;
    status) [ "${FAIL_FIREWALL_STATUS:-0}" = 0 ] ;;
    flowoffload-restore) exit 0 ;;
    flowoffload-ensure)
        [ "${FAIL_FLOWOFFLOAD_ENSURE:-0}" = 0 ]
        ;;
    *) exit 2 ;;
esac
FIREWALL
chmod 0755 "$TEMP/bin/r2o-firewall"

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
    hook)
        flowoffload_hook_install
        flowoffload_hook_install
        printf 'hook=%s type=%s path=%s compatible=%s reload=%s enabled=%s commits=%s\n' \
            "$(test -f "$UCI_HOOK_FILE" && echo present || echo absent)" \
            "$(uci -q get firewall.r2o_flowoffload_hook.type 2>/dev/null || echo absent)" \
            "$(uci -q get firewall.r2o_flowoffload_hook.path 2>/dev/null || echo absent)" \
            "$(uci -q get firewall.r2o_flowoffload_hook.fw4_compatible 2>/dev/null || echo absent)" \
            "$(uci -q get firewall.r2o_flowoffload_hook.reload 2>/dev/null || echo absent)" \
            "$(uci -q get firewall.r2o_flowoffload_hook.enabled 2>/dev/null || echo absent)" \
            "$(cat "$UCI_COMMIT_FILE" 2>/dev/null || echo 0)"
        flowoffload_hook_remove
        printf 'removed=%s commits=%s\n' \
            "$(test -e "$UCI_HOOK_FILE" && echo yes || echo no)" \
            "$(cat "$UCI_COMMIT_FILE" 2>/dev/null || echo 0)"
        exit 0
        ;;
    hook-existing)
        flowoffload_hook_install
        flowoffload_hook_remove
        printf 'present=%s marker=%s commits=%s\n' \
            "$(test -f "$UCI_HOOK_FILE" && echo yes || echo no)" \
            "$(test -f "$RUN/flowoffload-hook.created" && echo yes || echo no)" \
            "$(cat "$UCI_COMMIT_FILE" 2>/dev/null || echo 0)"
        exit 0
        ;;
    hook-fail)
        flowoffload_hook_install && exit 2
        printf 'flow=%s hw=%s pending=%s hook=%s\n' \
            "$(cat "$FLOW_SETTING_FILE")" \
            "$(cat "$FLOW_HW_SETTING_FILE")" \
            "$(cat "$FLOW_SETTING_PENDING_FILE" 2>/dev/null || echo absent)" \
            "$(test -f "$UCI_HOOK_FILE" && echo present || echo absent)"
        exit 0
        ;;
    skip-restore)
        flowoffload_restore
        printf 'saved=%s\n' "$(test -f "$RUN/flow-offloading.saved" && echo yes || echo no)"
        exit 0
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
        FIREWALL="$TEMP/bin/r2o-firewall" \
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

hook="$TEMP/r2o-hook"
mkdir -p "$hook"
printf '1\n' >"$hook/flow-setting"
printf '1\n' >"$hook/flow-hw-setting"
: >"$hook/fw.trace"
: >"$hook/commits"
RUN="$hook" RUNTIME="$hook" FLOW_SETTING_FILE="$hook/flow-setting" \
FLOW_HW_SETTING_FILE="$hook/flow-hw-setting" FW_TRACE="$hook/fw.trace" \
UCI_HOOK_FILE="$hook/include" UCI_COMMIT_FILE="$hook/commits" \
INIT="$TEMP/bin/r2o-init" FIREWALL="$TEMP/bin/r2o-firewall" \
PATH="$TEMP/bin:$PATH" sh "$TEMP/step.sh" "$TEMP/r2o.sh" hook >"$hook/output"
{
    printf 'hook=present type=script path=%s compatible=1 reload=absent enabled=1 commits=1\n' "$TEMP/bin/r2o-init"
    printf 'removed=no commits=2\n'
} >"$hook/expected"
if ! cmp -s "$hook/expected" "$hook/output"; then
    echo "fw4 include hook lifecycle is not idempotent or reversible" >&2
    diff -u "$hook/expected" "$hook/output" >&2 || true
    exit 1
fi
hook_iptables="$TEMP/r2o-hook-iptables"
mkdir -p "$hook_iptables"
printf '1\n' >"$hook_iptables/flow-setting"
printf '1\n' >"$hook_iptables/flow-hw-setting"
: >"$hook_iptables/fw.trace"
: >"$hook_iptables/commits"
RUN="$hook_iptables" RUNTIME="$hook_iptables" FLOW_SETTING_FILE="$hook_iptables/flow-setting" \
FLOW_HW_SETTING_FILE="$hook_iptables/flow-hw-setting" FW_TRACE="$hook_iptables/fw.trace" \
UCI_HOOK_FILE="$hook_iptables/include" UCI_COMMIT_FILE="$hook_iptables/commits" \
INIT="$TEMP/bin/r2o-init" FIREWALL="$TEMP/bin/r2o-firewall" R2O_TEST_BACKEND=iptables \
PATH="$TEMP/bin:$PATH" sh "$TEMP/step.sh" "$TEMP/r2o.sh" hook >"$hook_iptables/output"
{
    printf 'hook=present type=script path=%s compatible=1 reload=absent enabled=1 commits=1\n' "$TEMP/bin/r2o-init"
    printf 'removed=no commits=2\n'
} >"$hook_iptables/expected"
if ! cmp -s "$hook_iptables/expected" "$hook_iptables/output"; then
    echo "fw4 hook was not installed for runtime fallback with the iptables datapath" >&2
    diff -u "$hook_iptables/expected" "$hook_iptables/output" >&2 || true
    exit 1
fi
hook_fw3="$TEMP/r2o-hook-fw3"
mkdir -p "$hook_fw3"
printf '1\n' >"$hook_fw3/flow-setting"
printf '1\n' >"$hook_fw3/flow-hw-setting"
: >"$hook_fw3/fw.trace"
: >"$hook_fw3/commits"
mv "$TEMP/bin/fw4" "$TEMP/bin/fw4.disabled"
RUN="$hook_fw3" RUNTIME="$hook_fw3" FLOW_SETTING_FILE="$hook_fw3/flow-setting" \
FLOW_HW_SETTING_FILE="$hook_fw3/flow-hw-setting" FW_TRACE="$hook_fw3/fw.trace" \
UCI_HOOK_FILE="$hook_fw3/include" UCI_COMMIT_FILE="$hook_fw3/commits" \
INIT="$TEMP/bin/r2o-init" FIREWALL="$TEMP/bin/r2o-firewall" \
PATH="$TEMP/bin:$PATH" sh "$TEMP/step.sh" "$TEMP/r2o.sh" hook >"$hook_fw3/output"
mv "$TEMP/bin/fw4.disabled" "$TEMP/bin/fw4"
{
    printf 'hook=present type=script path=%s/r2o-firewall-fw3-include.sh compatible=absent reload=1 enabled=1 commits=1\n' "$TEMP/bin"
    printf 'removed=no commits=2\n'
} >"$hook_fw3/expected"
if ! cmp -s "$hook_fw3/expected" "$hook_fw3/output"; then
    echo "fw3 include hook lifecycle is not idempotent or reversible" >&2
    diff -u "$hook_fw3/expected" "$hook_fw3/output" >&2 || true
    exit 1
fi
: >"$hook_fw3/include-trace"
if ! ACTION=reload FW3_INCLUDE="$TEMP/bin/r2o-firewall-fw3-include.sh" \
    R2O_INIT="$ROOT/router/S99r2o" R2O_DIR="$hook_fw3" R2O_CONFIG="$hook_fw3/config" \
    R2O_FIREWALL="$TEMP/bin/r2o-firewall" FIREWALL_TRACE="$hook_fw3/include-trace" \
    sh -c 'config() { :; }; . "$FW3_INCLUDE"' >"$hook_fw3/include-output" 2>&1; then
    echo "fw3 script include handler failed" >&2
    cat "$hook_fw3/include-output" >&2
    exit 1
fi
printf '%s\n' status flowoffload-ensure >"$hook_fw3/include-expected"
if ! cmp -s "$hook_fw3/include-expected" "$hook_fw3/include-trace"; then
    echo "fw3 script include did not reapply native flow-offload fallback" >&2
    cat "$hook_fw3/include-expected" "$hook_fw3/include-trace" "$hook_fw3/include-output" >&2
    exit 1
fi
hook_failure="$TEMP/r2o-hook-failure"
mkdir -p "$hook_failure"
printf '1\n' >"$hook_failure/flow-setting"
printf '1\n' >"$hook_failure/flow-hw-setting"
printf '0\n' >"$hook_failure/flow-setting-pending"
: >"$hook_failure/commits"
FAIL_UCI_SET=1 RUN="$hook_failure" RUNTIME="$hook_failure" \
FLOW_SETTING_FILE="$hook_failure/flow-setting" FLOW_HW_SETTING_FILE="$hook_failure/flow-hw-setting" \
FLOW_SETTING_PENDING_FILE="$hook_failure/flow-setting-pending" \
FLOW_HW_PENDING_FILE="$hook_failure/flow-hw-setting-pending" \
UCI_HOOK_FILE="$hook_failure/include" UCI_COMMIT_FILE="$hook_failure/commits" \
INIT="$TEMP/bin/r2o-init" FIREWALL="$TEMP/bin/r2o-firewall" PATH="$TEMP/bin:$PATH" \
    sh "$TEMP/step.sh" "$TEMP/r2o.sh" hook-fail >"$hook_failure/output"
printf '%s\n' 'flow=1 hw=1 pending=0 hook=absent' >"$hook_failure/expected"
if ! cmp -s "$hook_failure/expected" "$hook_failure/output"; then
    echo "failed fw4 hook installation reverted unrelated pending offload settings" >&2
    diff -u "$hook_failure/expected" "$hook_failure/output" >&2 || true
    exit 1
fi
existing="$TEMP/r2o-hook-existing"
mkdir -p "$existing"
printf '%s\n' type=script "path=$TEMP/bin/r2o-init" fw4_compatible=1 enabled=1 >"$existing/include"
RUN="$existing" RUNTIME="$existing" UCI_HOOK_FILE="$existing/include" \
UCI_COMMIT_FILE="$existing/commits" INIT="$TEMP/bin/r2o-init" \
FIREWALL="$TEMP/bin/r2o-firewall" PATH="$TEMP/bin:$PATH" \
    sh "$TEMP/step.sh" "$TEMP/r2o.sh" hook-existing >"$existing/output"
printf '%s\n' 'present=yes marker=no commits=0' >"$existing/expected"
if ! cmp -s "$existing/expected" "$existing/output"; then
    echo "stopping R2O changed a pre-existing fw4 include" >&2
    cat "$existing/expected" "$existing/output" "$existing/include" >&2
    exit 1
fi
printf 'R2O_CONFIG=\n' >"$hook/config"
: >"$hook/include-trace"
if ! ACTION=includes R2O_DIR="$hook" R2O_CONFIG="$hook/config" \
    R2O_INIT="$TEMP/bin/r2o-init" R2O_FIREWALL="$TEMP/bin/r2o-firewall" \
    FIREWALL_TRACE="$hook/include-trace" PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/S99r2o" >"$hook/include-output" 2>&1; then
    echo "fw4 script include handler failed" >&2
    cat "$hook/include-output" >&2
    exit 1
fi
printf '%s\n' status flowoffload-ensure >"$hook/include-expected"
if ! cmp -s "$hook/include-expected" "$hook/include-trace"; then
    echo "fw4 script include did not reapply selective flow offload" >&2
    cat "$hook/include-expected" "$hook/include-trace" "$hook/include-output" >&2
    exit 1
fi
: >"$hook/include-trace"
ACTION=includes R2O_FLOWOFFLOAD_RESTORING=1 R2O_DIR="$hook" R2O_CONFIG="$hook/config" \
R2O_INIT="$TEMP/bin/r2o-init" R2O_FIREWALL="$TEMP/bin/r2o-firewall" \
FIREWALL_TRACE="$hook/include-trace" PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/S99r2o" >"$hook/restore-output" 2>&1
: >"$hook/restore-expected"
if ! cmp -s "$hook/restore-expected" "$hook/include-trace"; then
    echo "fw4 restore recursively invoked flow-offload ensure while holding its lock" >&2
    cat "$hook/restore-expected" "$hook/include-trace" "$hook/restore-output" >&2
    exit 1
fi
: >"$hook/failure-trace"
if ACTION=includes FAIL_FLOWOFFLOAD_ENSURE=1 R2O_DIR="$hook" R2O_CONFIG="$hook/config" \
    R2O_INIT="$ROOT/router/S99r2o" R2O_FIREWALL="$TEMP/bin/r2o-firewall" \
    R2O_RUNTIME_DIR="$hook/runtime" R2O_PROC="$hook/proc" \
    FIREWALL_TRACE="$hook/failure-trace" \
    PATH="$TEMP/bin:$PATH" sh "$ROOT/router/S99r2o" >"$hook/failure-output" 2>&1; then
    echo "fw4 include swallowed failed flow-offload enforcement" >&2
    exit 1
fi
printf '%s\n' status flowoffload-ensure ipv6-enabled down >"$hook/failure-expected"
if ! cmp -s "$hook/failure-expected" "$hook/failure-trace"; then
    echo "failed fw4 enforcement did not stop R2O without a nested reload" >&2
    cat "$hook/failure-expected" "$hook/failure-trace" "$hook/failure-output" >&2
    exit 1
fi
: >"$hook/status-failure-trace"
if ACTION=includes FAIL_FIREWALL_STATUS=1 R2O_DIR="$hook" R2O_CONFIG="$hook/config" \
    R2O_INIT="$ROOT/router/S99r2o" R2O_FIREWALL="$TEMP/bin/r2o-firewall" \
    R2O_RUNTIME_DIR="$hook/runtime" R2O_PROC="$hook/proc" \
    FIREWALL_TRACE="$hook/status-failure-trace" PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/S99r2o" >"$hook/status-failure-output" 2>&1; then
    echo "fw4 include left R2O running after firewall status failure" >&2
    exit 1
fi
printf '%s\n' status ipv6-enabled down >"$hook/status-failure-expected"
if ! cmp -s "$hook/status-failure-expected" "$hook/status-failure-trace"; then
    echo "fw4 status failure did not fail closed without a nested reload" >&2
    cat "$hook/status-failure-expected" "$hook/status-failure-trace" "$hook/status-failure-output" >&2
    exit 1
fi
skip_restore="$TEMP/r2o-skip-restore"
mkdir -p "$skip_restore"
: >"$skip_restore/fw.trace"
: >"$skip_restore/flow-offloading.saved"
R2O_FLOWOFFLOAD_SKIP_RESTORE=1 RUN="$skip_restore" FIREWALL_TRACE="$skip_restore/fw.trace" \
FIREWALL="$TEMP/bin/r2o-firewall" PATH="$TEMP/bin:$PATH" \
    sh "$TEMP/step.sh" "$TEMP/r2o.sh" skip-restore >"$skip_restore/output"
printf '%s\n' saved=yes >"$skip_restore/expected"
if ! cmp -s "$skip_restore/expected" "$skip_restore/output" || [ -s "$skip_restore/fw.trace" ]; then
    echo "include failure stop attempted a nested fw4 reload" >&2
    cat "$skip_restore/expected" "$skip_restore/output" "$skip_restore/fw.trace" >&2
    exit 1
fi

stale="$TEMP/r2o-stale-legacy-marker"
mkdir -p "$stale"
printf '0\n' >"$stale/flow-setting"
printf '0\n' >"$stale/flow-hw-setting"
: >"$stale/fw.trace"
: >"$stale/empty.sh"
printf '1\n' >"$stale/flow-offloading.saved"
RUN="$stale" RUNTIME="$stale" FLOW_SETTING_FILE="$stale/flow-setting" \
FLOW_HW_SETTING_FILE="$stale/flow-hw-setting" FW_TRACE="$stale/fw.trace" \
FIREWALL="$TEMP/bin/r2o-firewall" PATH="$TEMP/bin:$PATH" \
    sh "$TEMP/step.sh" "$TEMP/r2o.sh" stop >"$stale/output"
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

if [ "$(cat "$stale/flow-setting")" != 0 ] || [ "$(cat "$stale/flow-hw-setting")" != 0 ] \
    || [ -f "$stale/flow-offloading.saved" ]; then
    echo "R2O changed current UCI offload settings while cleaning a legacy marker" >&2
    cat "$stale/output" >&2
    exit 1
fi

if grep -Eq 'flowoffload_off|uci (set|delete) firewall\.@defaults\[0\]\.flow_offloading(_hw)?=' "$ROOT/router/S99r2o"; then
    echo "R2O must leave native fw4 flow-offload configuration untouched" >&2
    exit 1
fi

echo "test-router-flowoffload-lifecycle-differential: R2O preserves native fw4 state across start/restart/stop (intentionally differs from D2O)"
