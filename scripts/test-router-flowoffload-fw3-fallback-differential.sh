#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
actual_d2o_sha=$(git -C "$D2O_ROOT" rev-parse HEAD)
[ "$actual_d2o_sha" = "$EXPECTED_D2O_SHA" ] || {
    echo "unexpected D2O revision: $actual_d2o_sha" >&2
    exit 2
}
TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-fw3-flowoffload.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin" "$TEMP/run" "$TEMP/runtime"
sed -n '/^flowoffload_off() {/,/^}/p' "$D2O_ROOT/files/S99d2k" | tr -d '\r' > "$TEMP/d2o-flowoffload.sh"
cat > "$TEMP/config" <<'CONFIG'
FW_BACKEND=iptables
IPV6_ENABLED=1
CONFIG
fw3_hw_rule='-A FORWARD -p all -m comment --comment "!fw3: Traffic offloading" -m conntrack --ctstate RELATED,ESTABLISHED -j FLOWOFFLOAD --hw'
fw3_sw_rule='-A FORWARD -p all -m comment --comment "!fw3: Traffic offloading" -m conntrack --ctstate RELATED,ESTABLISHED -j FLOWOFFLOAD'
printf '%s\n' "$fw3_hw_rule" "$fw3_hw_rule" > "$TEMP/ipv4.rules"
printf '%s\n' "$fw3_hw_rule" > "$TEMP/ipv6.rules"
printf '1\n' > "$TEMP/flow_offloading"
printf '1\n' > "$TEMP/flow_offloading_hw"
cat > "$TEMP/bin/iptables" <<'IPTABLES'
#!/bin/sh
if [ "${NO_IPTABLES_WAIT:-0}" = 1 ] && [ "${1:-}" = -w ]; then exit 2; fi
printf 'args=[%s] rule_file=[%s]\n' "$*" "$RULE_FILE" >> "$IPTABLES_TRACE"
case " $* " in
    *' -L POSTROUTING '*) exit 0 ;;
esac
case " $* " in
    *' -S FORWARD '*) cat "$RULE_FILE"; exit 0 ;;
    *' -L FORWARD --line-numbers -n '*)
        awk '/^-A FORWARD/ { printf "%d 0 0 FLOWOFFLOAD all -- * * 0.0.0.0/0 0.0.0.0/0 ctstate RELATED,ESTABLISHED\n", ++line }' "$RULE_FILE"
        exit 0
        ;;
    *' -D FORWARD '*)
        line=$(printf '%s\n' "$*" | sed -n 's/.* -D FORWARD \([0-9][0-9]*\).*/\1/p')
        [ -n "$line" ] || exit 2
        tr -d '\r' < "$RULE_FILE" | awk -v target="$line" \
            'BEGIN { removed=0 } /^-A FORWARD/ { line++ ; if (line == target) { removed=1; next } } { print } END { if (!removed) exit 1 }' \
            > "$RULE_FILE.new"
        mv -f "$RULE_FILE.new" "$RULE_FILE"
        ;;
    *) echo "unexpected iptables call: $*" >&2; exit 2 ;;
esac
IPTABLES
cat > "$TEMP/bin/ip6tables" <<'IP6TABLES'
#!/bin/sh
RULE_FILE=$IPV6_RULES exec "$IPTABLES_BIN" "$@"
IP6TABLES
cat > "$TEMP/bin/nft" <<'NFT'
#!/bin/sh
exit 1
NFT
cat > "$TEMP/bin/fw3" <<'FW3'
#!/bin/sh
exit 0
FW3
cat > "$TEMP/bin/firewall-init" <<'INIT'
#!/bin/sh
echo "$*" >> "$RELOAD_TRACE"
case "${1:-}" in
    reload)
        [ "${FAIL_RELOAD:-0}" = 0 ] || exit 1
        suffix=
        [ "$(cat "$FLOW_HW_SETTING_FILE")" = 1 ] && suffix=' --hw'
        rule='-A FORWARD -p all -m comment --comment "!fw3: Traffic offloading" -m conntrack --ctstate RELATED,ESTABLISHED -j FLOWOFFLOAD'
        printf '%s\n' "$rule$suffix" > "$IPV4_RULES"
        printf '%s\n' "$rule$suffix" > "$IPV6_RULES"
        ;;
    *) exit 2 ;;
esac
INIT
chmod 0755 "$TEMP/bin/iptables" "$TEMP/bin/ip6tables" "$TEMP/bin/nft" \
    "$TEMP/bin/fw3" "$TEMP/bin/firewall-init"

run_firewall() {
    R2O_DIR=$TEMP R2O_CONFIG=$TEMP/config R2O_RUN_DIR=$TEMP/run \
        R2O_RUNTIME_DIR=$TEMP/runtime R2O_FW3=$TEMP/bin/fw3 \
        R2O_FIREWALL_INIT=$TEMP/bin/firewall-init \
        RULE_FILE=$TEMP/ipv4.rules IPV4_RULES=$TEMP/ipv4.rules IPV6_RULES=$TEMP/ipv6.rules \
        FLOW_HW_SETTING_FILE=$TEMP/flow_offloading_hw \
        NO_IPTABLES_WAIT=1 \
        FAIL_RELOAD=${FAIL_RELOAD:-0} \
        RELOAD_TRACE=$TEMP/reloads IPTABLES_TRACE=$TEMP/iptables.trace IPTABLES_BIN=$TEMP/bin/iptables \
        R2O_PROC_DIR=$TEMP/proc R2O_SYS_MODULE_DIR=$TEMP/sys R2O_MODULES_DIR=$TEMP/modules \
        PATH="$TEMP/bin:$PATH" sh "$ROOT/router/r2o-firewall.sh" "$@"
}

# D2O's own guard returns before touching UCI or iptables on an iptables/fw3 backend.
cat > "$TEMP/run-d2o.sh" <<'D2O'
#!/bin/sh
set -eu
say() { :; }
. "$D2O_FLOWOFFLOAD_FUNCTIONS"
flowoffload_off
echo preserved
D2O
mkdir -p "$TEMP/empty-bin" "$TEMP/d2o-run"
d2o_trace=$(FW_BACKEND=iptables RUN="$TEMP/d2o-run" \
    D2O_FLOWOFFLOAD_FUNCTIONS="$TEMP/d2o-flowoffload.sh" \
    PATH="$TEMP/empty-bin" /bin/sh "$TEMP/run-d2o.sh")
[ "$d2o_trace" = preserved ] && [ ! -e "$TEMP/d2o-run/flow-offloading.saved" ] || {
    echo "D2O changed legacy fw3 flow-offload state unexpectedly" >&2
    exit 1
}

run_firewall flowoffload-ensure || { cat "$TEMP/iptables.trace" >&2; exit 1; }
[ ! -s "$TEMP/ipv4.rules" ] && [ ! -s "$TEMP/ipv6.rules" ] || {
    echo "legacy OpenWrt FLOWOFFLOAD targets remained active during R2O" >&2
    exit 1
}
[ "$(cat "$TEMP/run/flow-offloading.runtime")" = legacy ] || {
    echo "runtime legacy-offload state was not recorded" >&2
    exit 1
}
[ "$(cat "$TEMP/flow_offloading")" = 1 ] && [ "$(cat "$TEMP/flow_offloading_hw")" = 1 ] || {
    echo "native OpenWrt UCI software/hardware settings changed" >&2
    exit 1
}

# A fw3 reload recreates its configured hardware target; the firewall include
# calls ensure again before the reload completes.
printf '%s\n' "$fw3_hw_rule" > "$TEMP/ipv4.rules"
printf '%s\n' "$fw3_hw_rule" > "$TEMP/ipv6.rules"
run_firewall flowoffload-ensure
[ ! -s "$TEMP/ipv4.rules" ] && [ ! -s "$TEMP/ipv6.rules" ] || {
    echo "reapply did not remove native targets recreated by fw3" >&2
    exit 1
}
run_firewall flowoffload-restore
[ -s "$TEMP/ipv4.rules" ] && [ -s "$TEMP/ipv6.rules" ] || {
    echo "R2O stop did not restore fw3 software/hardware flow offload" >&2
    exit 1
}
[ ! -e "$TEMP/run/flow-offloading.runtime" ] || {
    echo "legacy offload state was not cleared after restoration" >&2
    exit 1
}
[ "$(cat "$TEMP/flow_offloading")" = 1 ] && [ "$(cat "$TEMP/flow_offloading_hw")" = 1 ] || {
    echo "restoring native targets changed the configured UCI values" >&2
    exit 1
}
[ "$(cat "$TEMP/reloads")" = reload ] || {
    echo "legacy stop did not request exactly one native firewall reload" >&2
    exit 1
}

# Software-only configuration must be restored without enabling hardware offload.
printf '0\n' > "$TEMP/flow_offloading_hw"
printf '%s\n' "$fw3_sw_rule" > "$TEMP/ipv4.rules"
printf '%s\n' "$fw3_sw_rule" > "$TEMP/ipv6.rules"
run_firewall flowoffload-ensure
[ ! -s "$TEMP/ipv4.rules" ] && [ ! -s "$TEMP/ipv6.rules" ] || {
    echo "software-only native targets remained active during R2O" >&2
    exit 1
}
if FAIL_RELOAD=1 run_firewall flowoffload-restore; then
    echo "failed legacy firewall reload was reported as a successful restore" >&2
    exit 1
fi
[ "$(cat "$TEMP/run/flow-offloading.runtime")" = legacy ] \
    && [ ! -s "$TEMP/ipv4.rules" ] && [ ! -s "$TEMP/ipv6.rules" ] || {
    echo "failed firewall reload lost retry state or restored only part of fw3" >&2
    exit 1
}
run_firewall flowoffload-restore
expected_rule=$fw3_sw_rule
[ "$(cat "$TEMP/ipv4.rules")" = "$expected_rule" ] && [ "$(cat "$TEMP/ipv6.rules")" = "$expected_rule" ] || {
    echo "software-only firewall configuration was not restored exactly" >&2
    exit 1
}
[ "$(cat "$TEMP/flow_offloading")" = 1 ] && [ "$(cat "$TEMP/flow_offloading_hw")" = 0 ] \
    && [ "$(cat "$TEMP/reloads" | wc -l | tr -d ' ')" = 3 ] || {
    echo "software-only restoration changed UCI or had the wrong reload count" >&2
    exit 1
}

# Unknown FLOWOFFLOAD rule shapes fail closed before any target or state is changed.
printf '%s\n' '-A FORWARD -p tcp -j FLOWOFFLOAD --hw' > "$TEMP/ipv4.rules"
if run_firewall flowoffload-ensure; then
    echo "unsupported legacy flow-offload shape was silently left active" >&2
    exit 1
fi
[ "$(cat "$TEMP/ipv4.rules")" = '-A FORWARD -p tcp -j FLOWOFFLOAD --hw' ] \
    && [ ! -e "$TEMP/run/flow-offloading.runtime" ] || {
    echo "unsupported legacy flow-offload state was partially modified" >&2
    exit 1
}

echo "D2O leaves fw3 flow offload untouched; R2O runtime fallback preserves SW/HW settings, restores on stop, and fails closed on unknown rules"
