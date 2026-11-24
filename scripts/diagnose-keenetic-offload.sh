#!/bin/sh
# Read-only F3/F4 snapshot. Run locally as root on the router.
set -eu
export PATH="/opt/sbin:/opt/bin:$PATH"

case "${1:-}" in
    KN-1910 | KN-3810) model=$1 ;;
    *) echo "Usage: $0 KN-1910|KN-3810 PHASE [WAN_IF LAN_IF]" >&2; exit 2 ;;
esac
phase=${2:?specify the measurement phase}
shift 2
proc=${R2O_PROC_DIR:-/proc}
root=${R2O_DIR:-/opt/r2o}
run=${R2O_RUN_DIR:-$root/run}
datapath=${R2O_DATAPATH_BIN:-}
manager=${R2O_MANAGER:-$root/r2o-manager}
ppe_target=${R2O_PPE_TARGET:-PPE}
export R2O_DIR="$root" R2O_RUN_DIR="$run"

printf 'model=%s phase=%s utc=%s\n' "$model" "$phase" "$(date -u +%FT%TZ)"
uname -a
awk '/^(MemTotal|MemAvailable):/ {print}' "$proc/meminfo"
if command -v ndmc >/dev/null 2>&1; then
    ndmc -c 'show version' || echo 'ndm_version=unavailable'
else
    echo 'ndm_version=unavailable'
fi

for name in nf_conntrack_fastnat nf_conntrack_acct; do
    file="$proc/sys/net/netfilter/$name"
    val=$(cat "$file" 2>/dev/null) || val=unavailable
    printf '%s=%s\n' "$name" "$val"
done
if [ -r "$run/fastnat.saved" ]; then
    printf 'fastnat_journal=%s\n' "$(cat "$run/fastnat.saved")"
else
    echo 'fastnat_journal=absent'
fi

platform() {
    if [ -n "$datapath" ]; then
        R2O_PLATFORM=keenetic FW_BACKEND=iptables "$datapath" --platform "$@"
    else
        R2O_PLATFORM=keenetic FW_BACKEND=iptables "$manager" exec --root "$root" --component r2o-datapath -- --platform "$@"
    fi
}
if [ -x "${datapath:-$manager}" ]; then
    platform status || echo 'platform_status=failed'
    platform ppe status || echo 'ppe_status=failed'
else
    echo 'platform_status=unavailable'
fi

for tables in iptables ip6tables; do
    if command -v "$tables-save" >/dev/null 2>&1 &&
        snapshot=$("$tables-save" -c -t mangle 2>/dev/null); then
        printf '%s mangle packet/byte counters\n' "$tables"
        printf '%s\n' "$snapshot" | awk -v target="$ppe_target" '
            /R2O|r2o-/ || index($0, "-j " target) || index($0, "-j NFQUEUE")'
    else
        printf '%s_mangle=unavailable\n' "$tables"
    fi
done
echo 'NFQUEUE queue peer pending copy-mode range kernel-drop user-drop sequence'
cat "$proc/net/netfilter/nfnetlink_queue" 2>/dev/null || echo 'nfqueue=unavailable'
for device do
    ip -s link show dev "$device" || printf 'interface=%s unavailable\n' "$device"
done
echo 'lan_coverage=requires_correlated_client_origin_capture'
