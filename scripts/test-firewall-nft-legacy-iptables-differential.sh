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

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-firewall-nft-legacy.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin"

cat >"$TEMP/bin/iptables" <<'IPTABLES'
#!/bin/sh
tool=${0##*/}
printf '%s %s\n' "$tool" "$*" >>"$IPTABLES_TRACE"
if [ "${1:-}" = -w ]; then shift; fi
chain=${5:-}
hook=${4:-}
state=$IPTABLES_STATE/$tool.D2K_OUT
if [ "${1:-}" = -t ] && [ "${2:-}" = mangle ]; then
    case "${3:-}" in
        -D)
            if [ "$hook" = POSTROUTING ] && [ "${5:-}" = -j ] && [ "${6:-}" = D2K_OUT ] && [ -f "$state.hook" ]; then
                rm -f "$state.hook"
                exit 0
            fi
            ;;
        -n)
            if [ "${4:-}" = -L ] && [ "${5:-}" = D2K_OUT ] && [ -f "$state.chain" ]; then exit 0; fi
            ;;
        -F) exit 0 ;;
        -X)
            if [ "${4:-}" = D2K_OUT ]; then rm -f "$state.chain"; exit 0; fi
            ;;
    esac
fi
exit 1
IPTABLES
cp "$TEMP/bin/iptables" "$TEMP/bin/ip6tables"
cat >"$TEMP/bin/nft" <<'NFT'
#!/bin/sh
if [ "${1:-}" = list ]; then exit 1; fi
if [ "${1:-}" = -f ]; then exit 0; fi
exit 0
NFT
for tool in modprobe insmod; do printf '#!/bin/sh\nexit 1\n' >"$TEMP/bin/$tool"; done
printf '#!/bin/sh\nexit 0\n' >"$TEMP/bin/lsmod"
chmod 0755 "$TEMP/bin/iptables" "$TEMP/bin/ip6tables" "$TEMP/bin/nft" \
    "$TEMP/bin/modprobe" "$TEMP/bin/insmod" "$TEMP/bin/lsmod"

tr -d '\r' <"$D2O_ROOT/files/S99d2k" |
    awk '$0 == "case \"$1\" in" { exit } { print }' >"$TEMP/d2k-functions.sh"
cat >"$TEMP/run-d2o.sh" <<'D2O'
#!/bin/sh
set -eu
D2K_DIR=$1
FW_LOCK=$D2K_DIR/run/firewall-operation.lock
export D2K_DIR FW_LOCK
. "$2"
PATH=$3:$PATH
IPTABLES_STATE=$4
IPTABLES_TRACE=$5
export PATH IPTABLES_STATE IPTABLES_TRACE
say() { :; }
if [ "$6" = down ]; then
    if fw_down; then echo DOWN:success; else echo DOWN:failed; fi
else
    if fw_up; then echo UP:success; else echo UP:failed; fi
fi
if [ -f "$IPTABLES_STATE/iptables.D2K_OUT.hook" ] || [ -f "$IPTABLES_STATE/iptables.D2K_OUT.chain" ]; then
    echo LEGACY_IPV4:present
else
    echo LEGACY_IPV4:absent
fi
if [ -f "$IPTABLES_STATE/ip6tables.D2K_OUT.hook" ] || [ -f "$IPTABLES_STATE/ip6tables.D2K_OUT.chain" ]; then
    echo LEGACY_IPV6:present
else
    echo LEGACY_IPV6:absent
fi
D2O
chmod 0755 "$TEMP/run-d2o.sh"

run_side() {
    side=$1
    action=$2
    base=$TEMP/$side-$action
    mkdir -p "$base/bin" "$base/run" "$base/proc/net" "$base/sys" "$base/modules" "$base/iptables-state"
    : >"$base/iptables-state/iptables.D2K_OUT.hook"
    : >"$base/iptables-state/iptables.D2K_OUT.chain"
    : >"$base/iptables-state/ip6tables.D2K_OUT.hook"
    : >"$base/iptables-state/ip6tables.D2K_OUT.chain"
    if [ "$side" = d2o ]; then
        printf 'FW_BACKEND=nft\n' >"$base/config"
        if IPTABLES_STATE="$base/iptables-state" IPTABLES_TRACE="$base/iptables.trace" \
            "$TEMP/run-d2o.sh" "$base" "$TEMP/d2k-functions.sh" "$TEMP/bin" \
            "$base/iptables-state" "$base/iptables.trace" "$action" >"$base/out"; then :; else return 1; fi
    else
        printf 'FW_BACKEND=nft\nIPV6_ENABLED=0\n' >"$base/config"
        if R2O_DIR="$base" R2O_CONFIG="$base/config" R2O_RUN_DIR="$base/run" \
            R2O_PROC_DIR="$base/proc" R2O_SYS_MODULE_DIR="$base/sys" \
            R2O_MODULES_DIR="$base/modules" IPTABLES_STATE="$base/iptables-state" \
            IPTABLES_TRACE="$base/iptables.trace" PATH="$TEMP/bin:$PATH" \
            sh "$ROOT/router/r2o-firewall.sh" "$action" >"$base.log" 2>&1; then
            if [ "$action" = down ]; then echo DOWN:success >"$base/out"; else echo UP:success >"$base/out"; fi
        else
            if [ "$action" = down ]; then echo DOWN:failed >"$base/out"; else echo UP:failed >"$base/out"; fi
        fi
        if [ -f "$base/iptables-state/iptables.D2K_OUT.hook" ] || [ -f "$base/iptables-state/iptables.D2K_OUT.chain" ]; then
            echo LEGACY_IPV4:present >>"$base/out"
        else echo LEGACY_IPV4:absent >>"$base/out"; fi
        if [ -f "$base/iptables-state/ip6tables.D2K_OUT.hook" ] || [ -f "$base/iptables-state/ip6tables.D2K_OUT.chain" ]; then
            echo LEGACY_IPV6:present >>"$base/out"
        else echo LEGACY_IPV6:absent >>"$base/out"; fi
    fi
}

for action in up down; do
    run_side d2o "$action"
    run_side r2o "$action"
    cat "$TEMP/d2o-$action/out" "$TEMP/r2o-$action/out"
    cmp "$TEMP/d2o-$action/out" "$TEMP/r2o-$action/out"
done
printf 'D2O %s and R2O agree on nft-backend cleanup of legacy iptables chains.\n' \
    "$ACTUAL_D2O_SHA"
