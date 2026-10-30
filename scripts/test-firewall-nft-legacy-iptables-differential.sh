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
if [ "${1:-}" != -t ]; then exit 1; fi
table=$2
state=$IPTABLES_STATE/$tool
case "$3" in
    -D)
        key=
        if [ "$table" = nat ] && [ "$4" = PREROUTING ] && [ "$5" = -j ] && [ "$6" = D2K_HTTP ]; then
            key=nat.D2K_HTTP.hook
        elif [ "$table" = nat ] && [ "$4" = POSTROUTING ] && [ "$5" = -p ] && [ "$6" = udp ] \
            && [ "$7" = -m ] && [ "$8" = mark ] && [ "$9" = --mark ] \
            && { [ "${10}" = 0x2d ] || [ "${10}" = 45 ]; } && [ "${11}" = -j ] && [ "${12}" = MASQUERADE ]; then
            key=nat.MASQUERADE
        elif [ "$table" = mangle ] && [ "$4" = OUTPUT ] && [ "$5" = -m ] && [ "$6" = mark ] \
            && [ "$7" = --mark ] && [ "$8" = 0x30 ] && [ "$9" = -j ] \
            && [ "${10}" = CONNMARK ] && [ "${11}" = --save-mark ]; then
            key=mangle.HTTPUP_MARK
        elif [ "$table" = mangle ] && [ "$4" = OUTPUT ] && [ "$5" = -j ] && [ "$6" = D2K_HTTP_MARK ]; then
            key=mangle.D2K_HTTP_MARK.OUTPUT
        elif [ "$table" = mangle ] && [ "$5" = -j ] && { [ "$6" = D2K_OUT ] || [ "$6" = D2K_IN ]; }; then
            key=mangle.$4.$6.hook
        fi
        if [ -n "$key" ] && [ -f "$state/$key" ]; then rm -f "$state/$key"; exit 0; fi
        ;;
    -n)
        if [ "$4" = -L ] && [ -f "$state/$table.$5.chain" ]; then exit 0; fi
        ;;
    -F)
        if [ -f "$state/$table.$4.chain" ]; then exit 0; fi
        ;;
    -X)
        if [ -f "$state/$table.$4.chain" ]; then rm -f "$state/$table.$4.chain"; exit 0; fi
        ;;
esac
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
echo "LEGACY_IPV4_RULES:$(find "$IPTABLES_STATE/iptables" -type f | wc -l | tr -d ' ')"
echo "LEGACY_IPV6_RULES:$(find "$IPTABLES_STATE/ip6tables" -type f | wc -l | tr -d ' ')"
D2O
chmod 0755 "$TEMP/run-d2o.sh"

run_side() {
    side=$1
    action=$2
    base=$TEMP/$side-$action
    mkdir -p "$base/bin" "$base/run" "$base/proc/net" "$base/sys" "$base/modules" \
        "$base/iptables-state/iptables" "$base/iptables-state/ip6tables"
    for tool in iptables ip6tables; do
        family=$base/iptables-state/$tool
        : >"$family/nat.D2K_HTTP.hook"
        : >"$family/nat.D2K_HTTP.chain"
        : >"$family/mangle.HTTPUP_MARK"
        : >"$family/mangle.D2K_HTTP_MARK.OUTPUT"
        : >"$family/mangle.D2K_HTTP_MARK.chain"
        : >"$family/mangle.D2K_OUT.chain"
        : >"$family/mangle.D2K_IN.chain"
        for hook in POSTROUTING FORWARD OUTPUT INPUT; do
            for chain in D2K_OUT D2K_IN; do : >"$family/mangle.$hook.$chain.hook"; done
        done
    done
    : >"$base/iptables-state/iptables/nat.MASQUERADE"
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
        echo "LEGACY_IPV4_RULES:$(find "$base/iptables-state/iptables" -type f | wc -l | tr -d ' ')" >>"$base/out"
        echo "LEGACY_IPV6_RULES:$(find "$base/iptables-state/ip6tables" -type f | wc -l | tr -d ' ')" >>"$base/out"
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
