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

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-firewall-nft-failure.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin" "$TEMP/d2k/run" "$TEMP/r2o/run" "$TEMP/proc/net" "$TEMP/sys" "$TEMP/modules"
printf 'FW_BACKEND=nft\n' >"$TEMP/d2k/config"
printf 'FW_BACKEND=nft\nIPV6_ENABLED=0\n' >"$TEMP/r2o/config"

cat >"$TEMP/bin/nft" <<'NFT'
#!/bin/sh
printf '%s\n' "$*" >>"$NFT_TRACE"
if [ "${1:-}" = list ]; then
    case "$*" in
        'list table inet r2o'|'list table inet r2o_rst')
            echo 'table inet r2o { comment "r2o-managed"; }'
            exit 0
            ;;
        'list table inet d2k'|'list table inet d2k_rst'|\
        'list set inet r2o_rst rst4'|'list set inet r2o_rst rst6'|\
        'list chain inet r2o_rst output') exit 0 ;;
        *) exit 1 ;;
    esac
fi
if [ "${1:-}" = -f ]; then
    exit 1
fi
exit 0
NFT
for tool in modprobe insmod; do
    printf '#!/bin/sh\nexit 1\n' >"$TEMP/bin/$tool"
done
printf '#!/bin/sh\nexit 0\n' >"$TEMP/bin/lsmod"
chmod 0755 "$TEMP/bin/nft" "$TEMP/bin/modprobe" "$TEMP/bin/insmod" "$TEMP/bin/lsmod"

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
NFT_TRACE=$4
export PATH NFT_TRACE
say() { :; }
if fw_up; then echo UP:success; else echo UP:failed; fi
if grep -Fx 'delete table inet d2k' "$NFT_TRACE" >/dev/null; then
    echo MAIN_TABLE:removed
else
    echo 'D2O did not remove its table after nft failure' >&2
    exit 1
fi
D2O
chmod 0755 "$TEMP/run-d2o.sh"
NFT_TRACE=$TEMP/d2o.trace "$TEMP/run-d2o.sh" "$TEMP/d2k" "$TEMP/d2k-functions.sh" "$TEMP/bin" "$TEMP/d2o.trace" >"$TEMP/d2o.out"

if R2O_DIR="$TEMP/r2o" R2O_CONFIG="$TEMP/r2o/config" \
    R2O_RUN_DIR="$TEMP/r2o/run" R2O_PROC_DIR="$TEMP/proc" \
    R2O_SYS_MODULE_DIR="$TEMP/sys" R2O_MODULES_DIR="$TEMP/modules" \
    NFT_TRACE="$TEMP/r2o.trace" PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/r2o-firewall.sh" up >"$TEMP/r2o.log" 2>&1; then
    echo UP:success >"$TEMP/r2o.out"
else
    echo UP:failed >"$TEMP/r2o.out"
fi

if grep -Fx 'delete table inet r2o' "$TEMP/r2o.trace" >/dev/null; then
    echo MAIN_TABLE:removed
else
    echo MAIN_TABLE:preserved
fi >>"$TEMP/r2o.out"
cat "$TEMP/d2o.out" "$TEMP/r2o.out"
cmp "$TEMP/d2o.out" "$TEMP/r2o.out"
printf 'D2O %s and R2O both clean up the main nft table after a failed up transaction.\n' \
    "$ACTUAL_D2O_SHA"
