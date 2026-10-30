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
mkdir -p "$TEMP/bin"
cat >"$TEMP/bin/nft" <<'NFT'
#!/bin/sh
printf '%s\n' "$*" >>"$NFT_TRACE"
if [ "${1:-}" = list ]; then
    case "$*" in
        'list table inet r2o') table=r2o ;;
        'list table inet r2o_rst') table=r2o_rst ;;
        'list table inet d2k') table=d2k ;;
        'list table inet d2k_rst') table=d2k_rst ;;
        'list set inet r2o_rst rst4'|'list set inet r2o_rst rst6'|\
        'list chain inet r2o_rst output') table=r2o_rst ;;
        *) exit 1 ;;
    esac
    if [ -f "$NFT_STATE_DIR/$table" ]; then
        echo "table inet $table { comment \"r2o-managed\"; }"
        exit 0
    fi
    exit 1
fi
if [ "${1:-}" = -f ]; then
    rules=$2
    case "$rules" in *firewall-rst.nft.*)
        if grep -q 'r2o_rst' "$rules"; then : >"$NFT_STATE_DIR/r2o_rst"; fi
        exit 0
        ;;
    esac
    exit 1
fi
if [ "${1:-}" = delete ] && [ "${2:-}" = table ]; then
    rm -f "$NFT_STATE_DIR/$4"
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
D2O
chmod 0755 "$TEMP/run-d2o.sh"
run_case() {
    name=$1
    initial=$2
    case_dir=$TEMP/$name
    mkdir -p "$case_dir/bin" "$case_dir/d2k/run" "$case_dir/r2o/run" \
        "$case_dir/proc/net" "$case_dir/sys" "$case_dir/modules" \
        "$case_dir/d2o-state" "$case_dir/r2o-state"
    printf 'FW_BACKEND=nft\n' >"$case_dir/d2k/config"
    printf 'FW_BACKEND=nft\nIPV6_ENABLED=0\n' >"$case_dir/r2o/config"
    if [ "$initial" = existing ]; then
        : >"$case_dir/d2o-state/d2k"
        : >"$case_dir/d2o-state/d2k_rst"
        : >"$case_dir/r2o-state/r2o"
        : >"$case_dir/r2o-state/r2o_rst"
    fi

    if NFT_STATE_DIR="$case_dir/d2o-state" NFT_TRACE="$case_dir/d2o.trace" \
        "$TEMP/run-d2o.sh" "$case_dir/d2k" "$TEMP/d2k-functions.sh" \
        "$TEMP/bin" "$case_dir/d2o.trace" >"$case_dir/d2o.out"; then
        :
    else
        echo "D2O driver failed for $name" >&2
        exit 1
    fi
    if R2O_DIR="$case_dir/r2o" R2O_CONFIG="$case_dir/r2o/config" \
        R2O_RUN_DIR="$case_dir/r2o/run" R2O_PROC_DIR="$case_dir/proc" \
        R2O_SYS_MODULE_DIR="$case_dir/sys" R2O_MODULES_DIR="$case_dir/modules" \
        NFT_STATE_DIR="$case_dir/r2o-state" NFT_TRACE="$case_dir/r2o.trace" \
        PATH="$TEMP/bin:$PATH" sh "$ROOT/router/r2o-firewall.sh" up \
        >"$case_dir/r2o.log" 2>&1; then
        echo UP:success >"$case_dir/r2o.out"
    else
        echo UP:failed >"$case_dir/r2o.out"
    fi

    for side in d2o r2o; do
        if [ "$side" = d2o ]; then state=$case_dir/d2o-state; else state=$case_dir/r2o-state; fi
        if [ "$side" = d2o ]; then main=$state/d2k; rst=$state/d2k_rst
        else main=$state/r2o; rst=$state/r2o_rst; fi
        if [ -f "$main" ]; then echo MAIN_TABLE:present; else echo MAIN_TABLE:absent; fi >>"$case_dir/$side.out"
        if [ -f "$rst" ]; then echo RST_TABLE:present; else echo RST_TABLE:absent; fi >>"$case_dir/$side.out"
    done
    cmp "$case_dir/d2o.out" "$case_dir/r2o.out" || {
        printf '%s\n' "D2O ($name):"; cat "$case_dir/d2o.out"
        printf '%s\n' "R2O ($name):"; cat "$case_dir/r2o.out"
        return 1
    }
    cat "$case_dir/r2o.out"
}

run_case existing existing
run_case initial initial
printf 'D2O %s and R2O agree on nft rollback with pre-existing and newly-created tables.\n' \
    "$ACTUAL_D2O_SHA"
