#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    echo "unexpected D2O revision" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-flowoffload-d2o.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin"

sed -n '/^flowoffload_saved() {/,/^prepare_runtime() {/p' "$D2O_ROOT/files/S99d2k" |
    sed '$d' | tr -d '\r' > "$TEMP/d2o.sh"
sed -n '/^flowoffload_store_state() {/,/^ppe_call_unlocked() {/p' "$ROOT/router/r2o-firewall.sh" |
    sed '$d' | tr -d '\r' > "$TEMP/r2o.sh"
[ -s "$TEMP/d2o.sh" ] && [ -s "$TEMP/r2o.sh" ] || {
    echo "could not extract D2O/R2O flow-offload helpers" >&2
    exit 2
}

cat > "$TEMP/bin/uci" <<'UCI'
#!/bin/sh
[ "${1:-}" = -q ] && shift
case "${1:-}" in
    get)
        case "${2:-}" in
            firewall.@defaults\[0\].flow_offloading) cat "$FLOW_SETTING_FILE" ;;
            *) exit 2 ;;
        esac
        ;;
    set)
        case "${2:-}" in
            firewall.@defaults\[0\].flow_offloading=*)
                printf '%s\n' "${2#*=}" > "$FLOW_SETTING_FILE"
                printf 'uci set %s\n' "${2#*=}" >> "$FLOW_TRACE"
                ;;
            *) exit 2 ;;
        esac
        ;;
    commit)
        [ "${2:-}" = firewall ] || exit 2
        printf 'uci commit firewall\n' >> "$FLOW_TRACE"
        ;;
    *) exit 2 ;;
esac
UCI
cat > "$TEMP/bin/fw4" <<'FW4'
#!/bin/sh
printf 'fw4 %s\n' "$*" >> "$FLOW_TRACE"
FW4
chmod 0755 "$TEMP/bin/uci" "$TEMP/bin/fw4"

cat > "$TEMP/run-helper.sh" <<'RUN'
#!/bin/sh
set -eu
helper=$1
kind=$2
RUN=$3
FLOWOFFLOAD_STATE=$RUN/flow-offloading.saved
FLOWOFFLOAD_LEGACY_STATE=$RUN/flow-offloading.runtime
RUN_DIR=$RUN
FW4=fw4
FIREWALL_INIT=firewall-init
say() { :; }
. "$helper"
case "$kind" in
    d2o)
        FW_BACKEND=$HELPER_BACKEND flowoffload_off
        FW_BACKEND=$HELPER_BACKEND flowoffload_restore
        ;;
    r2o)
        BACKEND=$HELPER_BACKEND flowoffload_ensure_unlocked
        BACKEND=$HELPER_BACKEND flowoffload_restore_unlocked
        ;;
    *) exit 2 ;;
esac
printf 'flow=%s hw=%s saved=%s\n' "$(cat "$FLOW_SETTING_FILE")" "$(cat "$FLOW_HW_SETTING_FILE")" \
    "$(if [ -f "$FLOWOFFLOAD_STATE" ]; then cat "$FLOWOFFLOAD_STATE"; else echo absent; fi)"
cat "$FLOW_TRACE"
RUN
chmod 0755 "$TEMP/run-helper.sh"

for scenario in nft-on nft-off iptables-on; do
    case "$scenario" in
        nft-on) backend=nft; flow=1 ;;
        nft-off) backend=nft; flow=0 ;;
        iptables-on) backend=iptables; flow=1 ;;
    esac
    [ -z "${R2O_FLOWOFFLOAD_BACKEND_ONLY:-}" ] || [ "$backend" = "$R2O_FLOWOFFLOAD_BACKEND_ONLY" ] || continue
    for kind in d2o r2o; do
        run="$TEMP/$scenario/$kind"
        mkdir -p "$run"
        printf '%s\n' "$flow" > "$run/flow"
        printf '1\n' > "$run/hw"
        : > "$run/trace"
        RUN="$run" FLOW_SETTING_FILE="$run/flow" FLOW_HW_SETTING_FILE="$run/hw" \
            FLOW_TRACE="$run/trace" HELPER_BACKEND="$backend" PATH="$TEMP/bin:$PATH" \
            sh "$TEMP/run-helper.sh" "$TEMP/$kind.sh" "$kind" "$run" > "$run/output"
    done

    if ! cmp -s "$TEMP/$scenario/d2o/output" "$TEMP/$scenario/r2o/output"; then
        echo "R2O $scenario flow-offload lifecycle differs from D2O" >&2
        diff -u "$TEMP/$scenario/d2o/output" "$TEMP/$scenario/r2o/output" >&2 || true
        exit 1
    fi
done

if grep -Eq 'ct mark|mark_flow|flow offload @' "$ROOT/router/r2o-firewall.sh"; then
    echo "R2O still selectively edits the native flowtable or conntrack marks" >&2
    exit 1
fi

echo "D2O/R2O global flow-offload lifecycle matches; HW setting and fw3/iptable backend stay untouched."
