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

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-ppe-legacy.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

_ipt() {
    _family=$1
    shift
    [ "${1:-}" != -w ] || shift
    [ "${1:-}" = -t ] && [ "${2:-}" = mangle ] || return 2
    shift 2
    _operation=${1:-}
    shift || true
    _chain=${1:-}
    shift || true
    _rule="$_chain|$*"
    _rules=$MOCK_RULES/$_family
    case "$_operation" in
        -S)
            awk -F'|' -v chain="$_chain" '$1 == chain { printf "-A %s %s\n", $1, $2 }' "$_rules"
            ;;
        -D)
            awk -v rule="$_rule" 'BEGIN { removed=0 } !removed && $0 == rule { removed=1; next } { print } END { if (!removed) exit 1 }' \
                "$_rules" >"$_rules.new" || { rm -f "$_rules.new"; return 1; }
            mv "$_rules.new" "$_rules"
            ;;
        *) return 2 ;;
    esac
}

iptables() { _ipt v4 "$@"; }
ip6tables() { _ipt v6 "$@"; }

seed_rules() {
    mkdir -p "$MOCK_RULES"
    for _family in v4 v6; do
        cat >"$MOCK_RULES/$_family" <<'RULES'
PREROUTING|-p tcp --dport 443 -m comment --comment d2k-ppe -j PPE
FORWARD|-p udp --dport 3478 -m comment --comment d2k-ppe -j PPE
FORWARD|-p tcp --dport 80 -m comment --comment other-owner -j PPE
RULES
    done
}

summary() {
    for _family in v4 v6; do
        _rules=$MOCK_RULES/$_family
        printf '%s legacy=%s current=%s foreign=%s\n' "$_family" \
            "$(grep -c -- '--comment d2k-ppe ' "$_rules" || true)" \
            "$(grep -c -- '--comment r2o-ppe ' "$_rules" || true)" \
            "$(grep -c -- '--comment other-owner ' "$_rules" || true)"
    done
}

D2O_PPE_LIB=$D2O_ROOT/files/d2k-ppe-deoffload.sh
R2O_PPE_LIB=$ROOT/router/r2o-ppe-deoffload.sh
[ -r "$D2O_PPE_LIB" ] && [ -r "$R2O_PPE_LIB" ] || {
    echo "PPE helper is missing" >&2
    exit 2
}

MOCK_RULES=$TEMP/d2o
export MOCK_RULES
seed_rules
set --
sed 's/\r$//' "$D2O_PPE_LIB" >"$TEMP/d2o-ppe-deoffload.sh"
. "$TEMP/d2o-ppe-deoffload.sh"
d2k_ppe_remove
summary >"$TEMP/d2o.out"

MOCK_RULES=$TEMP/r2o
export MOCK_RULES
seed_rules
set -- remove
. "$R2O_PPE_LIB"
summary >"$TEMP/r2o.out"

cat "$TEMP/d2o.out" "$TEMP/r2o.out"
cmp "$TEMP/d2o.out" "$TEMP/r2o.out"
printf 'D2O %s and R2O agree on IPv4/IPv6 legacy PPE cleanup and foreign-rule preservation.\n' \
    "$ACTUAL_D2O_SHA"
