#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
HELPER=$ROOT/router/r2o-ppe-deoffload.sh
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

fail() {
    echo "test-r2o-ppe-deoffload: $*" >&2
    exit 1
}

[ -x "$HELPER" ] || fail "PPE adapter is missing or not executable"

make_case() {
    CASE=$TEMP/$1
    mkdir -p "$CASE/bin" "$CASE/proc/net"
    : > "$CASE/rules"
    : > "$CASE/rules6"
    printf 'PPE\n' > "$CASE/proc/net/ip_tables_targets"
    cat > "$CASE/bin/iptables" <<'MOCK'
#!/bin/sh
set -eu
[ "${1:-}" = -w ] && shift
if [ "${1:-}" = -t ]; then
    [ "${2:-}" = mangle ] || exit 2
    shift 2
fi
operation=${1:-}
shift || true
chain=${1:-}
shift || true
args=$*
rule="$chain|$args"
if [ "${0##*/}" = ip6tables ]; then
    rules=${MOCK_RULES6:-$MOCK_RULES}
else
    rules=$MOCK_RULES
fi
case "$operation" in
    -S)
        awk -F'|' -v chain="$chain" '$1 == chain { printf "-A %s %s\n", $1, $2 }' "$rules"
        ;;
    -C)
        grep -Fqx -- "$rule" "$rules"
        ;;
    -I)
        case " $args " in
            *" --dports 80 "*) [ "${MOCK_FAIL_HTTP:-0}" = 1 ] && exit 1 ;;
        esac
        printf '%s\n' "$rule" >> "$rules"
        ;;
    -D)
        awk -v rule="$rule" '$0 != rule' "$rules" > "$rules.new"
        mv "$rules.new" "$rules"
        ;;
    *) exit 2 ;;
esac
MOCK
    chmod +x "$CASE/bin/iptables"
    printf 'FORWARD|-p tcp -m comment --comment other-owner -j PPE\n' > "$CASE/rules"
}

run_helper() {
    PATH="$CASE/bin:/usr/bin:/bin" \
        MOCK_RULES="$CASE/rules" \
        MOCK_RULES6="$CASE/rules6" \
        R2O_PPE_PROC="$CASE/proc/net" \
        R2O_PPE_CONFIG="$CASE/config" \
        R2O_PPE_BINDS="$CASE/binds" \
        R2O_PPE_DEOFFLOAD="${TEST_PPE_ENABLED:-1}" \
        MOCK_FAIL_HTTP="${MOCK_FAIL_HTTP:-0}" \
        "$HELPER" "$@"
}

make_case idempotent
run_helper ensure
run_helper ensure
[ "$(grep -c 'r2o-ppe' "$CASE/rules")" -eq 8 ] || fail "ensure did not install exactly eight IPv4 rules once"
run_helper status | grep -q 'PPE: включена' || fail "status did not report the installed rules"
run_helper remove
[ "$(grep -c 'r2o-ppe' "$CASE/rules" || true)" -eq 0 ] || fail "remove left R2O rules behind"
grep -q 'other-owner' "$CASE/rules" || fail "remove deleted another owner's PPE rule"

make_case disabled
run_helper ensure
if TEST_PPE_ENABLED=0 run_helper ensure; then fail "disabled PPE setting was accepted as installed"; else rc=$?; fi
[ "$rc" -eq 3 ] || fail "disabled PPE setting returned $rc instead of 3"
[ "$(grep -c 'r2o-ppe' "$CASE/rules" || true)" -eq 0 ] || fail "disabled PPE setting left owned rules"

make_case configured_disabled
printf 'R2O_PPE_DEOFFLOAD="0"\n' > "$CASE/config"
if PATH="$CASE/bin:/usr/bin:/bin" MOCK_RULES="$CASE/rules" MOCK_RULES6="$CASE/rules6" \
    R2O_PPE_PROC="$CASE/proc/net" R2O_PPE_CONFIG="$CASE/config" \
    R2O_PPE_BINDS="$CASE/binds" R2O_PPE_DEOFFLOAD='' "$HELPER" ensure; then
    fail "config file PPE disable was accepted as installed"
else
    rc=$?
fi
[ "$rc" -eq 3 ] || fail "config file PPE disable returned $rc instead of 3"

make_case invalid_ports
if R2O_PPE_TCP_PORTS="80;touch $CASE/injected" run_helper ensure 2>"$CASE/invalid.log"; then
    fail "unsafe PPE port list was accepted"
else
    rc=$?
fi
[ "$rc" -eq 1 ] || fail "invalid PPE port list returned $rc instead of 1"
[ ! -e "$CASE/injected" ] || fail "unsafe PPE port list executed shell text"
grep -q 'неверная конфигурация' "$CASE/invalid.log" || fail "invalid PPE setting had no diagnostic"

make_case unavailable
: > "$CASE/proc/net/ip_tables_targets"
if run_helper ensure; then fail "ensure succeeded without a PPE target"; else rc=$?; fi
[ "$rc" -eq 2 ] || fail "missing PPE target returned $rc instead of 2"
[ "$(grep -c 'r2o-ppe' "$CASE/rules" || true)" -eq 0 ] || fail "missing PPE target installed rules"

make_case ipv6
cp "$CASE/bin/iptables" "$CASE/bin/ip6tables"
printf 'PPE\n' > "$CASE/proc/net/ip6_tables_targets"
run_helper ensure
[ "$(grep -c 'r2o-ppe' "$CASE/rules")" -eq 8 ] || fail "IPv4 rule set was incomplete"
[ "$(grep -c 'r2o-ppe' "$CASE/rules6")" -eq 8 ] || fail "IPv6 rule set was incomplete"

make_case partial
MOCK_FAIL_HTTP=1
if run_helper ensure; then fail "ensure ignored an injected insertion failure"; else rc=$?; fi
[ "$rc" -eq 1 ] || fail "partial insertion returned $rc instead of 1"
run_helper remove
[ "$(grep -c 'r2o-ppe' "$CASE/rules" || true)" -eq 0 ] || fail "partial installation could not be removed"
grep -q 'other-owner' "$CASE/rules" || fail "partial cleanup removed another owner's rule"

echo "test-r2o-ppe-deoffload: owner isolation, idempotence, disable, capability, and partial failure passed"
