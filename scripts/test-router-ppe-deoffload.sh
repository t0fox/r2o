#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
HELPER=$ROOT/router/r2o-ppe-deoffload.sh
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

fail() {
    echo "test-router-ppe-deoffload: $*" >&2
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
        [ "${MOCK_FAIL_LIST:-0}" = 1 ] && exit 1
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
        case " $args " in
            *" -m comment --comment r2o-ppe "*)
                case " $args " in
                    *" -p tcp "*) [ "${MOCK_FAIL_DELETE_TCP:-0}" = 1 ] && exit 1 ;;
                esac
                ;;
        esac
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
        MOCK_FAIL_DELETE_TCP="${MOCK_FAIL_DELETE_TCP:-0}" \
        MOCK_FAIL_LIST="${MOCK_FAIL_LIST:-0}" \
        "$HELPER" "$@"
}

make_case idempotent
run_helper ensure
run_helper ensure
[ "$(grep -c 'r2o-ppe' "$CASE/rules")" -eq 8 ] || fail "ensure did not install exactly eight IPv4 rules once"
run_helper status | grep -q 'PPE: включена' || fail "status did not report the installed rules"
cat > "$CASE/binds" <<'BINDS'
PPE0:
IPv4_NAPT=802: 87.228.47.201:443 -> 192.0.2.7:443
IPv4_NAPT=803: 187.228.47.201:443 -> 192.0.2.8:443
BINDS
printf 'r2o-datapath: ответ невидим очереди: 6 из 20 TCP-потоков с приветствием\n' > "$CASE/datapath.log"
R2O_PPE_DPLOG="$CASE/datapath.log" run_helper status 87.228.47.201 \
    | grep -q '87.228.47.201: в ускорителе' || fail "status did not match an exact accelerated IPv4 address"
TARGET_STATUS=$(R2O_PPE_DPLOG="$CASE/datapath.log" run_helper status 7.228.47.201)
printf '%s\n' "$TARGET_STATUS" | grep -q '7.228.47.201: в PPE binds не найден' || {
    printf '%s\n' "$TARGET_STATUS" >&2
    fail "status matched a substring of another accelerated address"
}
R2O_PPE_DPLOG="$CASE/datapath.log" run_helper status 87.228.47.201 \
    | grep -q 'ответ невидим очереди: 6 из 20 (30%)' || fail "status omitted the datapath visibility counter"
if run_helper status '87.228.47.201|.*'; then
    fail "status accepted a non-IPv4 address"
else
    rc=$?
fi
[ "$rc" -eq 2 ] || fail "invalid status address returned $rc instead of 2"
run_helper remove
[ "$(grep -c 'r2o-ppe' "$CASE/rules" || true)" -eq 0 ] || fail "remove left R2O rules behind"
grep -q 'other-owner' "$CASE/rules" || fail "remove deleted another owner's PPE rule"

make_case legacy_cleanup
printf 'PREROUTING|-p tcp -m comment --comment d2k-ppe -j PPE\nFORWARD|-p udp --dport 443 -m comment --comment d2k-ppe -j PPE\n' >> "$CASE/rules"
run_helper ensure
[ "$(grep -c 'd2k-ppe' "$CASE/rules" || true)" -eq 0 ] || fail "ensure left legacy D2O PPE rules behind"
[ "$(grep -c 'r2o-ppe' "$CASE/rules")" -eq 8 ] || fail "ensure did not replace legacy D2O rules with R2O rules"
run_helper remove
[ "$(grep -c 'd2k-ppe\|r2o-ppe' "$CASE/rules" || true)" -eq 0 ] || fail "remove left legacy or current PPE rules behind"
grep -q 'other-owner' "$CASE/rules" || fail "legacy cleanup removed another owner's PPE rule"

make_case disabled
run_helper ensure
if TEST_PPE_ENABLED=0 run_helper ensure; then fail "disabled PPE setting was accepted as installed"; else rc=$?; fi
[ "$rc" -eq 3 ] || fail "disabled PPE setting returned $rc instead of 3"
[ "$(grep -c 'r2o-ppe' "$CASE/rules" || true)" -eq 0 ] || fail "disabled PPE setting left owned rules"

make_case disabled_cleanup_failure
run_helper ensure
if TEST_PPE_ENABLED=0 MOCK_FAIL_DELETE_TCP=1 run_helper ensure; then
    fail "disabled setting hid a failed owned-rule cleanup"
else
    rc=$?
fi
[ "$rc" -eq 1 ] || fail "disabled cleanup failure returned $rc instead of 1"

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
MOCK_FAIL_HTTP=0

make_case cleanup_failure
run_helper ensure
if MOCK_FAIL_DELETE_TCP=1 run_helper remove; then
    fail "remove hid a failed owned-rule deletion"
else
    rc=$?
fi
[ "$rc" -eq 1 ] || fail "failed cleanup returned $rc instead of 1"
[ "$(grep -c 'r2o-ppe' "$CASE/rules" || true)" -eq 5 ] || fail "cleanup stopped early or lost failed rules"
run_helper remove
[ "$(grep -c 'r2o-ppe' "$CASE/rules" || true)" -eq 0 ] || fail "retry did not remove remaining owned rules"
grep -q 'other-owner' "$CASE/rules" || fail "retry cleanup removed another owner's PPE rule"

make_case listing_failure
run_helper ensure
if MOCK_FAIL_LIST=1 run_helper remove; then
    fail "remove reported success after iptables rule discovery failed"
else
    rc=$?
fi
[ "$rc" -eq 1 ] || fail "rule discovery failure returned $rc instead of 1"
[ "$(grep -c 'r2o-ppe' "$CASE/rules" || true)" -eq 8 ] || fail "cleanup modified rules after failed discovery"
if TEST_PPE_ENABLED=0 MOCK_FAIL_LIST=1 run_helper ensure; then
    fail "disabled PPE setting hid an iptables rule discovery failure"
else
    rc=$?
fi
[ "$rc" -eq 1 ] || fail "disabled cleanup discovery failure returned $rc instead of 1"

make_case incomplete_status
run_helper ensure
_missing_rule=$(grep -F 'FORWARD|-p udp -m multiport --sports 443,50000:50099,1400,3478:3481,5349,19294:19344' "$CASE/rules")
[ -n "$_missing_rule" ] || fail "could not find the fixture rule to remove"
grep -Fvx -- "$_missing_rule" "$CASE/rules" > "$CASE/rules.new"
mv "$CASE/rules.new" "$CASE/rules"
_duplicate_rule=$(grep 'r2o-ppe' "$CASE/rules" | head -n 1)
printf '%s\n' "$_duplicate_rule" >> "$CASE/rules"
[ "$(grep -c 'r2o-ppe' "$CASE/rules")" -eq 8 ] || fail "status fixture does not have the expected duplicate count"
_status=$(run_helper status)
printf '%s\n' "$_status" | grep -q 'PPE: установлена не полностью' || fail "status treated a duplicate as a complete rule set"
printf '%s\n' "$_status" | grep -q 'отсутствует 1' || fail "status did not report the missing required rule"

make_case maximum_voice_ports
if R2O_PPE_VOICE_PORTS=1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 run_helper ensure; then
    :
else
    fail "valid 15-slot voice port list failed because of the added UDP 443 rule"
fi
[ "$(grep -c 'r2o-ppe' "$CASE/rules")" -eq 11 ] || fail "maximum voice-port list did not split into supported PPE rules"
grep -Fq 'PREROUTING|-p udp -m multiport --dports 443 ' "$CASE/rules" || fail "split UDP rules omitted port 443"
grep -Fq 'PREROUTING|-p udp -m multiport --dports 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 ' "$CASE/rules" || fail "split UDP rules omitted configured voice ports"

echo "test-router-ppe-deoffload: owner isolation, idempotence, disable, capability, and partial failure passed"
