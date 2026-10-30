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

TEMP=$(mktemp -d "$ROOT/target/r2o-firewall-port-scope.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin"

sed -n '/^fw_family_up() (/,/^)/p' "$D2O_ROOT/files/S99d2k" |
    tr -d '\r' > "$TEMP/d2o-function.sh"
sed -n '/^xt_family_up() {/,/^}/p' "$ROOT/router/r2o-firewall.sh" |
    tr -d '\r' > "$TEMP/r2o-function.sh"
[ -s "$TEMP/d2o-function.sh" ] && [ -s "$TEMP/r2o-function.sh" ] || {
    echo "could not extract the current D2O and R2O firewall family functions" >&2
    exit 1
}

cat > "$TEMP/bin/iptables" <<'IPTABLES'
#!/bin/sh
printf '%s\n' "$*" >> "$FW_TRACE"
exit 0
IPTABLES
chmod 0755 "$TEMP/bin/iptables"

cat > "$TEMP/d2o-harness.sh" <<'HARNESS'
#!/bin/sh
set -eu
CHAIN_OUT=D2K_OUT
CHAIN_IN=D2K_IN
QUEUE_NUM=2000
MARK=0x2d
MEASURE_MARK=0x2f
PORTS=443,8443
CONNBYTES=0:8
DNS_PORTS=53,853
VOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344
VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80
GATE_IP=
GATE_PORT=443
late_rst_from() { printf '%s\n' 9; }
fw_return_broadcast() { :; }
fw_icmp_te_rule() { :; }
. "$1"
fw_family_up iptables
HARNESS

cat > "$TEMP/r2o-harness.sh" <<'HARNESS'
#!/bin/sh
set -eu
QUEUE4=2000
MARK=0x2d
TG_OUTBOUND_MARK=0x51
PORTS=443,8443
CONNBYTES=0:8
DNS_PORTS=53,853
VOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344
VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80
xt() { "$@"; }
xt_broadcast_return() { :; }
ipv6_mangle_wait_probe() { return 1; }
. "$1"
xt_family_up iptables "$QUEUE4"
HARNESS

assert_rule() {
    trace=$1
    chain=$2
    rule=$3
    if ! grep -F -- "-A $chain $rule" "$trace" >/dev/null; then
        echo "missing configured-port NFQUEUE rule in $trace: -A $chain $rule" >&2
        grep -E -- "-A $chain .*NFQUEUE" "$trace" >&2 || true
        exit 1
    fi
}

FW_TRACE="$TEMP/d2o.trace" PATH="$TEMP/bin:$PATH" \
    sh "$TEMP/d2o-harness.sh" "$TEMP/d2o-function.sh"
FW_TRACE="$TEMP/r2o.trace" PATH="$TEMP/bin:$PATH" \
    sh "$TEMP/r2o-harness.sh" "$TEMP/r2o-function.sh"

for implementation in d2o r2o; do
    trace="$TEMP/$implementation.trace"
    if [ "$implementation" = d2o ]; then out=D2K_OUT; in=D2K_IN; else out=R2O_OUT; in=R2O_IN; fi
    assert_rule "$trace" "$out" '-p tcp -m conntrack --ctdir ORIGINAL -m multiport --dports 443,8443 -m connbytes --connbytes 0:8 --connbytes-dir original --connbytes-mode packets -j NFQUEUE --queue-num 2000 --queue-bypass'
    assert_rule "$trace" "$in" '-p tcp -m conntrack --ctdir REPLY -m multiport --sports 443,8443 -m connbytes --connbytes 0:8 --connbytes-dir reply --connbytes-mode packets -j NFQUEUE --queue-num 2000 --queue-bypass'
    assert_rule "$trace" "$out" '-p udp -m conntrack --ctdir ORIGINAL -m multiport --dports 443,8443 -m connbytes --connbytes 0:8 --connbytes-dir original --connbytes-mode packets -j NFQUEUE --queue-num 2000 --queue-bypass'
    assert_rule "$trace" "$in" '-p udp -m conntrack --ctdir REPLY -m multiport --sports 443,8443 -m connbytes --connbytes 0:8 --connbytes-dir reply --connbytes-mode packets -j NFQUEUE --queue-num 2000 --queue-bypass'
    for direction in "$out:ORIGINAL:original:dports" "$in:REPLY:reply:sports"; do
        old_ifs=$IFS
        IFS=:
        set -- $direction
        IFS=$old_ifs
        chain=$1 ct_direction=$2 count_direction=$3 port_direction=$4
        for flag in RST FIN; do
            assert_rule "$trace" "$chain" "-p tcp -m conntrack --ctdir $ct_direction -m multiport --$port_direction 443,8443 -m connbytes --connbytes 9: --connbytes-dir $count_direction --connbytes-mode packets --tcp-flags $flag $flag -j NFQUEUE --queue-num 2000 --queue-bypass"
        done
    done
done

echo "D2O/R2O iptables NFQUEUE rules honor configured TCP/UDP and late RST/FIN ports (d2o $ACTUAL_D2O_SHA)."
