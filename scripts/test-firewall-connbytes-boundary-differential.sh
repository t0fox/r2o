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

TEMP=$(mktemp -d "$ROOT/target/r2o-firewall-window.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin" "$TEMP/root/run" "$TEMP/proc/net" "$TEMP/sys" "$TEMP/modules"

sed -n '/^late_rst_from() {/,/^}/p' "$D2O_ROOT/files/S99d2k" | tr -d '\r' > "$TEMP/d2o-late.sh"
sed -n '/^fw_family_up() (/,/^)/p' "$D2O_ROOT/files/S99d2k" | tr -d '\r' > "$TEMP/d2o-xt.sh"
sed -n '/^nft_ruleset() (/,/^)/p' "$D2O_ROOT/files/S99d2k" | tr -d '\r' > "$TEMP/d2o-nft.sh"
sed -n '/^number() {/,/^}/p' "$ROOT/router/r2o-firewall.sh" | tr -d '\r' > "$TEMP/r2o-number.sh"
sed -n '/^late_rst_from() {/,/^}/p' "$ROOT/router/r2o-firewall.sh" | tr -d '\r' > "$TEMP/r2o-late.sh"
sed -n '/^xt_family_up() {/,/^}/p' "$ROOT/router/r2o-firewall.sh" | tr -d '\r' > "$TEMP/r2o-xt.sh"
[ -s "$TEMP/d2o-late.sh" ] && [ -s "$TEMP/d2o-xt.sh" ] && \
    [ -s "$TEMP/d2o-nft.sh" ] && [ -s "$TEMP/r2o-number.sh" ] && \
    [ -s "$TEMP/r2o-late.sh" ] && \
    [ -s "$TEMP/r2o-xt.sh" ] || {
    echo "could not extract current D2O and R2O firewall functions" >&2
    exit 1
}

cat > "$TEMP/bin/iptables" <<'IPTABLES'
#!/bin/sh
case " $* " in
    *' -D '*|*' -C '*) exit 1 ;;
esac
printf '%s\n' "$*" >> "$FW_TRACE"
exit 0
IPTABLES
cat > "$TEMP/bin/nft" <<'NFT'
#!/bin/sh
if [ "${1:-}" = list ]; then exit 1; fi
if [ "${1:-}" = -f ]; then cat "$2" >> "$R2O_NFT_TRACE"; exit 0; fi
exit 2
NFT
for tool in modprobe insmod; do printf '#!/bin/sh\nexit 1\n' > "$TEMP/bin/$tool"; done
printf '#!/bin/sh\nexit 0\n' > "$TEMP/bin/lsmod"
chmod 0755 "$TEMP/bin/iptables" "$TEMP/bin/nft" "$TEMP/bin/modprobe" "$TEMP/bin/insmod" "$TEMP/bin/lsmod"

cat > "$TEMP/d2o-xt-harness.sh" <<'HARNESS'
#!/bin/sh
set -eu
CHAIN_OUT=D2K_OUT CHAIN_IN=D2K_IN
QUEUE_NUM=2000 MARK=0x2d MEASURE_MARK=0x2f
PORTS=443,8443 CONNBYTES=0:3 DNS_PORTS=53,853
VOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344 VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80 GATE_IP= GATE_PORT=443
fw_return_broadcast() { :; }
fw_icmp_te_rule() { :; }
. "$1"
. "$2"
fw_family_up iptables
HARNESS

cat > "$TEMP/d2o-nft-harness.sh" <<'HARNESS'
#!/bin/sh
set -eu
QUEUE_NUM=2000 MARK=0x2d MEASURE_MARK=0x2f
PORTS=443,8443 CONNBYTES=0:3 DNS_PORTS=53,853
VOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344 VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80 GATE_IP= GATE_PORT=443 NFT_TABLE=d2k
NFT_PACKETS_MAX=18446744073709551615
nft_list() { printf '%s' "$1" | sed -e 's/:/-/g' -e 's/,/, /g'; }
nft_count() {
    case "$1" in
        *:) printf '%s-%s' "${1%:}" "$NFT_PACKETS_MAX" ;;
        0:*) printf '1-%s' "${1#0:}" ;;
        *) printf '%s' "$1" | tr ':' '-' ;;
    esac
}
. "$1"
. "$2"
nft_ruleset
HARNESS

cat > "$TEMP/r2o-xt-harness.sh" <<'HARNESS'
#!/bin/sh
set -eu
QUEUE4=2000 MARK=0x2d TG_OUTBOUND_MARK=0x51
PORTS=443,8443 CONNBYTES=0:3 DNS_PORTS=53,853
VOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344 VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80
xt() { "$@"; }
xt_broadcast_return() { :; }
ipv6_mangle_wait_probe() { return 1; }
. "$1"
. "$2"
. "$3"
xt_family_up iptables "$QUEUE4"
HARNESS

FW_TRACE="$TEMP/d2o.xt" PATH="$TEMP/bin:$PATH" \
    sh "$TEMP/d2o-xt-harness.sh" "$TEMP/d2o-late.sh" "$TEMP/d2o-xt.sh"
sh "$TEMP/d2o-nft-harness.sh" "$TEMP/d2o-late.sh" "$TEMP/d2o-nft.sh" > "$TEMP/d2o.nft"
FW_TRACE="$TEMP/r2o.xt" PATH="$TEMP/bin:$PATH" \
    sh "$TEMP/r2o-xt-harness.sh" "$TEMP/r2o-number.sh" "$TEMP/r2o-late.sh" "$TEMP/r2o-xt.sh"

printf 'FW_BACKEND=nft\nIPV6_ENABLED=0\nPORTS=443,8443\nCONNBYTES=0:3\n' > "$TEMP/config"
R2O_DIR="$TEMP/root" R2O_CONFIG="$TEMP/config" R2O_RUN_DIR="$TEMP/root/run" \
R2O_PROC_DIR="$TEMP/proc" R2O_SYS_MODULE_DIR="$TEMP/sys" R2O_MODULES_DIR="$TEMP/modules" \
R2O_NFT_TRACE="$TEMP/r2o.nft" PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/r2o-firewall.sh" up > "$TEMP/r2o.log" 2>&1

failures=0
check_count() {
    trace=$1
    fragment=$2
    expected=$3
    description=$4
    actual=$(grep -Fc -- "$fragment" "$trace" || true)
    if [ "$actual" != "$expected" ]; then
        echo "$description: expected $expected, got $actual in $trace" >&2
        failures=$((failures + 1))
    fi
}

for trace in "$TEMP/d2o.xt" "$TEMP/r2o.xt"; do
    check_count "$trace" '--connbytes 4: --connbytes-dir original' 3 'wrong count of dynamic iptables original late rules'
    check_count "$trace" '--connbytes 4: --connbytes-dir reply' 3 'wrong count of dynamic iptables reply late rules'
    for direction in original reply; do
        for flag in RST FIN; do
            check_count "$trace" "--connbytes 4: --connbytes-dir $direction --connbytes-mode packets --tcp-flags $flag $flag" 1 "wrong $direction $flag boundary"
        done
    done
done

for trace in "$TEMP/d2o.nft" "$TEMP/r2o.nft"; do
    case "$trace" in
        */d2o.nft) family_rules=3; flag_rules=1 ;;
        *) family_rules=6; flag_rules=2 ;;
    esac
    actual=$(grep -F 'ct original packets 4-18446744073709551615' "$trace" | grep -Fc 'queue num' || true)
    [ "$actual" = "$family_rules" ] || { echo "wrong count of dynamic nft original NFQUEUE late rules: expected $family_rules, got $actual in $trace" >&2; failures=$((failures + 1)); }
    actual=$(grep -F 'ct reply packets 4-18446744073709551615' "$trace" | grep -Fc 'queue num' || true)
    [ "$actual" = "$family_rules" ] || { echo "wrong count of dynamic nft reply NFQUEUE late rules: expected $family_rules, got $actual in $trace" >&2; failures=$((failures + 1)); }
    for direction in original reply; do
        for flag in rst fin; do
            actual=$(grep -F "packets 4-18446744073709551615 tcp flags & $flag == $flag" "$trace" | grep -F "ct direction $direction" | grep -Fc 'queue num' || true)
            [ "$actual" = "$flag_rules" ] || { echo "wrong nft $direction $flag boundary: expected $flag_rules, got $actual in $trace" >&2; failures=$((failures + 1)); }
        done
    done
    actual=$(grep -F 'packets 4-18446744073709551615' "$trace" | grep -F 'th dport { 80 }' | grep -Fc 'queue num' || true)
    [ "$actual" = "$flag_rules" ] || { echo "wrong nft original HTTP keepalive boundary: expected $flag_rules, got $actual in $trace" >&2; failures=$((failures + 1)); }
    actual=$(grep -F 'packets 4-18446744073709551615' "$trace" | grep -F 'th sport { 80 }' | grep -Fc 'queue num' || true)
    [ "$actual" = "$flag_rules" ] || { echo "wrong nft reply HTTP keepalive boundary: expected $flag_rules, got $actual in $trace" >&2; failures=$((failures + 1)); }
done

[ "$failures" -eq 0 ] || exit 1

echo "D2O/R2O nft and iptables late TCP rules use CONNBYTES upper bound + 1 (d2o $ACTUAL_D2O_SHA)."
