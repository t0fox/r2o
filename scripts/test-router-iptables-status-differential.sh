#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    echo "unexpected D2O revision" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-iptables-status.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin"

{
    sed -n '/^late_rst_from() {/,/^}/p' "$D2O_ROOT/files/S99d2k"
    sed -n '/^fw_icmp_te_rule() {/,/^}/p' "$D2O_ROOT/files/S99d2k"
    sed -n '/^fw_family_installed() (/,/^)/p' "$D2O_ROOT/files/S99d2k"
} | tr -d '\r' > "$TEMP/d2o-family-status.sh"
[ -s "$TEMP/d2o-family-status.sh" ] || { echo "could not extract D2O family status" >&2; exit 2; }
{
    sed -n '/^number() {/,/^}/p' "$ROOT/router/r2o-firewall.sh"
    sed -n '/^late_rst_from() {/,/^}/p' "$ROOT/router/r2o-firewall.sh"
    sed -n '/^xt() {/,/^}/p' "$ROOT/router/r2o-firewall.sh"
    sed -n '/^xt_broadcast_return() {/,/^}/p' "$ROOT/router/r2o-firewall.sh"
    sed -n '/^xt_family_up() {/,/^}/p' "$ROOT/router/r2o-firewall.sh"
    sed -n '/^xt_family_installed() {/,/^}/p' "$ROOT/router/r2o-firewall.sh"
} | tr -d '\r' > "$TEMP/r2o-family-functions.sh"
[ -s "$TEMP/r2o-family-functions.sh" ] || { echo "could not extract R2O family functions" >&2; exit 2; }

cat >"$TEMP/bin/iptables" <<'IPTABLES'
#!/bin/sh
if [ "${1:-}" = -w ]; then shift; fi
case "$STATUS_STATE:$*" in
    missing-queues:*NFQUEUE*) exit 1 ;;
    missing-forward:*'-C FORWARD -j'*) exit 1 ;;
    missing-input:*'-C INPUT -j'*) exit 1 ;;
esac
if [ "$STATUS_IMPL" = d2o ]; then exit 0; fi
case " $* " in
    *' -C '*)
        expected=$(printf '%s\n' "$*" | sed 's/ -C / -A /')
        grep -F -x -q -- "$expected" "$STATE_FILE"
        ;;
    *' -A '*|*' -I '*)
        expected=$(printf '%s\n' "$*" | sed -e 's/ -I \([^ ]*\) 1 / -A \1 /')
        printf '%s\n' "$expected" >> "$STATE_FILE"
        ;;
    *) exit 0 ;;
esac
IPTABLES
chmod 0755 "$TEMP/bin/iptables"

cat >"$TEMP/d2o-check.sh" <<'D2O'
#!/bin/sh
QUEUE_NUM=2000
CHAIN_OUT=D2K_OUT
CHAIN_IN=D2K_IN
MARK=45
MEASURE_MARK=12
PORTS=443,8443
CONNBYTES=0:8
DNS_PORTS=5353,853
GATE_IP=
GATE_PORT=443
HTTP_KEEPALIVE_PORTS=80
. "$D2O_FAMILY_STATUS"
fw_family_installed iptables
D2O
chmod 0755 "$TEMP/d2o-check.sh"

cat >"$TEMP/r2o-seed.sh" <<'R2O'
#!/bin/sh
set -eu
QUEUE4=2000
MARK=45
TG_OUTBOUND_MARK=0x40000000
PORTS=443,8443
CONNBYTES=0:8
VOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344
VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80
DNS_PORTS=5353,853
ipv6_mangle_wait_probe() { return 1; }
. "$R2O_FAMILY_FUNCTIONS"
xt_family_up iptables "$QUEUE4"
R2O
chmod 0755 "$TEMP/r2o-seed.sh"

cat >"$TEMP/config" <<'CONFIG'
FW_BACKEND=iptables
IPV6_ENABLED=0
QUEUE_NUM=2000
QUEUE_NUM6=2001
MARK=45
PORTS=443,8443
CONNBYTES=0:8
VOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344
VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80
DNS_PORTS=5353,853
CONFIG

check_d2o() {
    STATUS_IMPL=d2o STATUS_STATE=$2 D2O_FAMILY_STATUS="$TEMP/d2o-family-status.sh" \
        PATH="$TEMP/bin:$PATH" sh "$TEMP/d2o-check.sh"
}

check_r2o() {
    : > "$TEMP/r2o-state"
    STATUS_IMPL=r2o STATUS_STATE=seed STATE_FILE="$TEMP/r2o-state" \
    R2O_FAMILY_FUNCTIONS="$TEMP/r2o-family-functions.sh" PATH="$TEMP/bin:$PATH" \
        sh "$TEMP/r2o-seed.sh"
    STATUS_IMPL=r2o STATUS_STATE=$2 STATE_FILE="$TEMP/r2o-state" R2O_CONFIG=$TEMP/config R2O_RUN_DIR=$TEMP/run \
        PATH="$TEMP/bin:$PATH" sh "$ROOT/router/r2o-firewall.sh" status
}

for state in complete missing-queues missing-forward missing-input; do
    d2o_status=healthy
    r2o_status=healthy
    check_d2o "$TEMP" "$state" || d2o_status=unhealthy
    check_r2o "$TEMP" "$state" || r2o_status=unhealthy
    printf '%s installed-rule state: D2O=%s R2O=%s\n' "$state" "$d2o_status" "$r2o_status"
    [ "$d2o_status" = "$r2o_status" ] || {
        echo "R2O iptables status accepted missing NFQUEUE rules rejected by D2O" >&2
        exit 1
    }
done

echo "test-router-iptables-status-differential: C and Rust status agree on complete and incomplete rules"
