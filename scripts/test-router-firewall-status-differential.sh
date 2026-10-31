#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    echo "unexpected D2O revision" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-firewall-status.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin"

sed -n '/^fw_nft_installed() (/,/^)/p' "$D2O_ROOT/files/S99d2k" |
    tr -d '\r' > "$TEMP/d2o-fw-status.sh"
[ -s "$TEMP/d2o-fw-status.sh" ] || { echo "could not extract D2O nft status check" >&2; exit 2; }
{
    sed -n '/^late_rst_from() {/,/^}/p' "$D2O_ROOT/files/S99d2k"
    sed -n '/^nft_list() {/,/^}/p' "$D2O_ROOT/files/S99d2k"
    sed -n '/^nft_count() {/,/^}/p' "$D2O_ROOT/files/S99d2k"
    sed -n '/^nft_ruleset() (/,/^)/p' "$D2O_ROOT/files/S99d2k"
} | tr -d '\r' > "$TEMP/d2o-rule-generators.sh"
[ -s "$TEMP/d2o-rule-generators.sh" ] || { echo "could not extract D2O nft rule generator" >&2; exit 2; }

cat >"$TEMP/bin/nft" <<'NFT'
#!/bin/sh
case "$*" in
    'list table inet d2k') cat "$D2O_TABLE" ;;
    'list table inet d2k_rst') exit 0 ;;
    'list table inet r2o') cat "$R2O_TABLE" ;;
    'list table inet r2o_rst') exit 0 ;;
    'list chain inet r2o '*)
        chain=${5}
        awk -v wanted="$chain" \
            '$1 == "chain" && $2 == wanted && $3 == "{" { inside = 1 }
             inside { print }
             inside && $1 == "}" { exit }' "$R2O_TABLE"
        ;;
    *) echo "unexpected nft command: $*" >&2; exit 2 ;;
esac
NFT
chmod 0755 "$TEMP/bin/nft"

cat >"$TEMP/d2o-check.sh" <<'D2O'
#!/bin/sh
nft_has() { nft list table inet "$1" >/dev/null 2>&1; }
NFT_TABLE=d2k
NFT_RST_TABLE=d2k_rst
QUEUE_NUM=2000
NFT_PACKETS_MAX=4294967295
CONNBYTES=0:8
PORTS=443
DNS_PORTS=53,853
VOICE_PORTS=50000:50099
VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80
GATE_IP=
GATE_PORT=443
MARK=0x1
MEASURE_MARK=0x2
. "$D2O_RULE_GENERATORS"
. "$D2O_STATUS_FUNCTIONS"
fw_nft_installed
D2O
chmod 0755 "$TEMP/d2o-check.sh"

cat >"$TEMP/config" <<'CONFIG'
FW_BACKEND=nft
IPV6_ENABLED=1
QUEUE_NUM=2000
QUEUE_NUM6=2001
PORTS=443
CONNBYTES=0:8
VOICE_PORTS=50000:50099
VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80
DNS_PORTS=53,853
CONFIG

write_d2o_table() {
    table_file=$1
    queue_rules=$2
    {
        cat <<'TABLE'
table inet d2k {
chain out {
TABLE
        if [ "$queue_rules" = complete ] || [ "$queue_rules" = missing-in ]; then
            i=0
            while [ "$i" -lt 6 ]; do
                printf '    tcp dport 443 queue flags bypass to 2000\n'
                i=$((i + 1))
            done
        fi
        printf '}\n'
        cat <<'TABLE'
chain in_rules {
TABLE
        if [ "$queue_rules" = complete ] || [ "$queue_rules" = missing-out ]; then
            i=0
            while [ "$i" -lt 8 ]; do
                printf '    tcp sport 443 queue flags bypass to 2000\n'
                i=$((i + 1))
            done
        fi
        printf '}\n'
        cat <<'TABLE'
chain in_forward {
}
chain in_input {
}
chain nat_post {
    masquerade
}
TABLE
        printf '}\n'
    } > "$table_file"
}

write_r2o_table() {
    table_file=$1
    queue_rules=$2
    {
        cat <<'TABLE'
table inet r2o {
    comment "r2o-managed"
chain mark_flow {
}
chain out {
    type filter hook postrouting priority mangle; policy accept;
TABLE
        if [ "$queue_rules" = complete ] || [ "$queue_rules" = missing-in ]; then
            i=0
            while [ "$i" -lt 6 ]; do
                printf '    tcp dport 443 queue flags bypass to 2000\n'
                printf '    tcp dport 443 queue flags bypass to 2001\n'
                i=$((i + 1))
            done
        fi
        cat <<'TABLE'
}
chain in_rules {
TABLE
        if [ "$queue_rules" = complete ] || [ "$queue_rules" = missing-out ]; then
            i=0
            while [ "$i" -lt 7 ]; do
                printf '    tcp sport 443 queue flags bypass to 2000\n'
                printf '    tcp sport 443 queue flags bypass to 2001\n'
                i=$((i + 1))
            done
        fi
        cat <<'TABLE'
}
chain forward {
    type filter hook forward priority mangle; policy accept;
    jump mark_flow
    jump in_rules
}
chain input {
    type filter hook input priority mangle; policy accept;
    jump in_rules
}
chain nat_post {
    type nat hook postrouting priority srcnat - 1; policy accept;
    masquerade
}
TABLE
        printf '}\n'
    } > "$table_file"
}

check_d2o() {
    D2O_TABLE=$1 D2O_RULE_GENERATORS="$TEMP/d2o-rule-generators.sh" \
    D2O_STATUS_FUNCTIONS="$TEMP/d2o-fw-status.sh" PATH="$TEMP/bin:$PATH" \
        sh "$TEMP/d2o-check.sh"
}

check_r2o() {
    R2O_DIR=$TEMP R2O_CONFIG=$TEMP/config R2O_RUN_DIR=$TEMP/run \
    R2O_TABLE=$1 PATH="$TEMP/bin:$PATH" \
        sh "$ROOT/router/r2o-firewall.sh" status
}

write_d2o_table "$TEMP/d2o-complete" complete
write_r2o_table "$TEMP/r2o-complete" complete
if ! check_d2o "$TEMP/d2o-complete" || ! check_r2o "$TEMP/r2o-complete"; then
    echo "a complete nft firewall is not accepted by both implementations" >&2
    exit 1
fi

for broken in missing missing-out missing-in; do
    write_d2o_table "$TEMP/d2o-$broken" "$broken"
    write_r2o_table "$TEMP/r2o-$broken" "$broken"
    d2o_status=healthy
    r2o_status=healthy
    check_d2o "$TEMP/d2o-$broken" || d2o_status=unhealthy
    check_r2o "$TEMP/r2o-$broken" || r2o_status=unhealthy
    printf '%s NFQUEUE rules: D2O=%s R2O=%s\n' "$broken" "$d2o_status" "$r2o_status"
    [ "$d2o_status" = unhealthy ] && [ "$r2o_status" = unhealthy ] || {
        echo "R2O/D2O status mismatch for $broken NFQUEUE rules" >&2
        exit 1
    }
done

echo "test-router-firewall-status-differential: both implementations reject incomplete NFQUEUE chains"
