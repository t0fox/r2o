#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=8e2c98146cf0b712dc967fbec558c7b904666e87
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-firewall-broadcast.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin" "$TEMP/root/run" "$TEMP/proc/net" "$TEMP/sys" "$TEMP/modules"
printf '#!/bin/sh\nexit 1\n' > "$TEMP/bin/modprobe"
printf '#!/bin/sh\nexit 0\n' > "$TEMP/bin/lsmod"
printf '#!/bin/sh\nexit 1\n' > "$TEMP/bin/insmod"
chmod 0755 "$TEMP/bin/modprobe" "$TEMP/bin/lsmod" "$TEMP/bin/insmod"

line_number() {
    grep -nF -- "$2" "$1" | sed -n '1s/:.*//p'
}
assert_before() {
    trace_file=$1
    rule=$2
    anchor=$3
    rule_line=$(line_number "$trace_file" "$rule")
    queue_line=$(line_number "$trace_file" "$anchor")
    [ -n "$rule_line" ] && [ -n "$queue_line" ] && [ "$rule_line" -lt "$queue_line" ] || {
        echo "rule is missing or appears after queue anchor $anchor: $rule" >&2
        exit 1
    }
}
assert_before_queue() { assert_before "$1" "$2" 'queue num'; }
assert_xt_chain_before_queue() {
    awk -v chain="-A $2 " -v rule="$3" '
        index($0, chain) {
            if (!gate && index($0, rule)) gate = NR
            if (!queue && index($0, "--queue-num")) queue = NR
        }
        END { exit !(gate && queue && gate < queue) }
    ' "$1" || { echo "iptables rule is missing or appears after queue in $2: $3" >&2; exit 1; }
}
assert_nft_chain_before_queue() {
    awk -v chain="$2" -v rule="$3" '
        index($0, chain) { in_chain = 1; next }
        in_chain && /^    chain / { exit }
        in_chain && !gate && index($0, rule) { gate = NR }
        in_chain && !queue && index($0, "queue num") { queue = NR }
        END { exit !(gate && queue && gate < queue) }
    ' "$1" || { echo "nft rule is missing or appears after queue in $2: $3" >&2; exit 1; }
}
assert_nft_rule_order() {
    awk -v chain="$2" -v first_rule="$3" -v first_count="$4" \
        -v second_rule="$5" -v second_count="$6" '
        index($0, chain) { in_chain = 1; next }
        in_chain && /^    chain / { exit }
        in_chain && !first && index($0, first_rule) && index($0, first_count) { first = NR }
        in_chain && !second && index($0, second_rule) && index($0, second_count) { second = NR }
        END { exit !(first && second && first < second) }
    ' "$1" || {
        echo "UDP rules are out of D2O order in $2: common port queue must precede voice queue" >&2
        sed -n '/chain out {/,/chain in_rules {/p; /chain in_rules {/,/chain in_forward {/p' "$1" >&2
        exit 1
    }
}

sed -n '/^nft_ruleset() (/,$p' "$D2O_ROOT/files/S99d2k" |
    tr -d '\r' | sed -n '1,/^)/p' > "$TEMP/d2o-nft-function.sh"
[ -s "$TEMP/d2o-nft-function.sh" ] || {
    echo "could not extract the current D2O nft_ruleset function" >&2
    exit 1
}
cat > "$TEMP/d2o-nft-harness.sh" <<'HARNESS'
#!/bin/sh
set -eu
CONNBYTES=0:8
PORTS=0:65535
DNS_PORTS=53,853
VOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344
VOICE_CONNBYTES=0:4
HTTP_KEEPALIVE_PORTS=80
QUEUE_NUM=2000
MARK=0x2d
MEASURE_MARK=0x2f
NFT_TABLE=d2k
NFT_PACKETS_MAX=18446744073709551615
GATE_IP=203.0.113.9
GATE_PORT=8443
late_rst_from() { echo $((${CONNBYTES#0:} + 1)); }
nft_list() { printf '%s' "$1" | sed -e 's/:/-/g' -e 's/,/, /g'; }
nft_count() {
    case "$1" in
        *:) printf '%s-%s' "${1%:}" "$NFT_PACKETS_MAX" ;;
        0:*) printf '1-%s' "${1#0:}" ;;
        *) printf '%s' "$1" | tr ':' '-' ;;
    esac
}
. "$1"
nft_ruleset
HARNESS

sh "$TEMP/d2o-nft-harness.sh" "$TEMP/d2o-nft-function.sh" > "$TEMP/d2o.nft"

sed -n '/^fw_return_broadcast() {/,/^}/p' "$D2O_ROOT/files/S99d2k" |
    tr -d '\r' > "$TEMP/d2o-broadcast-function.sh"
[ -s "$TEMP/d2o-broadcast-function.sh" ] || {
    echo "could not extract the current D2O broadcast helper" >&2
    exit 1
}
sed -n '/^fw_icmp_te_rule() {/,/^}/p' "$D2O_ROOT/files/S99d2k" |
    tr -d '\r' > "$TEMP/d2o-icmp-function.sh"
[ -s "$TEMP/d2o-icmp-function.sh" ] || {
    echo "could not extract the current D2O ICMP helper" >&2
    exit 1
}

cat > "$TEMP/bin/nft" <<'NFT'
#!/bin/sh
if [ "${1:-}" = list ]; then exit 1; fi
if [ "${1:-}" = -f ]; then cat "$2" >> "$R2O_TEST_RULES"; exit 0; fi
exit 2
NFT
chmod 0755 "$TEMP/bin/nft"

D2K_GATE=http://203.0.113.9:8443/update \
R2O_DIR="$TEMP/root" \
R2O_CONFIG=/dev/null \
R2O_RUN_DIR="$TEMP/root/run" \
R2O_PROC_DIR="$TEMP/proc" R2O_SYS_MODULE_DIR="$TEMP/sys" R2O_MODULES_DIR="$TEMP/modules" \
R2O_TEST_RULES="$TEMP/r2o.nft" \
FW_BACKEND=nft \
PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/r2o-firewall.sh" up

for rule in \
    'meta nfproto ipv4 fib daddr type broadcast return' \
    'ip daddr 224.0.0.0/4 return' \
    'ip6 daddr ff00::/8 return'; do
    grep -Fq "$rule" "$TEMP/d2o.nft" || {
        echo "D2O nft oracle omitted expected rule: $rule" >&2
        exit 1
    }
    grep -Fq "$rule" "$TEMP/r2o.nft" || {
        echo "R2O nft rules differ from D2O: missing $rule" >&2
        echo 'D2O rules:' >&2
        grep -E 'broadcast return|224\.0\.0\.0/4 return|ff00::/8 return' "$TEMP/d2o.nft" >&2 || true
        echo 'R2O rules:' >&2
        grep -E 'broadcast return|224\.0\.0\.0/4 return|ff00::/8 return' "$TEMP/r2o.nft" >&2 || true
        exit 1
    }
    assert_before_queue "$TEMP/r2o.nft" "$rule"
done
for rules in "$TEMP/d2o.nft" "$TEMP/r2o.nft"; do
    grep -Fq 'meta mark 0x2f return' "$rules" || {
        echo "$rules omitted the measurement-mark NFQUEUE bypass" >&2
        exit 1
    }
    grep -Fq 'ip daddr 203.0.113.9 tcp dport 8443 return' "$rules" || {
        echo "$rules omitted the IPv4 update-gate exclusion" >&2
        exit 1
    }
    grep -Fq 'ip saddr 203.0.113.9 tcp sport 8443 return' "$rules" || {
        echo "$rules omitted the IPv4 update-gate reply exclusion" >&2
        exit 1
    }
done
assert_before_queue "$TEMP/r2o.nft" 'ip daddr 203.0.113.9 tcp dport 8443 return'
assert_nft_chain_before_queue "$TEMP/r2o.nft" 'chain in_rules {' 'ip saddr 203.0.113.9 tcp sport 8443 return'
for rules in "$TEMP/d2o.nft" "$TEMP/r2o.nft"; do
    assert_nft_rule_order "$rules" 'chain out {' \
        'meta l4proto udp' 'ct original packets 1-8' \
        'meta l4proto udp' 'ct original packets 1-4'
    assert_nft_rule_order "$rules" 'chain in_rules {' \
        'meta l4proto udp' 'ct reply packets 1-8' \
        'meta l4proto udp' 'ct reply packets 1-4'
done
if grep -Eq 'th dport \{[^}]*50000-50099[^}]*\} return|th sport \{[^}]*50000-50099[^}]*\} return' "$TEMP/r2o.nft"; then
    echo "R2O prematurely returns from overlapping voice UDP ports" >&2
    exit 1
fi
grep -Fq 'icmp type time-exceeded icmp code 0 queue num 2000 bypass' "$TEMP/d2o.nft" || {
    echo "D2O nft oracle omitted IPv4 time-exceeded queue" >&2
    exit 1
}
grep -Fq 'icmpv6 type time-exceeded icmpv6 code 0 queue num 2000 bypass' "$TEMP/d2o.nft" || {
    echo "D2O nft oracle omitted IPv6 time-exceeded queue" >&2
    exit 1
}
grep -Fq 'icmp type time-exceeded icmp code 0 queue num 2000 bypass' "$TEMP/r2o.nft" || {
    echo "R2O nft rules differ from D2O: missing IPv4 time-exceeded queue" >&2
    exit 1
}
grep -Fq 'icmpv6 type time-exceeded icmpv6 code 0 queue num 2001 bypass' "$TEMP/r2o.nft" || {
    echo "R2O nft rules differ from D2O: missing IPv6 time-exceeded queue" >&2
    exit 1
}

for tool in iptables ip6tables; do
    cat > "$TEMP/bin/$tool" <<'XT'
#!/bin/sh
case " $* " in
    *' --dst-type BROADCAST '*)
        printf '%s\n' "$*" >> "$FW_TRACE"
        [ "${FW_NO_ADDRTYPE:-0}" = 0 ]
        exit
        ;;
    *' -A '*) printf '%s\n' "$*" >> "$FW_TRACE"; exit 0 ;;
    *' -N '*) exit 0 ;;
    *' -D '*) exit 1 ;;
    *' -C '*) exit 1 ;;
    *) exit 0 ;;
esac
XT
    chmod 0755 "$TEMP/bin/$tool"
done
cat > "$TEMP/bin/ip" <<'IP'
#!/bin/sh
[ "$*" = '-4 addr show' ] || exit 2
echo 'inet 192.168.1.1/24 brd 192.168.1.255 scope global br0'
IP
cat > "$TEMP/bin/awk" <<'AWK'
#!/bin/sh
input=$1
cat >/dev/null
case "$input" in *brd*) printf '192.168.1.255\n' ;; esac
AWK
cat > "$TEMP/bin/sort" <<'SORT'
#!/bin/sh
cat
SORT
chmod 0755 "$TEMP/bin/ip" "$TEMP/bin/awk" "$TEMP/bin/sort"
cat > "$TEMP/d2o-iptables-harness.sh" <<'HARNESS'
#!/bin/sh
set -eu
say() { :; }
. "$1"
fw_return_broadcast iptables mangle D2K_OUT
HARNESS
cat > "$TEMP/d2o-icmp-harness.sh" <<'HARNESS'
#!/bin/sh
set -eu
CHAIN_IN=D2K_IN
QUEUE_NUM=2000
. "$1"
fw_icmp_te_rule iptables -A
fw_icmp_te_rule ip6tables -A
HARNESS
FW_TRACE="$TEMP/d2o-iptables.trace" PATH="$TEMP/bin:$PATH" \
    sh "$TEMP/d2o-iptables-harness.sh" "$TEMP/d2o-broadcast-function.sh"
FW_TRACE="$TEMP/d2o-iptables-fallback.trace" FW_NO_ADDRTYPE=1 PATH="$TEMP/bin:$PATH" \
    sh "$TEMP/d2o-iptables-harness.sh" "$TEMP/d2o-broadcast-function.sh"
FW_TRACE="$TEMP/d2o-icmp.trace" PATH="$TEMP/bin:$PATH" \
    sh "$TEMP/d2o-icmp-harness.sh" "$TEMP/d2o-icmp-function.sh"

D2K_GATE=http://203.0.113.9:8443/update \
R2O_DIR="$TEMP/root" \
R2O_CONFIG=/dev/null \
R2O_RUN_DIR="$TEMP/root/run" \
R2O_PROC_DIR="$TEMP/proc" R2O_SYS_MODULE_DIR="$TEMP/sys" R2O_MODULES_DIR="$TEMP/modules" \
FW_BACKEND=iptables \
IPV6_ENABLED=1 \
FW_TRACE="$TEMP/r2o-iptables.trace" \
PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/r2o-firewall.sh" up
D2K_GATE=http://203.0.113.9:8443/update \
R2O_DIR="$TEMP/root" \
R2O_CONFIG=/dev/null \
R2O_RUN_DIR="$TEMP/root/run" \
R2O_PROC_DIR="$TEMP/proc" R2O_SYS_MODULE_DIR="$TEMP/sys" R2O_MODULES_DIR="$TEMP/modules" \
FW_BACKEND=iptables \
IPV6_ENABLED=1 \
FW_NO_ADDRTYPE=1 \
FW_TRACE="$TEMP/r2o-iptables-fallback.trace" \
PATH="$TEMP/bin:$PATH" \
    sh "$ROOT/router/r2o-firewall.sh" up

grep -Fq -- '-m addrtype --dst-type BROADCAST -j RETURN' "$TEMP/d2o-iptables.trace" || {
    echo "D2O iptables oracle did not emit its broadcast exclusion" >&2
    exit 1
}
grep -Fq -- '-m addrtype --dst-type BROADCAST -j RETURN' "$TEMP/r2o-iptables.trace" || {
    echo "R2O iptables rules differ from D2O: missing broadcast exclusion" >&2
    exit 1
}
for trace in "$TEMP/r2o-iptables.trace"; do
    grep -Fq -- '-p tcp -d 203.0.113.9 --dport 8443 -j RETURN' "$trace" || {
        echo "$trace omitted the IPv4 update-gate outbound exclusion" >&2
        exit 1
    }
    grep -Fq -- '-p tcp -s 203.0.113.9 --sport 8443 -j RETURN' "$trace" || {
        echo "$trace omitted the IPv4 update-gate reply exclusion" >&2
        exit 1
    }
done
assert_before "$TEMP/r2o-iptables.trace" '-d 203.0.113.9 --dport 8443 -j RETURN' '--queue-num'
assert_xt_chain_before_queue "$TEMP/r2o-iptables.trace" R2O_IN '-p tcp -s 203.0.113.9 --sport 8443 -j RETURN'
assert_before "$TEMP/r2o-iptables.trace" '-m addrtype --dst-type BROADCAST -j RETURN' '--queue-num'
assert_before "$TEMP/r2o-iptables.trace" '-d 224.0.0.0/4 -j RETURN' '--queue-num 2000'
assert_before "$TEMP/r2o-iptables.trace" '-d ff00::/8 -j RETURN' '--queue-num 2001'
for trace in d2o-iptables-fallback.trace r2o-iptables-fallback.trace; do
    grep -Fq -- '-d 255.255.255.255 -j RETURN' "$TEMP/$trace" || {
        echo "$trace omitted the D2O all-ones broadcast fallback" >&2
        exit 1
    }
    grep -Fq -- '-d 192.168.1.255 -j RETURN' "$TEMP/$trace" || {
        echo "$trace omitted the interface broadcast fallback" >&2
        exit 1
    }
    if [ "$trace" = r2o-iptables-fallback.trace ]; then
        assert_before "$TEMP/$trace" '-d 255.255.255.255 -j RETURN' '--queue-num 2000'
        assert_before "$TEMP/$trace" '-d 192.168.1.255 -j RETURN' '--queue-num 2000'
    fi
done
grep -Fq -- '-d 224.0.0.0/4 -j RETURN' "$TEMP/r2o-iptables.trace" || {
    echo "R2O iptables rules differ from D2O: missing IPv4 multicast exclusion" >&2
    exit 1
}
grep -Fq -- '-d ff00::/8 -j RETURN' "$TEMP/r2o-iptables.trace" || {
    echo "R2O ip6tables rules differ from D2O: missing IPv6 multicast exclusion" >&2
    exit 1
}
for rule in \
    '-p icmp --icmp-type 11/0 -j NFQUEUE --queue-num 2000 --queue-bypass' \
    '-p ipv6-icmp --icmpv6-type 3/0 -j NFQUEUE --queue-num 2000 --queue-bypass'; do
    grep -Fq -- "$rule" "$TEMP/d2o-icmp.trace" || {
        echo "D2O iptables oracle omitted expected ICMP rule: $rule" >&2
        exit 1
    }
done
grep -Fq -- '-p icmp --icmp-type 11/0 -j NFQUEUE --queue-num 2000 --queue-bypass' "$TEMP/r2o-iptables.trace" || {
    echo "R2O iptables rules differ from D2O: missing IPv4 time-exceeded queue" >&2
    exit 1
}
grep -Fq -- '-p ipv6-icmp --icmpv6-type 3/0 -j NFQUEUE --queue-num 2001 --queue-bypass' "$TEMP/r2o-iptables.trace" || {
    echo "R2O ip6tables rules differ from D2O: missing IPv6 time-exceeded queue" >&2
    exit 1
}

echo "R2O IPv4 gate exclusions and D2O/R2O nft and iptables broadcast/multicast/ICMP rules match d2o $ACTUAL_D2O_SHA."
