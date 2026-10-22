#!/bin/sh
set -eu

ROOT=${R2O_DIR:-/opt/r2o}
CONF=${R2O_CONFIG:-$ROOT/config}
[ ! -r "$CONF" ] || . "$CONF"

QUEUE4=${QUEUE_NUM:-2000}
QUEUE6=${QUEUE_NUM6:-2001}
MARK=${MARK:-45}
TG_OUTBOUND_MARK=0x40000000
BACKEND=${FW_BACKEND:-auto}
IPV6_ENABLED=${IPV6_ENABLED:-1}
PORTS=${PORTS:-0:65535}
CONNBYTES=${CONNBYTES:-0:8}
VOICE_PORTS=${VOICE_PORTS:-50000:50099,1400,3478:3481,5349,19294:19344}
VOICE_CONNBYTES=${VOICE_CONNBYTES:-0:4}
HTTP_KEEPALIVE_PORTS=${HTTP_KEEPALIVE_PORTS:-80}
DNS_PORTS=${DNS_PORTS:-53,853}

number() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -le "$2" ]
}

number "$QUEUE4" 65535 || { echo "неверный QUEUE_NUM" >&2; exit 2; }
number "$QUEUE6" 65535 || { echo "неверный QUEUE_NUM6" >&2; exit 2; }
[ "$QUEUE4" != "$QUEUE6" ] || { echo "номера очередей IPv4 и IPv6 должны различаться" >&2; exit 2; }
case "$IPV6_ENABLED" in 0|1) ;; *) echo "IPV6_ENABLED должен быть равен 0 или 1" >&2; exit 2 ;; esac
for value in "$PORTS" "$VOICE_PORTS" "$HTTP_KEEPALIVE_PORTS" "$DNS_PORTS"; do
    case "$value" in ''|*[!0-9:,]*) echo "неверный список портов в конфигурации" >&2; exit 2 ;; esac
done
for value in "$CONNBYTES" "$VOICE_CONNBYTES"; do
    case "$value" in ''|*[!0-9:]*) echo "неверное окно соединения в конфигурации" >&2; exit 2 ;; esac
done
case "$MARK" in
    0x*|0X*) MARK=$(printf '%d' "$MARK") || exit 2 ;;
esac
number "$MARK" 4294967295 || { echo "неверная MARK" >&2; exit 2; }

case "$BACKEND" in
    nft|iptables) ;;
    auto)
        if command -v nft >/dev/null 2>&1 && { [ -f /etc/openwrt_release ] || [ "${R2O_PLATFORM:-}" = openwrt ]; }; then
            BACKEND=nft
        else
            BACKEND=iptables
        fi
        ;;
    *) echo "FW_BACKEND должен быть auto, nft или iptables" >&2; exit 2 ;;
esac

nft_up() {
    rules=${R2O_RUN_DIR:-$ROOT/run}/firewall.nft.$$
    nft_ports=$(printf '%s' "$PORTS" | sed -e 's/:/-/g' -e 's/,/, /g')
    nft_voice=$(printf '%s' "$VOICE_PORTS" | sed -e 's/:/-/g' -e 's/,/, /g')
    nft_keepalive=$(printf '%s' "$HTTP_KEEPALIVE_PORTS" | sed -e 's/:/-/g' -e 's/,/, /g')
    nft_dns=$(printf '%s' "$DNS_PORTS" | sed -e 's/:/-/g' -e 's/,/, /g')
    nft_window=$(printf '%s' "$CONNBYTES" | sed -e 's/^0:/1-/' -e 's/:/-/g')
    nft_voice_window=$(printf '%s' "$VOICE_CONNBYTES" | sed -e 's/^0:/1-/' -e 's/:/-/g')
    mkdir -p "$(dirname "$rules")"
    umask 077
    if nft list table inet r2o >/dev/null 2>&1; then
        if ! nft list table inet r2o 2>/dev/null | grep -F -q 'comment "r2o-managed"'; then
            echo "отказ: таблица nft inet r2o не принадлежит r2o" >&2
            return 1
        fi
        printf 'delete table inet r2o\n' > "$rules"
    else
        : > "$rules"
    fi
    cat >> "$rules" <<EOF
table inet r2o {
    comment "r2o-managed"
    chain out {
        type filter hook postrouting priority mangle; policy accept;
        ip saddr 127.0.0.0/8 return
        ip daddr 127.0.0.0/8 return
        ip6 saddr ::1 return
        ip6 daddr ::1 return
        meta mark $MARK return
        meta mark $TG_OUTBOUND_MARK return
        meta l4proto { tcp, udp } th dport { $nft_dns } return
        ct status dnat return
        meta nfproto ipv4 meta l4proto udp th dport { $nft_voice } ct direction original ct original packets $nft_voice_window queue num $QUEUE4 bypass
        meta nfproto ipv4 meta l4proto udp th dport { $nft_voice } return
        meta nfproto ipv6 meta l4proto udp th dport { $nft_voice } ct direction original ct original packets $nft_voice_window queue num $QUEUE6 bypass
        meta nfproto ipv6 meta l4proto udp th dport { $nft_voice } return
        meta nfproto ipv4 meta l4proto tcp th dport { $nft_ports } ct direction original ct original packets $nft_window queue num $QUEUE4 bypass
        meta nfproto ipv4 meta l4proto udp th dport { $nft_ports } ct direction original ct original packets $nft_window queue num $QUEUE4 bypass
        meta nfproto ipv6 meta l4proto tcp th dport { $nft_ports } ct direction original ct original packets $nft_window queue num $QUEUE6 bypass
        meta nfproto ipv6 meta l4proto udp th dport { $nft_ports } ct direction original ct original packets $nft_window queue num $QUEUE6 bypass
        meta nfproto ipv4 meta l4proto tcp ct direction original ct original packets 9-18446744073709551615 tcp flags & rst == rst queue num $QUEUE4 bypass
        meta nfproto ipv4 meta l4proto tcp ct direction original ct original packets 9-18446744073709551615 tcp flags & fin == fin queue num $QUEUE4 bypass
        meta nfproto ipv4 meta l4proto tcp th dport { $nft_keepalive } ct direction original ct original packets 9-18446744073709551615 queue num $QUEUE4 bypass
        meta nfproto ipv6 meta l4proto tcp ct direction original ct original packets 9-18446744073709551615 tcp flags & rst == rst queue num $QUEUE6 bypass
        meta nfproto ipv6 meta l4proto tcp ct direction original ct original packets 9-18446744073709551615 tcp flags & fin == fin queue num $QUEUE6 bypass
        meta nfproto ipv6 meta l4proto tcp th dport { $nft_keepalive } ct direction original ct original packets 9-18446744073709551615 queue num $QUEUE6 bypass
    }
    chain in_rules {
        ip saddr 127.0.0.0/8 return
        ip daddr 127.0.0.0/8 return
        ip6 saddr ::1 return
        ip6 daddr ::1 return
        meta l4proto { tcp, udp } th sport { $nft_dns } return
        ct status dnat return
        meta nfproto ipv4 meta l4proto udp th sport { $nft_voice } ct direction reply ct reply packets $nft_voice_window queue num $QUEUE4 bypass
        meta nfproto ipv4 meta l4proto udp th sport { $nft_voice } return
        meta nfproto ipv6 meta l4proto udp th sport { $nft_voice } ct direction reply ct reply packets $nft_voice_window queue num $QUEUE6 bypass
        meta nfproto ipv6 meta l4proto udp th sport { $nft_voice } return
        meta nfproto ipv4 meta l4proto tcp th sport { $nft_ports } ct direction reply ct reply packets $nft_window queue num $QUEUE4 bypass
        meta nfproto ipv4 meta l4proto udp th sport { $nft_ports } ct direction reply ct reply packets $nft_window queue num $QUEUE4 bypass
        meta nfproto ipv6 meta l4proto tcp th sport { $nft_ports } ct direction reply ct reply packets $nft_window queue num $QUEUE6 bypass
        meta nfproto ipv6 meta l4proto udp th sport { $nft_ports } ct direction reply ct reply packets $nft_window queue num $QUEUE6 bypass
        meta nfproto ipv4 meta l4proto tcp ct direction reply ct reply packets 9-18446744073709551615 tcp flags & rst == rst queue num $QUEUE4 bypass
        meta nfproto ipv4 meta l4proto tcp ct direction reply ct reply packets 9-18446744073709551615 tcp flags & fin == fin queue num $QUEUE4 bypass
        meta nfproto ipv4 meta l4proto tcp th sport { $nft_keepalive } ct direction reply ct reply packets 9-18446744073709551615 queue num $QUEUE4 bypass
        meta nfproto ipv6 meta l4proto tcp ct direction reply ct reply packets 9-18446744073709551615 tcp flags & rst == rst queue num $QUEUE6 bypass
        meta nfproto ipv6 meta l4proto tcp ct direction reply ct reply packets 9-18446744073709551615 tcp flags & fin == fin queue num $QUEUE6 bypass
        meta nfproto ipv6 meta l4proto tcp th sport { $nft_keepalive } ct direction reply ct reply packets 9-18446744073709551615 queue num $QUEUE6 bypass
    }
    chain forward {
        type filter hook forward priority mangle; policy accept;
        jump in_rules
    }
    chain input {
        type filter hook input priority mangle; policy accept;
        jump in_rules
    }
    chain nat_post {
        type nat hook postrouting priority srcnat - 1; policy accept;
        meta nfproto ipv4 meta l4proto udp meta mark $MARK masquerade
    }
}
EOF
    nft -f "$rules"
    rm -f "$rules"
}

nft_down() {
    nft list table inet r2o >/dev/null 2>&1 || return 0
    if ! nft list table inet r2o 2>/dev/null | grep -F -q 'comment "r2o-managed"'; then
            echo "отказ: таблица nft inet r2o не принадлежит r2o" >&2
        return 1
    fi
    nft delete table inet r2o
}

xt() {
    tool=$1
    shift
    "$tool" -w "$@" 2>/dev/null && return 0
    rc=$?
    [ "$rc" = 2 ] || return "$rc"
    "$tool" "$@"
}

xt_family_down() {
    tool=$1
    for hook in POSTROUTING FORWARD INPUT; do
        while xt "$tool" -t mangle -D "$hook" -j R2O_OUT 2>/dev/null; do :; done
        while xt "$tool" -t mangle -D "$hook" -j R2O_IN 2>/dev/null; do :; done
    done
    for chain in R2O_OUT R2O_IN; do
        xt "$tool" -t mangle -F "$chain" 2>/dev/null || true
        xt "$tool" -t mangle -X "$chain" 2>/dev/null || true
    done
    if [ "$tool" = iptables ]; then
        while xt "$tool" -t nat -D POSTROUTING -p udp -m mark --mark "$MARK" -j MASQUERADE 2>/dev/null; do :; done
    fi
    return 0
}

xt_family_up() {
    tool=$1
    queue=$2
    loopback=127.0.0.0/8
    [ "$tool" != ip6tables ] || loopback=::1/128
    xt "$tool" -t mangle -N R2O_OUT
    xt "$tool" -t mangle -N R2O_IN
    for chain in R2O_OUT R2O_IN; do
        xt "$tool" -t mangle -A "$chain" -s "$loopback" -j RETURN
        xt "$tool" -t mangle -A "$chain" -d "$loopback" -j RETURN
        xt "$tool" -t mangle -A "$chain" -m conntrack --ctstate DNAT -j RETURN
    done
    xt "$tool" -t mangle -A R2O_OUT -m mark --mark "$MARK" -j RETURN
    xt "$tool" -t mangle -A R2O_OUT -m mark --mark "$TG_OUTBOUND_MARK" -j RETURN
    for proto in tcp udp; do
        xt "$tool" -t mangle -A R2O_OUT -p "$proto" -m multiport --dports 53,853 -j RETURN
        xt "$tool" -t mangle -A R2O_IN -p "$proto" -m multiport --sports 53,853 -j RETURN
    done
    voice_ports=$VOICE_PORTS
    for proto in tcp udp; do
        if [ "$proto" = udp ]; then
            xt "$tool" -t mangle -A R2O_OUT -p udp -m multiport --dports "$voice_ports" \
                -m conntrack --ctdir ORIGINAL -m connbytes --connbytes "$VOICE_CONNBYTES" --connbytes-dir original --connbytes-mode packets \
                -j NFQUEUE --queue-num "$queue" --queue-bypass
            xt "$tool" -t mangle -A R2O_OUT -p udp -m multiport --dports "$voice_ports" -j RETURN
            xt "$tool" -t mangle -A R2O_IN -p udp -m multiport --sports "$voice_ports" \
                -m conntrack --ctdir REPLY -m connbytes --connbytes "$VOICE_CONNBYTES" --connbytes-dir reply --connbytes-mode packets \
                -j NFQUEUE --queue-num "$queue" --queue-bypass
            xt "$tool" -t mangle -A R2O_IN -p udp -m multiport --sports "$voice_ports" -j RETURN
        fi
        xt "$tool" -t mangle -A R2O_OUT -p "$proto" -m conntrack --ctdir ORIGINAL \
            -m connbytes --connbytes "$CONNBYTES" --connbytes-dir original --connbytes-mode packets \
            -j NFQUEUE --queue-num "$queue" --queue-bypass
        xt "$tool" -t mangle -A R2O_IN -p "$proto" -m conntrack --ctdir REPLY \
            -m connbytes --connbytes "$CONNBYTES" --connbytes-dir reply --connbytes-mode packets \
            -j NFQUEUE --queue-num "$queue" --queue-bypass
    done
    for direction in OUT IN; do
        chain=R2O_$direction
        if [ "$direction" = OUT ]; then ct_direction=ORIGINAL; count_direction=original; ports=--dports; else ct_direction=REPLY; count_direction=reply; ports=--sports; fi
        for flag in RST FIN; do
            xt "$tool" -t mangle -A "$chain" -p tcp -m conntrack --ctdir "$ct_direction" \
                -m connbytes --connbytes 9: --connbytes-dir "$count_direction" --connbytes-mode packets \
                --tcp-flags "$flag" "$flag" -j NFQUEUE --queue-num "$queue" --queue-bypass
        done
        keepalive_port=80
        xt "$tool" -t mangle -A "$chain" -p tcp -m multiport "$ports" "$HTTP_KEEPALIVE_PORTS" \
            -m conntrack --ctdir "$ct_direction" \
            -m connbytes --connbytes 9: --connbytes-dir "$count_direction" --connbytes-mode packets \
            -j NFQUEUE --queue-num "$queue" --queue-bypass
    done
    if [ "$tool" = iptables ]; then
        xt "$tool" -t nat -A POSTROUTING -p udp -m mark --mark "$MARK" -j MASQUERADE
    fi
    xt "$tool" -t mangle -I POSTROUTING 1 -j R2O_OUT
    xt "$tool" -t mangle -I FORWARD 1 -j R2O_IN
    xt "$tool" -t mangle -I INPUT 1 -j R2O_IN
}

iptables_up() {
    xt_family_down iptables
    [ "$IPV6_ENABLED" = 0 ] || xt_family_down ip6tables
    xt_family_up iptables "$QUEUE4" || { xt_family_down iptables; return 1; }
    if [ "$IPV6_ENABLED" = 1 ]; then
        xt_family_up ip6tables "$QUEUE6" || {
            xt_family_down ip6tables
            xt_family_down iptables
            return 1
        }
    fi
}

case "${1:-}" in
    up)
        if [ "$BACKEND" = nft ]; then nft_up; else iptables_up; fi
        ;;
    down)
        if [ "$BACKEND" = nft ]; then nft_down; else
            xt_family_down iptables
            [ "$IPV6_ENABLED" = 0 ] || xt_family_down ip6tables
        fi
        ;;
    status)
        if [ "$BACKEND" = nft ]; then nft list table inet r2o; else
            xt iptables -t mangle -C POSTROUTING -j R2O_OUT &&
                { [ "$IPV6_ENABLED" = 0 ] || xt ip6tables -t mangle -C POSTROUTING -j R2O_OUT; }
        fi
        ;;
    *) echo "использование: $0 {up|down|status}" >&2; exit 2 ;;
esac
