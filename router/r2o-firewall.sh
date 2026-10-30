#!/bin/sh
set -eu

ROOT=${R2O_DIR:-/opt/r2o}
CONF=${R2O_CONFIG:-$ROOT/config}
# shellcheck disable=SC1090 # the config path is selected by the runtime environment
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
RUN_DIR=${R2O_RUN_DIR:-$ROOT/run}
FW_LOCK=${R2O_FIREWALL_LOCK:-$RUN_DIR/firewall-operation.lock}

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
        meta nfproto ipv4 fib daddr type broadcast return
        ip daddr 224.0.0.0/4 return
        ip6 daddr ff00::/8 return
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
        icmp type time-exceeded icmp code 0 queue num $QUEUE4 bypass
        icmpv6 type time-exceeded icmpv6 code 0 queue num $QUEUE6 bypass
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
    nft_rst_up || { rm -f "$rules"; return 1; }
    nft -f "$rules"
    rm -f "$rules"
}

nft_rst_up() {
    rst_rules=${R2O_RUN_DIR:-$ROOT/run}/firewall-rst.nft.$$
    mkdir -p "$(dirname "$rst_rules")"
    umask 077
    : > "$rst_rules"
    if nft list table inet r2o_rst >/dev/null 2>&1; then
        if ! nft list table inet r2o_rst 2>/dev/null | grep -F -q 'comment "r2o-managed"'; then
            echo "отказ: таблица nft inet r2o_rst не принадлежит r2o" >&2
            rm -f "$rst_rules"
            return 1
        fi
    else
        cat >> "$rst_rules" <<'EOF'
add table inet r2o_rst { comment "r2o-managed"; }
EOF
    fi
    if ! nft list set inet r2o_rst rst4 >/dev/null 2>&1; then
        cat >> "$rst_rules" <<'EOF'
add set inet r2o_rst rst4 { type inet_service . ipv4_addr . inet_service; flags timeout; timeout 30s; }
EOF
    fi
    if ! nft list set inet r2o_rst rst6 >/dev/null 2>&1; then
        cat >> "$rst_rules" <<'EOF'
add set inet r2o_rst rst6 { type inet_service . ipv6_addr . inet_service; flags timeout; timeout 30s; }
EOF
    fi
    if ! nft list chain inet r2o_rst output >/dev/null 2>&1; then
        cat >> "$rst_rules" <<'EOF'
add chain inet r2o_rst output { type filter hook output priority filter; policy accept; }
add rule inet r2o_rst output tcp flags & rst == rst tcp sport . ip daddr . tcp dport @rst4 drop
add rule inet r2o_rst output tcp flags & rst == rst tcp sport . ip6 daddr . tcp dport @rst6 drop
EOF
    fi
    if [ -s "$rst_rules" ]; then nft -f "$rst_rules" || { rm -f "$rst_rules"; return 1; }; fi
    rm -f "$rst_rules"
}

nft_rst_down() {
    nft list table inet r2o_rst >/dev/null 2>&1 || return 0
    if ! nft list table inet r2o_rst 2>/dev/null | grep -F -q 'comment "r2o-managed"'; then
        echo "отказ: таблица nft inet r2o_rst не принадлежит r2o" >&2
        return 1
    fi
    nft delete table inet r2o_rst
}

nft_down() {
    if nft list table inet r2o >/dev/null 2>&1; then
        if ! nft list table inet r2o 2>/dev/null | grep -F -q 'comment "r2o-managed"'; then
            echo "отказ: таблица nft inet r2o не принадлежит r2o" >&2
            return 1
        fi
        nft delete table inet r2o || return 1
    fi
    nft_rst_down
}

xt() {
    tool=$1
    shift
    "$tool" -w "$@" 2>/dev/null && return 0
    rc=$?
    [ "$rc" = 2 ] || return "$rc"
    "$tool" "$@"
}

fw_lock_acquire() {
    mkdir -p "$(dirname "$FW_LOCK")" || return 1
    fw_lock_attempt=0
    while ! mkdir "$FW_LOCK" 2>/dev/null; do
        fw_lock_owner=$(cat "$FW_LOCK/pid" 2>/dev/null)
        case "$fw_lock_owner" in
            ''|*[!0-9]*) ;;
            *)
                if ! kill -0 "$fw_lock_owner" 2>/dev/null; then
                    rm -f "$FW_LOCK/pid" 2>/dev/null
                    rmdir "$FW_LOCK" 2>/dev/null
                    continue
                fi ;;
        esac
        [ "$fw_lock_attempt" -lt 300 ] || return 1
        fw_lock_attempt=$((fw_lock_attempt + 1))
        sleep 0.1 2>/dev/null || sleep 1
    done
    printf '%s\n' "$$" > "$FW_LOCK/pid" || { rmdir "$FW_LOCK"; return 1; }
}

fw_lock_release() {
    [ "$(cat "$FW_LOCK/pid" 2>/dev/null)" = "$$" ] || return 1
    rm -f "$FW_LOCK/pid"
    rmdir "$FW_LOCK"
}

dns_upstreams() {
    command -v ndmc >/dev/null 2>&1 || return 0
    ndmc -c "show dns-proxy" 2>/dev/null | tr -d '\033\r' | awk '
        function emit(s, def,    host, port, t) {
            host = s; port = def; t = s
            if (s ~ /^\[/) {
                sub(/^\[/, "", host); sub(/\].*/, "", host)
                if (s ~ /\]:[0-9]+$/) { port = s; sub(/.*\]:/, "", port) }
            } else if (gsub(/:/, ":", t) == 1) {
                sub(/:.*/, "", host); port = s; sub(/.*:/, "", port)
            }
            if (host != "" && port ~ /^[0-9]+$/) print host, port
        }
        $1 == "dns_server" && $2 == "=" {
            a = $3
            if (a !~ /^127\./ && a !~ /^\[?::1\]?(:|$)/) emit(a, 53)
            c = ""
            for (i = 4; i < NF; i++) if ($i == "#") { c = $(i + 1); break }
            if (c == "") next
            sub(/@.*/, "", c)
            if (c ~ /^https:\/\//) { sub(/^https:\/\//, "", c); sub(/\/.*/, "", c); emit(c, 443) }
            else { sub(/^tls:\/\//, "", c); emit(c, 853) }
        }'
}

dns_excl_rule() {
    dns_tool=iptables
    case "$2" in *:*) dns_tool=ip6tables; [ "$IPV6_ENABLED" = 1 ] || return 0 ;; esac
    for dns_proto in tcp udp; do
        for dns_direction in out in; do
            if [ "$dns_direction" = out ]; then
                set -- "$1" "$2" "$3" R2O_OUT -d --dport
            else
                set -- "$1" "$2" "$3" R2O_IN -s --sport
            fi
            if [ "$1" = -D ]; then
                while xt "$dns_tool" -t mangle -C "$4" -p "$dns_proto" "$5" "$2" "$6" "$3" -j RETURN; do
                    xt "$dns_tool" -t mangle -D "$4" -p "$dns_proto" "$5" "$2" "$6" "$3" -j RETURN || break
                done
            else
                xt "$dns_tool" -t mangle -C "$4" -p "$dns_proto" "$5" "$2" "$6" "$3" -j RETURN ||
                    xt "$dns_tool" -t mangle -I "$4" -p "$dns_proto" "$5" "$2" "$6" "$3" -j RETURN
            fi
        done
    done
}

dns_excl_sync_unlocked() {
    [ "$BACKEND" = iptables ] || return 0
    mkdir -p "$RUN_DIR" || return 1
    dns_state=$RUN_DIR/dns-excl
    dns_new=$dns_state.new
    dns_upstreams | while read -r dns_host dns_port; do
        case "$dns_host" in
            *:*|*[!0-9.]*) ;;
            *) printf '%s %s %s\n' "$dns_host" "$dns_host" "$dns_port"; continue ;;
        esac
        case "$dns_host" in *:*) printf '%s %s %s\n' "$dns_host" "$dns_host" "$dns_port"; continue ;; esac
        dns_ips=$(nslookup "$dns_host" 127.0.0.1 2>/dev/null |
            awk '/^Name:/ { n = 1; next } n && /^Address/ { print $3 }')
        if [ -n "$dns_ips" ]; then
            for dns_ip in $dns_ips; do printf '%s %s %s\n' "$dns_host" "$dns_ip" "$dns_port"; done
        elif [ -f "$dns_state" ]; then
            awk -v h="$dns_host" '$1 == h' "$dns_state"
        fi
    done | sort -u > "$dns_new" || { rm -f "$dns_new"; return 1; }
    if [ "${1:-}" != fresh ] && [ -f "$dns_state" ]; then
        while read -r dns_host dns_ip dns_port; do
            awk -v a="$dns_ip" -v p="$dns_port" '$2 == a && $3 == p { f = 1 } END { exit !f }' "$dns_new" ||
                dns_excl_rule -D "$dns_ip" "$dns_port"
        done < "$dns_state"
    fi
    while read -r dns_host dns_ip dns_port; do dns_excl_rule -A "$dns_ip" "$dns_port"; done < "$dns_new"
    mv -f "$dns_new" "$dns_state"
}

dns_excl_sync() {
    fw_lock_acquire || return 1
    dns_excl_sync_unlocked || true
    fw_lock_release
}

xt_broadcast_return() {
    tool=$1
    if xt "$tool" -t mangle -A R2O_OUT -m addrtype --dst-type BROADCAST -j RETURN; then
        return 0
    fi
    echo "в прошивке нет xt_addrtype: широковещательные адреса исключаю явным списком" >&2
    xt "$tool" -t mangle -A R2O_OUT -d 255.255.255.255 -j RETURN || return 1
    for address in $(ip -4 addr show 2>/dev/null | awk '$1 == "inet" { for (i = 1; i < NF; i++) if ($i == "brd") print $(i + 1) }' | sort -u); do
        xt "$tool" -t mangle -A R2O_OUT -d "$address" -j RETURN || return 1
    done
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
    if [ "$tool" = iptables ]; then
        xt_broadcast_return "$tool" || return 1
        xt "$tool" -t mangle -A R2O_OUT -d 224.0.0.0/4 -j RETURN || return 1
    else
        xt "$tool" -t mangle -A R2O_OUT -d ff00::/8 -j RETURN || return 1
    fi
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
        xt "$tool" -t mangle -A "$chain" -p tcp -m multiport "$ports" "$HTTP_KEEPALIVE_PORTS" \
            -m conntrack --ctdir "$ct_direction" \
            -m connbytes --connbytes 9: --connbytes-dir "$count_direction" --connbytes-mode packets \
            -j NFQUEUE --queue-num "$queue" --queue-bypass
    done
    if [ "$tool" = iptables ]; then
        xt "$tool" -t mangle -A R2O_IN -p icmp --icmp-type 11/0 \
            -j NFQUEUE --queue-num "$queue" --queue-bypass || return 1
    else
        xt "$tool" -t mangle -A R2O_IN -p ipv6-icmp --icmpv6-type 3/0 \
            -j NFQUEUE --queue-num "$queue" --queue-bypass || return 1
    fi
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

firewall_up() {
    fw_lock_acquire || return 1
    if [ "$BACKEND" = nft ]; then
        if nft_up; then fw_rc=0; else fw_rc=$?; fi
    elif iptables_up; then
        fw_rc=0
        dns_excl_sync_unlocked fresh || echo "r2o: исключение DNS-upstream не встало полностью" >&2
    else
        fw_rc=$?
    fi
    fw_lock_release || return 1
    return "$fw_rc"
}

firewall_down() {
    fw_lock_acquire || return 1
    if [ "$BACKEND" = nft ]; then
        if nft_down; then fw_rc=0; else fw_rc=$?; fi
    else
        xt_family_down iptables
        if [ "$IPV6_ENABLED" = 0 ] || xt_family_down ip6tables; then fw_rc=0; else fw_rc=$?; fi
    fi
    fw_lock_release || return 1
    return "$fw_rc"
}

case "${1:-}" in
    backend)
        printf '%s\n' "$BACKEND"
        ;;
    up)
        firewall_up
        ;;
    down)
        firewall_down
        ;;
    status)
        if [ "$BACKEND" = nft ]; then nft list table inet r2o; else
            xt iptables -t mangle -C POSTROUTING -j R2O_OUT &&
                { [ "$IPV6_ENABLED" = 0 ] || xt ip6tables -t mangle -C POSTROUTING -j R2O_OUT; }
        fi
        ;;
    dns-ensure)
        dns_excl_sync
        ;;
    *) echo "использование: $0 {backend|up|down|status|dns-ensure}" >&2; exit 2 ;;
esac
