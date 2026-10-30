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
IPV6_ENABLED_CONFIG=${IPV6_ENABLED:-1}
IPV6_ENABLED=$IPV6_ENABLED_CONFIG
IPV6_ENABLED=${R2O_IPV6_ENABLED_RUNTIME:-$IPV6_ENABLED}
PORTS=${PORTS:-0:65535}
CONNBYTES=${CONNBYTES:-0:8}
VOICE_PORTS=${VOICE_PORTS:-50000:50099,1400,3478:3481,5349,19294:19344}
VOICE_CONNBYTES=${VOICE_CONNBYTES:-0:4}
HTTP_KEEPALIVE_PORTS=${HTTP_KEEPALIVE_PORTS:-80}
DNS_PORTS=${DNS_PORTS:-53,853}
RUN_DIR=${R2O_RUN_DIR:-$ROOT/run}
FW_LOCK=${R2O_FIREWALL_LOCK:-$RUN_DIR/firewall-operation.lock}
FW_V4ONLY=$RUN_DIR/fw-ipv4-only
PROC_DIR=${R2O_PROC_DIR:-/proc}
SYS_MODULE_DIR=${R2O_SYS_MODULE_DIR:-/sys/module}
MODULES_DIR=${R2O_MODULES_DIR:-/lib/modules}

number() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -le "$2" ]
}

number "$QUEUE4" 65535 || { echo "неверный QUEUE_NUM" >&2; exit 2; }
number "$QUEUE6" 65535 || { echo "неверный QUEUE_NUM6" >&2; exit 2; }
[ "$QUEUE4" != "$QUEUE6" ] || { echo "номера очередей IPv4 и IPv6 должны различаться" >&2; exit 2; }
case "$IPV6_ENABLED_CONFIG" in 0|1) ;; *) echo "IPV6_ENABLED должен быть равен 0 или 1" >&2; exit 2 ;; esac
case "$IPV6_ENABLED" in 0|1) ;; *) echo "R2O_IPV6_ENABLED_RUNTIME должен быть равен 0 или 1" >&2; exit 2 ;; esac
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

ipv6_mangle_available() {
    command -v ip6tables >/dev/null 2>&1 || return 1
    if ip6tables -w -t mangle -n -L POSTROUTING >/dev/null 2>&1; then return 0; else ipv6_probe_rc=$?; fi
    [ "$ipv6_probe_rc" = 2 ] || return 1
    ip6tables -t mangle -n -L POSTROUTING >/dev/null 2>&1
}

ipv6_mangle_wait_probe() {
    command -v ip6tables >/dev/null 2>&1 || return 1
    ip6tables -w -t mangle -n -L POSTROUTING >/dev/null 2>&1
}

if [ "$BACKEND" = nft ]; then
    R2O_MODULES='nfnetlink_queue nft_queue nf_conntrack_netlink'
else
    R2O_MODULES='nfnetlink_queue xt_NFQUEUE xt_conntrack xt_connbytes xt_multiport xt_mark xt_connmark xt_CONNMARK xt_addrtype xt_comment ip6table_mangle nf_conntrack_netlink'
fi

module_present() {
    case "$1" in
        xt_NFQUEUE|xt_CONNMARK)
            grep -qw "${1#xt_}" "$PROC_DIR/net/ip_tables_targets" 2>/dev/null && return 0 ;;
        nfnetlink_queue) [ -e "$PROC_DIR/net/netfilter/nfnetlink_queue" ] && return 0 ;;
        ip6table_mangle) grep -qw mangle "$PROC_DIR/net/ip6_tables_names" 2>/dev/null && return 0 ;;
        xt_*) grep -qw "${1#xt_}" "$PROC_DIR/net/ip_tables_matches" 2>/dev/null && return 0 ;;
    esac
    [ -d "$SYS_MODULE_DIR/$1" ] && return 0
    lsmod 2>/dev/null | grep -q "^$1 "
}

load_modules() {
    module_kver=$(uname -r 2>/dev/null)
    for module_name in $R2O_MODULES; do
        module_present "$module_name" && continue
        modprobe "$module_name" 2>/dev/null && module_present "$module_name" && continue
        module_ko=
        for module_dir in "$MODULES_DIR/$module_kver" "$MODULES_DIR"; do
            if [ -f "$module_dir/$module_name.ko" ]; then
                module_ko=$module_dir/$module_name.ko
                break
            fi
        done
        if [ -z "$module_ko" ]; then
            module_ko=$(find "$MODULES_DIR" -name "$module_name.ko" -type f 2>/dev/null | head -1)
        fi
        if [ -n "$module_ko" ] && insmod "$module_ko" 2>/dev/null; then
            echo "r2o: загружен модуль ядра $module_name" >&2
        fi
    done
}

if [ "${1:-}" = up ]; then
    load_modules
fi

if [ "$BACKEND" = iptables ] && [ "$IPV6_ENABLED" = 1 ] && ! ipv6_mangle_available; then
    IPV6_ENABLED=0
fi

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
    nft -f "$rules" || { rm -f "$rules"; return 1; }
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

nft_main_down() {
    if nft list table inet r2o >/dev/null 2>&1; then
        if ! nft list table inet r2o 2>/dev/null | grep -F -q 'comment "r2o-managed"'; then
            echo "отказ: таблица nft inet r2o не принадлежит r2o" >&2
            return 1
        fi
        nft delete table inet r2o || return 1
    fi
}

nft_down() {
    nft_main_down
}

firewall_rst_down() {
    fw_lock_acquire || return 1
    if nft_rst_down; then fw_rc=0; else fw_rc=$?; fi
    fw_lock_release || return 1
    return "$fw_rc"
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
    case "$2" in
        *:*)
            dns_tool=ip6tables
            [ "$IPV6_ENABLED" = 1 ] && [ ! -f "$FW_V4ONLY" ] || return 0
            ;;
    esac
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

xt_legacy_d2k_family_down() {
    tool=$1
    while xt "$tool" -t nat -D PREROUTING -j D2K_HTTP 2>/dev/null; do :; done
    if xt "$tool" -t nat -n -L D2K_HTTP >/dev/null 2>&1; then
        xt "$tool" -t nat -F D2K_HTTP 2>/dev/null || true
        xt "$tool" -t nat -X D2K_HTTP 2>/dev/null || true
    fi
    while xt "$tool" -t nat -D POSTROUTING -p udp -m mark --mark "$MARK" \
        -j MASQUERADE 2>/dev/null; do :; done
    while xt "$tool" -t mangle -D OUTPUT -m mark --mark 0x30 \
        -j CONNMARK --save-mark 2>/dev/null; do :; done
    while xt "$tool" -t mangle -D OUTPUT -j D2K_HTTP_MARK 2>/dev/null; do :; done
    if xt "$tool" -t mangle -n -L D2K_HTTP_MARK >/dev/null 2>&1; then
        xt "$tool" -t mangle -F D2K_HTTP_MARK 2>/dev/null || true
        xt "$tool" -t mangle -X D2K_HTTP_MARK 2>/dev/null || true
    fi
    for hook in POSTROUTING FORWARD OUTPUT INPUT; do
        for chain in D2K_OUT D2K_IN; do
            while xt "$tool" -t mangle -D "$hook" -j "$chain" 2>/dev/null; do :; done
        done
    done
    for chain in D2K_OUT D2K_IN; do
        if xt "$tool" -t mangle -n -L "$chain" >/dev/null 2>&1; then
            xt "$tool" -t mangle -F "$chain" 2>/dev/null || true
            xt "$tool" -t mangle -X "$chain" 2>/dev/null || true
        fi
    done
}

xt_family_up() {
    tool=$1
    queue=$2
    loopback=127.0.0.0/8
    [ "$tool" != ip6tables ] || loopback=::1/128
    if ! xt "$tool" -t mangle -N R2O_OUT; then
        if [ "$tool" = ip6tables ] && ! ipv6_mangle_wait_probe; then return 3; fi
        return 1
    fi
    xt "$tool" -t mangle -N R2O_IN || return 1
    for chain in R2O_OUT R2O_IN; do
        xt "$tool" -t mangle -A "$chain" -s "$loopback" -j RETURN || return 1
        xt "$tool" -t mangle -A "$chain" -d "$loopback" -j RETURN || return 1
        xt "$tool" -t mangle -A "$chain" -m conntrack --ctstate DNAT -j RETURN || return 1
    done
    if [ "$tool" = iptables ]; then
        xt_broadcast_return "$tool" || return 1
        xt "$tool" -t mangle -A R2O_OUT -d 224.0.0.0/4 -j RETURN || return 1
    else
        xt "$tool" -t mangle -A R2O_OUT -d ff00::/8 -j RETURN || return 1
    fi
    xt "$tool" -t mangle -A R2O_OUT -m mark --mark "$MARK" -j RETURN || return 1
    xt "$tool" -t mangle -A R2O_OUT -m mark --mark "$TG_OUTBOUND_MARK" -j RETURN || return 1
    for proto in tcp udp; do
        xt "$tool" -t mangle -A R2O_OUT -p "$proto" -m multiport --dports 53,853 -j RETURN || return 1
        xt "$tool" -t mangle -A R2O_IN -p "$proto" -m multiport --sports 53,853 -j RETURN || return 1
    done
    voice_ports=$VOICE_PORTS
    for proto in tcp udp; do
        if [ "$proto" = udp ]; then
            xt "$tool" -t mangle -A R2O_OUT -p udp -m multiport --dports "$voice_ports" \
                -m conntrack --ctdir ORIGINAL -m connbytes --connbytes "$VOICE_CONNBYTES" --connbytes-dir original --connbytes-mode packets \
                -j NFQUEUE --queue-num "$queue" --queue-bypass || return 1
            xt "$tool" -t mangle -A R2O_OUT -p udp -m multiport --dports "$voice_ports" -j RETURN || return 1
            xt "$tool" -t mangle -A R2O_IN -p udp -m multiport --sports "$voice_ports" \
                -m conntrack --ctdir REPLY -m connbytes --connbytes "$VOICE_CONNBYTES" --connbytes-dir reply --connbytes-mode packets \
                -j NFQUEUE --queue-num "$queue" --queue-bypass || return 1
            xt "$tool" -t mangle -A R2O_IN -p udp -m multiport --sports "$voice_ports" -j RETURN || return 1
        fi
        xt "$tool" -t mangle -A R2O_OUT -p "$proto" -m conntrack --ctdir ORIGINAL \
            -m connbytes --connbytes "$CONNBYTES" --connbytes-dir original --connbytes-mode packets \
            -j NFQUEUE --queue-num "$queue" --queue-bypass || return 1
        xt "$tool" -t mangle -A R2O_IN -p "$proto" -m conntrack --ctdir REPLY \
            -m connbytes --connbytes "$CONNBYTES" --connbytes-dir reply --connbytes-mode packets \
            -j NFQUEUE --queue-num "$queue" --queue-bypass || return 1
    done
    for direction in OUT IN; do
        chain=R2O_$direction
        if [ "$direction" = OUT ]; then ct_direction=ORIGINAL; count_direction=original; ports=--dports; else ct_direction=REPLY; count_direction=reply; ports=--sports; fi
        for flag in RST FIN; do
            xt "$tool" -t mangle -A "$chain" -p tcp -m conntrack --ctdir "$ct_direction" \
                -m connbytes --connbytes 9: --connbytes-dir "$count_direction" --connbytes-mode packets \
                --tcp-flags "$flag" "$flag" -j NFQUEUE --queue-num "$queue" --queue-bypass || return 1
        done
        xt "$tool" -t mangle -A "$chain" -p tcp -m multiport "$ports" "$HTTP_KEEPALIVE_PORTS" \
            -m conntrack --ctdir "$ct_direction" \
            -m connbytes --connbytes 9: --connbytes-dir "$count_direction" --connbytes-mode packets \
            -j NFQUEUE --queue-num "$queue" --queue-bypass || return 1
    done
    if [ "$tool" = iptables ]; then
        xt "$tool" -t mangle -A R2O_IN -p icmp --icmp-type 11/0 \
            -j NFQUEUE --queue-num "$queue" --queue-bypass || return 1
    else
        xt "$tool" -t mangle -A R2O_IN -p ipv6-icmp --icmpv6-type 3/0 \
            -j NFQUEUE --queue-num "$queue" --queue-bypass || return 1
    fi
    if [ "$tool" = iptables ]; then
        xt "$tool" -t nat -A POSTROUTING -p udp -m mark --mark "$MARK" -j MASQUERADE || return 1
    fi
    xt "$tool" -t mangle -I POSTROUTING 1 -j R2O_OUT || return 1
    xt "$tool" -t mangle -I FORWARD 1 -j R2O_IN || return 1
    xt "$tool" -t mangle -I INPUT 1 -j R2O_IN || return 1
}

iptables_up() {
    xt_family_down iptables
    xt_legacy_d2k_family_down iptables
    if command -v ip6tables >/dev/null 2>&1; then
        xt_family_down ip6tables
        xt_legacy_d2k_family_down ip6tables
    fi
    rm -f "$FW_V4ONLY"
    xt_family_up iptables "$QUEUE4" || { xt_family_down iptables; return 1; }
    if [ "$IPV6_ENABLED_CONFIG" = 1 ] && [ "$IPV6_ENABLED" = 0 ]; then
        mkdir -p "$RUN_DIR" && : > "$FW_V4ONLY" || return 1
        echo "r2o: ВНИМАНИЕ: ip6tables mangle недоступна (нет IPv6 в прошивке или модуля ip6table_mangle) — работает только IPv4" >&2
    elif [ "$IPV6_ENABLED" = 1 ]; then
        if xt_family_up ip6tables "$QUEUE6"; then
            rm -f "$FW_V4ONLY"
        else
            ipv6_up_rc=$?
            if [ "$ipv6_up_rc" = 3 ]; then
                xt_family_down ip6tables
                mkdir -p "$RUN_DIR" && : > "$FW_V4ONLY" || return 1
                echo "r2o: ВНИМАНИЕ: ip6tables mangle недоступна (нет IPv6 в прошивке или модуля ip6table_mangle) — работает только IPv4" >&2
            else
                xt_family_down ip6tables
                xt_family_down iptables
                return 1
            fi
        fi
    fi
}

firewall_up() {
    fw_lock_acquire || return 1
    if [ "$BACKEND" = nft ]; then
        rm -f "$FW_V4ONLY" || true
        xt_family_down iptables
        xt_legacy_d2k_family_down iptables
        if command -v ip6tables >/dev/null 2>&1; then
            xt_family_down ip6tables
            xt_legacy_d2k_family_down ip6tables
        fi
        if nft list table inet r2o_rst >/dev/null 2>&1; then fw_rst_preexisting=1; else fw_rst_preexisting=0; fi
        if nft_up; then
            fw_rc=0
        else
            fw_rc=$?
            nft_main_down || echo "r2o: не удалось снять старую таблицу nft после отказа установки" >&2
            if [ "$fw_rst_preexisting" = 0 ]; then
                nft_rst_down || echo "r2o: не удалось снять новую RST таблицу nft после отказа установки" >&2
            fi
        fi
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
        xt_family_down iptables
        xt_legacy_d2k_family_down iptables
        if command -v ip6tables >/dev/null 2>&1; then
            xt_family_down ip6tables
            xt_legacy_d2k_family_down ip6tables
        fi
        if nft_down; then fw_rc=0; else fw_rc=$?; fi
    else
        xt_family_down iptables
        xt_legacy_d2k_family_down iptables
        if command -v ip6tables >/dev/null 2>&1; then
            xt_family_down ip6tables
            xt_legacy_d2k_family_down ip6tables
        fi
        fw_rc=0
    fi
    rm -f "$FW_V4ONLY" || true
    fw_lock_release || return 1
    return "$fw_rc"
}

case "${1:-}" in
    backend)
        printf '%s\n' "$BACKEND"
        ;;
    ipv6-enabled)
        if [ "$BACKEND" = iptables ] && [ -f "$FW_V4ONLY" ]; then
            printf '0\n'
        else
            printf '%s\n' "$IPV6_ENABLED"
        fi
        ;;
    up)
        firewall_up
        ;;
    down)
        firewall_down
        ;;
    rst-down)
        firewall_rst_down
        ;;
    status)
        if [ "$BACKEND" = nft ]; then nft list table inet r2o; else
            xt iptables -t mangle -C POSTROUTING -j R2O_OUT &&
                { [ "$IPV6_ENABLED_CONFIG" = 0 ] || [ -f "$FW_V4ONLY" ] ||
                    xt ip6tables -t mangle -C POSTROUTING -j R2O_OUT; }
        fi
        ;;
    dns-ensure)
        dns_excl_sync
        ;;
    *) echo "использование: $0 {backend|ipv6-enabled|up|down|rst-down|status|dns-ensure}" >&2; exit 2 ;;
esac
