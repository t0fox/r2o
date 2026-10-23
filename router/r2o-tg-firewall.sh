#!/bin/sh
# Правила перенаправления TCP-трафика Telegram для IPv4 и IPv6.
set -eu

ROOT=${R2O_DIR:-/opt/r2o}
CONF=${R2O_CONFIG:-$ROOT/config}
# shellcheck disable=SC1090 # the config path is selected by the runtime environment
[ ! -r "$CONF" ] || . "$CONF"

SET4=r2o_tg_dc
SET6=r2o_tg_dc6
PAIR4=r2o_tg_pair4
PAIR6=r2o_tg_pair6
DC_MAP_ENDPOINTS=${R2O_TG_DC_MAP_ENDPOINTS_PATH:-$ROOT/state/telegram-dc-endpoints.tsv}
PORT=${TG_PORT:-1443}
TCP_PORTS="443 5222"
OUTBOUND_MARK=0x40000000
LEGACY_OUTBOUND_MARK=0x31
OUTBOUND_COMMENT=r2o-tg-outbound
CIDRS4="149.154.160.0/20 91.108.4.0/22 91.108.8.0/22 91.108.12.0/22 91.108.16.0/22 91.108.20.0/22 91.108.56.0/22 91.105.192.0/23 95.161.64.0/20 185.76.151.0/24"
CIDRS6="2001:67c:4e8::/48 2001:b28:f23c::/47 2001:b28:f23f::/48 2a0a:f280:203::/48"

ipt() { iptables -w "$@" 2>/dev/null || iptables "$@" 2>/dev/null; }
ip6t() { ip6tables -w "$@" 2>/dev/null || ip6tables "$@" 2>/dev/null; }

# OpenWrt (25.12 без iptables вовсе): своя таблица nft, тот же выбор, что у
# S99r2o — он экспортирует R2O_FW; удаление зовёт без него, тогда по системе.
FW=${R2O_FW:-}
if [ -z "$FW" ]; then
    if [ -f "${R2O_OPENWRT_RELEASE:-/etc/openwrt_release}" ] && command -v nft >/dev/null 2>&1; then
        FW=nft
    else
        FW=iptables
    fi
fi
NFT_TABLE=r2o_tg

# shellcheck disable=SC2015 # reject values outside the inclusive port range
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || { echo "неверный TG_PORT" >&2; exit 2; }

nft_list() { printf '%s' "$1" | sed 's/ /, /g'; }
nft_redirects() {
    for port in $TCP_PORTS; do
        printf '\t\tip daddr @tg4 tcp dport %s redirect to :%s\n' "$port" "$PORT"
        printf '\t\tip6 daddr @tg6 tcp dport %s redirect to :%s\n' "$port" "$PORT"
    done
}

# Перехват (LAN — prerouting, сам роутер — output) раньше dstnat fw4.
# Таблица целиком, одной транзакцией.
nft_ruleset() {
    cat <<EOF2
table inet $NFT_TABLE {
    comment "r2o-managed"
	set tg4 { type ipv4_addr; flags interval; elements = { $(nft_list "$CIDRS4") }; }
	set tg6 { type ipv6_addr; flags interval; elements = { $(nft_list "$CIDRS6") }; }
	set tg4_pairs { type ipv4_addr . inet_service; }
	set tg6_pairs { type ipv6_addr . inet_service; }
	chain pre {
		type nat hook prerouting priority dstnat - 1; policy accept;
		ip daddr . tcp dport @tg4_pairs counter redirect to :$PORT
		ip6 daddr . tcp dport @tg6_pairs counter redirect to :$PORT
		$(nft_redirects)
	}
	chain out {
		type nat hook output priority -101; policy accept;
		meta mark $OUTBOUND_MARK return
		ip daddr . tcp dport @tg4_pairs counter redirect to :$PORT
		ip6 daddr . tcp dport @tg6_pairs counter redirect to :$PORT
		$(nft_redirects)
	}
}
EOF2
}

nft_owned() {
    listed=$(nft list table inet "$NFT_TABLE" 2>/dev/null) || return 1
    printf '%s\n' "$listed" | grep -F -q 'comment "r2o-managed"' && return 0
    # Предыдущая таблица r2o имела то же имя и точный набор перенаправлений.
    # Разрешить однократное обновление этой формы; чужие таблицы не трогать.
    [ "$(printf '%s\n' "$listed" | grep -c "redirect to :$PORT")" -eq 12 ] || return 1
    [ "$(printf '%s\n' "$listed" | grep -c 'meta mark 0x31 return')" -eq 1 ] || return 1
    [ "$(printf '%s\n' "$listed" | grep -c 'reject with tcp reset')" -eq 0 ]
}

nft_installed() {
    listed=$(nft list table inet "$NFT_TABLE" 2>/dev/null) || return 1
    nft_owned || return 1
    [ "$(printf '%s\n' "$listed" | grep -c "redirect to :$PORT")" -eq 12 ] || return 1
    for port in $TCP_PORTS; do
        [ "$(printf '%s\n' "$listed" | grep -cF "tcp dport $port redirect to :$PORT")" -eq 4 ] || return 1
    done
    [ "$(printf '%s\n' "$listed" | grep -c "meta mark $OUTBOUND_MARK return")" -eq 1 ] &&
        [ "$(printf '%s\n' "$listed" | grep -cF 'ip daddr . tcp dport @tg4_pairs counter redirect')" -eq 2 ] &&
        [ "$(printf '%s\n' "$listed" | grep -cF 'ip6 daddr . tcp dport @tg6_pairs counter redirect')" -eq 2 ] &&
        [ "$(printf '%s\n' "$listed" | grep -c 'reject with tcp reset')" -eq 0 ]
}

nft_up() {
    f=$(mktemp "${TMPDIR:-/tmp}/r2o-tg-nft.XXXXXX") || return 1
    # Под set -e отказ nft не должен обрывать скрипт до уборки: heal зовёт
    # nft_up последней командой списка ||, где set -e действует.
    rc=0
    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        if nft_owned; then
            printf 'delete table inet %s\n' "$NFT_TABLE" > "$f"
        else
            rm -f "$f"
            echo "отказ: таблица nft inet $NFT_TABLE принадлежит другому компоненту" >&2
            return 1
        fi
    else
        : > "$f"
    fi
    if nft_ruleset >> "$f"; then
        nft -f "$f" || rc=$?
    else
        rc=1
    fi
    rm -f "$f"
    return "$rc"
}

ensure4() {
    command -v ipset >/dev/null 2>&1 || return 1
    ipset create "$SET4" hash:net -exist 2>/dev/null || return 1
    ipset create "$PAIR4" hash:ip,port family inet -exist 2>/dev/null || return 1
    for c in $CIDRS4; do ipset add "$SET4" "$c" -exist 2>/dev/null || return 1; done
    for chain in PREROUTING OUTPUT; do
        ipt -t nat -C "$chain" -p tcp -m set --match-set "$PAIR4" dst,dst -j REDIRECT --to-port "$PORT" ||
            ipt -t nat -I "$chain" 1 -p tcp -m set --match-set "$PAIR4" dst,dst -j REDIRECT --to-port "$PORT" || return 1
        ipt -t nat -C "$chain" -p tcp -m set --match-set "$PAIR4" dst,dst -j REDIRECT --to-port "$PORT" || return 1
    done
    for port in $TCP_PORTS; do
        for chain in PREROUTING OUTPUT; do
            ipt -t nat -C "$chain" -p tcp --dport "$port" -m set --match-set "$SET4" dst -j REDIRECT --to-port "$PORT" ||
                ipt -t nat -I "$chain" 1 -p tcp --dport "$port" -m set --match-set "$SET4" dst -j REDIRECT --to-port "$PORT" || return 1
            ipt -t nat -C "$chain" -p tcp --dport "$port" -m set --match-set "$SET4" dst -j REDIRECT --to-port "$PORT" || return 1
        done
    done
    ipt -t nat -C OUTPUT -m mark --mark "$OUTBOUND_MARK" -m comment --comment "$OUTBOUND_COMMENT" -j RETURN ||
        ipt -t nat -I OUTPUT 1 -m mark --mark "$OUTBOUND_MARK" -m comment --comment "$OUTBOUND_COMMENT" -j RETURN || return 1
    ipt -t nat -C OUTPUT -m mark --mark "$OUTBOUND_MARK" -m comment --comment "$OUTBOUND_COMMENT" -j RETURN || return 1
}

ensure6() {
    command -v ip6tables >/dev/null 2>&1 || return 0
    # Удаляем отказы старой версии до установки новых правил, чтобы IPv6 не
    # оставался заблокированным, если на устройстве нет модуля ip6table_nat.
    for chain in FORWARD OUTPUT; do
        while ip6t -C "$chain" -p tcp -m set --match-set "$SET6" dst -j REJECT --reject-with tcp-reset; do
            ip6t -D "$chain" -p tcp -m set --match-set "$SET6" dst -j REJECT --reject-with tcp-reset || break
        done
    done
    command -v ipset >/dev/null 2>&1 || return 0
    ipset create "$SET6" hash:net family inet6 -exist 2>/dev/null || return 0
    for c in $CIDRS6; do ipset add "$SET6" "$c" -exist 2>/dev/null || return 0; done
    ipset create "$PAIR6" hash:ip,port family inet6 -exist 2>/dev/null || true
    if ipset list "$PAIR6" >/dev/null 2>&1; then
        for chain in PREROUTING OUTPUT; do
            ip6t -t nat -C "$chain" -p tcp -m set --match-set "$PAIR6" dst,dst -j REDIRECT --to-port "$PORT" ||
                ip6t -t nat -I "$chain" 1 -p tcp -m set --match-set "$PAIR6" dst,dst -j REDIRECT --to-port "$PORT" || return 1
            ip6t -t nat -C "$chain" -p tcp -m set --match-set "$PAIR6" dst,dst -j REDIRECT --to-port "$PORT" || return 1
        done
    fi
    for port in $TCP_PORTS; do
        for chain in PREROUTING OUTPUT; do
            ip6t -t nat -C "$chain" -p tcp --dport "$port" -m set --match-set "$SET6" dst -j REDIRECT --to-port "$PORT" ||
                ip6t -t nat -I "$chain" 1 -p tcp --dport "$port" -m set --match-set "$SET6" dst -j REDIRECT --to-port "$PORT" || return 1
            ip6t -t nat -C "$chain" -p tcp --dport "$port" -m set --match-set "$SET6" dst -j REDIRECT --to-port "$PORT" || return 1
        done
    done
    ip6t -t nat -C OUTPUT -m mark --mark "$OUTBOUND_MARK" -m comment --comment "$OUTBOUND_COMMENT" -j RETURN ||
        ip6t -t nat -I OUTPUT 1 -m mark --mark "$OUTBOUND_MARK" -m comment --comment "$OUTBOUND_COMMENT" -j RETURN || return 1
    ip6t -t nat -C OUTPUT -m mark --mark "$OUTBOUND_MARK" -m comment --comment "$OUTBOUND_COMMENT" -j RETURN || return 1
    return 0
}

start() {
    if [ "$FW" = nft ]; then
        ipt_stop
        nft_up || return 1
    else
        nft_stop || return 1
        ipt_stop
        ensure4 || return 1
        ensure6
    fi
    if command -v conntrack >/dev/null 2>&1; then
        for c in $CIDRS4; do conntrack -D -d "$c" >/dev/null 2>&1 || true; done
        for c in $CIDRS6; do conntrack -D -f ipv6 -d "$c" >/dev/null 2>&1 || true; done
    fi
}

heal() {
    if [ "$FW" = nft ]; then
        nft_installed || nft_up
    else
        ensure4 && ensure6
    fi
}

# Снятие iptables-правил — и на Keenetic, и на OpenWrt как остаток установки
# времён Entware. Без iptables здесь нечего делать.
ipt_stop() {
    command -v iptables >/dev/null 2>&1 || return 0
    for port in $TCP_PORTS; do
        for chain in PREROUTING OUTPUT; do
            while ipt -t nat -C "$chain" -p tcp --dport "$port" -m set --match-set "$SET4" dst -j REDIRECT --to-port "$PORT"; do
                ipt -t nat -D "$chain" -p tcp --dport "$port" -m set --match-set "$SET4" dst -j REDIRECT --to-port "$PORT" || break
            done
        done
    done
    for chain in PREROUTING OUTPUT; do
        while ipt -t nat -C "$chain" -p tcp -m set --match-set "$PAIR4" dst,dst -j REDIRECT --to-port "$PORT"; do
            ipt -t nat -D "$chain" -p tcp -m set --match-set "$PAIR4" dst,dst -j REDIRECT --to-port "$PORT" || break
        done
    done
    for mark in "$OUTBOUND_MARK" "$LEGACY_OUTBOUND_MARK"; do
        while ipt -t nat -C OUTPUT -m mark --mark "$mark" -m comment --comment "$OUTBOUND_COMMENT" -j RETURN; do
            ipt -t nat -D OUTPUT -m mark --mark "$mark" -m comment --comment "$OUTBOUND_COMMENT" -j RETURN || break
        done
    done
    if command -v ip6tables >/dev/null 2>&1; then
        for port in $TCP_PORTS; do
            for chain in PREROUTING OUTPUT; do
                while ip6t -t nat -C "$chain" -p tcp --dport "$port" -m set --match-set "$SET6" dst -j REDIRECT --to-port "$PORT"; do
                    ip6t -t nat -D "$chain" -p tcp --dport "$port" -m set --match-set "$SET6" dst -j REDIRECT --to-port "$PORT" || break
                done
            done
        done
        for chain in PREROUTING OUTPUT; do
            while ip6t -t nat -C "$chain" -p tcp -m set --match-set "$PAIR6" dst,dst -j REDIRECT --to-port "$PORT"; do
                ip6t -t nat -D "$chain" -p tcp -m set --match-set "$PAIR6" dst,dst -j REDIRECT --to-port "$PORT" || break
            done
        done
        for mark in "$OUTBOUND_MARK" "$LEGACY_OUTBOUND_MARK"; do
            while ip6t -t nat -C OUTPUT -m mark --mark "$mark" -m comment --comment "$OUTBOUND_COMMENT" -j RETURN; do
                ip6t -t nat -D OUTPUT -m mark --mark "$mark" -m comment --comment "$OUTBOUND_COMMENT" -j RETURN || break
            done
        done
        for chain in FORWARD OUTPUT; do
            while ip6t -C "$chain" -p tcp -m set --match-set "$SET6" dst -j REJECT --reject-with tcp-reset; do
                ip6t -D "$chain" -p tcp -m set --match-set "$SET6" dst -j REJECT --reject-with tcp-reset || break
            done
        done
    fi
}

nft_stop() {
    command -v nft >/dev/null 2>&1 || return 0
    nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || return 0
    nft_owned || { echo "отказ: таблица nft inet $NFT_TABLE принадлежит другому компоненту" >&2; return 1; }
    nft delete table inet "$NFT_TABLE"
}

stop() {
    nft_stop || return 1
    ipt_stop
}

manifest_records() {
    awk -v allowed="$TCP_PORTS" '
        BEGIN {
            count = split(allowed, ports, " ")
            for (i = 1; i <= count; i++) allowed_port[ports[i]] = 1
        }
        NR == 1 {
            if (NF != 3 || $1 != "r2o-tg-dc-options-v1" || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ || $2 < 1 || $3 < 1) {
                invalid = 1
                exit 1
            }
            header = 1
            next
        }
        {
            if (NF != 2 || $2 !~ /^[0-9]+$/ || !($2 in allowed_port)) {
                invalid = 1
                exit 1
            }
            if (index($1, ":") > 0) {
                if ($1 !~ /^[[:xdigit:]:]+$/ || $1 ~ /:::/) { invalid = 1; exit 1 }
            } else {
                if ($1 !~ /^[0-9.]+$/ || split($1, octets, ".") != 4) { invalid = 1; exit 1 }
                for (i = 1; i <= 4; i++) if (octets[i] !~ /^[0-9]+$/ || octets[i] > 255) { invalid = 1; exit 1 }
            }
            print $1, $2
            pairs++
        }
        END { if (invalid || !header || !pairs) exit 1 }
    ' "$DC_MAP_ENDPOINTS"
}

manifest_pairs() {
    family=$1
    printf '%s\n' "$DC_MAP_RECORDS" | awk -v family="$family" '
        NF == 2 && ((family == 4 && index($1, ":") == 0) || (family == 6 && index($1, ":") > 0)) {
            print $1 " . " $2
        }
    '
}

manifest_csv() {
    family=$1
    printf '%s\n' "$DC_MAP_RECORDS" | awk -v family="$family" '
        NF == 2 && ((family == 4 && index($1, ":") == 0) || (family == 6 && index($1, ":") > 0)) {
            if (found++) printf ", "
            printf "%s . %s", $1, $2
        }
        END { if (found) printf "\n" }
    '
}

nft_pair_set_matches() {
    family=$1
    set=$2
    listed=$(nft list set inet "$NFT_TABLE" "$set" 2>/dev/null) || return 1
    expected=$(manifest_pairs "$family" | sort)
    actual=$(printf '%s\n' "$listed" | awk '
        function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
        /elements[[:space:]]*=/ { reading = 1; sub(/^.*[{]/, "") }
        reading {
            line = $0
            if (line ~ /[}]/) { sub(/[}].*/, "", line); reading = 0 }
            count = split(line, entries, ",")
            for (i = 1; i <= count; i++) {
                entry = trim(entries[i])
                if (entry != "") { gsub(/[[:space:]]+[.][[:space:]]+/, " . ", entry); print entry }
            }
        }
    ' | sort)
    [ "$expected" = "$actual" ]
}

nft_sync_dc_map() {
    pair4=$(manifest_csv 4)
    pair6=$(manifest_csv 6)
    nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || { echo "таблица Telegram nft не установлена" >&2; return 1; }
    if nft_pair_set_matches 4 tg4_pairs && nft_pair_set_matches 6 tg6_pairs; then
        return 0
    fi
    {
        printf 'flush set inet %s tg4_pairs\n' "$NFT_TABLE"
        printf 'flush set inet %s tg6_pairs\n' "$NFT_TABLE"
        [ -z "$pair4" ] || printf 'add element inet %s tg4_pairs { %s }\n' "$NFT_TABLE" "$pair4"
        [ -z "$pair6" ] || printf 'add element inet %s tg6_pairs { %s }\n' "$NFT_TABLE" "$pair6"
    } | nft -f - || { echo "nft отклонил обновление пар Telegram; прежние наборы сохранены" >&2; return 1; }
    # shellcheck disable=SC2015 # both IPv4 and IPv6 sets must match
    nft_pair_set_matches 4 tg4_pairs && nft_pair_set_matches 6 tg6_pairs || {
        echo "nft не подтвердил обновлённые пары Telegram" >&2
        return 1
    }
}

ipset_pair_set_matches() {
    family=$1
    set=$2
    expected=$(manifest_pairs "$family" | sort)
    actual=$(ipset save "$set" 2>/dev/null | awk -v set="$set" '$1 == "add" && $2 == set { value = $3; sub(/,tcp:/, " . ", value); print value }' | sort)
    [ "$expected" = "$actual" ]
}

ipset_cleanup_temporary() {
    ipset destroy "$tmp4" 2>/dev/null || true
    if [ "$use6" = 1 ]; then
        ipset destroy "$tmp6" 2>/dev/null || true
    fi
}

ipset_sync_dc_map() {
    command -v ipset >/dev/null 2>&1 || { echo "для синхронизации Telegram требуется ipset" >&2; return 1; }
    tmp4=${PAIR4}_next_$$
    tmp6=${PAIR6}_next_$$
    use6=0
    ipset create "$PAIR4" hash:ip,port family inet -exist || return 1
    if command -v ip6tables >/dev/null 2>&1 && ipset create "$PAIR6" hash:ip,port family inet6 -exist 2>/dev/null; then
        use6=1
    fi
    if ipset_pair_set_matches 4 "$PAIR4" && { [ "$use6" != 1 ] || ipset_pair_set_matches 6 "$PAIR6"; }; then
        return 0
    fi
    ipset create "$tmp4" hash:ip,port family inet -exist || return 1
    ipset flush "$tmp4" || { ipset_cleanup_temporary; return 1; }
    if [ "$use6" = 1 ]; then
        if ! ipset create "$tmp6" hash:ip,port family inet6 -exist 2>/dev/null || ! ipset flush "$tmp6"; then
            ipset destroy "$tmp6" 2>/dev/null || true
            use6=0
        fi
    fi
    while read -r address port; do
        case "$address" in
            *:*)
                if [ "$use6" = 1 ]; then
                    ipset add "$tmp6" "$address,tcp:$port" -exist || { ipset_cleanup_temporary; return 1; }
                fi
                ;;
            *) ipset add "$tmp4" "$address,tcp:$port" -exist || { ipset_cleanup_temporary; return 1; } ;;
        esac
    done <<EOF2
$DC_MAP_RECORDS
EOF2
    ipset swap "$tmp4" "$PAIR4" || { ipset_cleanup_temporary; return 1; }
    if [ "$use6" = 1 ] && ! ipset swap "$tmp6" "$PAIR6"; then
        ipset swap "$tmp4" "$PAIR4" 2>/dev/null || true
        ipset_cleanup_temporary
        return 1
    fi
    if ! ipset_pair_set_matches 4 "$PAIR4" || { [ "$use6" = 1 ] && ! ipset_pair_set_matches 6 "$PAIR6"; }; then
        [ "$use6" != 1 ] || ipset swap "$tmp6" "$PAIR6" 2>/dev/null || true
        ipset swap "$tmp4" "$PAIR4" 2>/dev/null || true
        ipset_cleanup_temporary
        echo "ipset не подтвердил обновлённые пары Telegram" >&2
        return 1
    fi
    ipset_cleanup_temporary
}

sync_dc_map() {
    [ ! -e "$DC_MAP_ENDPOINTS" ] && return 0
    [ -f "$DC_MAP_ENDPOINTS" ] || { echo "манифест Telegram DC не является обычным файлом" >&2; return 1; }
    DC_MAP_RECORDS=$(manifest_records) || { echo "манифест Telegram DC повреждён; действующие правила сохранены" >&2; return 1; }
    if [ "$FW" = nft ]; then
        nft_sync_dc_map
    else
        ipset_sync_dc_map
    fi
}

case "${1:-}" in
    start) start ;;
    heal) heal ;;
    stop) stop ;;
    sync-dc-map) sync_dc_map ;;
    *) echo "использование: $0 {start|heal|stop|sync-dc-map}" >&2; exit 2 ;;
esac
