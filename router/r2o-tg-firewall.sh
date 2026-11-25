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
OUTBOUND_MARK=0x31
OUTBOUND_COMMENT=r2o-tg-outbound
CIDRS4="149.154.160.0/20 91.108.4.0/22 91.108.8.0/22 91.108.12.0/22 91.108.16.0/22 91.108.20.0/22 91.108.56.0/22 91.105.192.0/23 95.161.64.0/20 185.76.151.0/24"
CIDRS6="2001:67c:4e8::/48 2001:b28:f23c::/47 2001:b28:f23f::/48 2a0a:f280:203::/48"

# OpenWrt (25.12 без iptables вовсе): своя таблица nft, тот же выбор, что у
# S99r2o — он экспортирует R2O_FW; удаление зовёт без него, тогда по системе.
FW=${R2O_FW:-}
if [ -z "$FW" ]; then
    if command -v nft >/dev/null 2>&1 && { [ "${R2O_PLATFORM:-}" = openwrt ] || {
        [ -z "${R2O_PLATFORM:-}" ] && [ -f "${R2O_OPENWRT_RELEASE:-/etc/openwrt_release}" ] &&
            ! { [ -d /opt/etc/ndm ] && [ -x /opt/bin/opkg ]; }
    }; }; then
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
    f=$work/nft-rules
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

# Каждый стек меняется отдельной транзакцией. Обычные правила TCP позволяют
# использовать точные пары даже там, где ipset не знает hash:ip,port.
CHAIN=R2O_TG
OWNER=r2o-managed-tg

family_tools() {
    family=$1
    case "$family" in
        4) table=iptables; cidrs=$CIDRS4; net_set=$SET4; pair_set=$PAIR4; mask=32 ;;
        6) table=ip6tables; cidrs=$CIDRS6; net_set=$SET6; pair_set=$PAIR6; mask=128 ;;
    esac
}

report_family() {
    level=$1
    shift
    {
        printf '%s %s\n' "$level" "$*"
        if [ -s "$work/error" ]; then head -c 2048 "$work/error"; fi
    } > "$work/result" || return 1
    if ! cmp -s "$work/result" "$RUNTIME/telegram-firewall.ipv$family"; then
        mv -f "$work/result" "$RUNTIME/telegram-firewall.ipv$family" || return 1
        if [ "$level" = unavailable ]; then
            printf 'Telegram IPv%s: %s\n' "$family" "$*" >&2
            if [ -s "$work/error" ]; then head -c 2048 "$work/error" >&2; fi
        fi
    fi
}

list_rules() {
    if [ "${R2O_PLATFORM:-}" = keenetic ] || {
        [ -z "${R2O_PLATFORM:-}" ] && { [ -d /opt/etc/ndm ] || [ -x /bin/ndmc ]; }
    }; then
        "$(dirname -- "$0")/r2o-firewall.sh" list-rules "$1" "$2"
    elif [ "$1" = 4 ]; then
        iptables -t "$2" -S
    else
        ip6tables -t "$2" -S
    fi
}

family_read() {
    : > "$work/error"
    command -v "$table" >/dev/null 2>&1 || return 127
    list_rules "$family" nat > "$work/current" 2> "$work/error"
}

# Принимаем только точные сигнатуры предыдущего адаптера. Остальные правила,
# включая переходы сторонних компонентов, не удаляем.
legacy_rules() {
    awk -v net="$net_set" -v pair="$pair_set" -v common="$OUTBOUND_COMMENT" -v owner="$OWNER" -v chain="$CHAIN" '
        /^-A (PREROUTING|OUTPUT) / {
            if ($0 == "-A PREROUTING -m comment --comment " owner " -j " chain ||
                $0 == "-A OUTPUT -m mark ! --mark 0x31 -m comment --comment " owner " -j " chain ||
                $0 ~ ("^-A (PREROUTING|OUTPUT) -p tcp -m set --match-set " pair " dst,dst -j REDIRECT --to-ports? [0-9]+$") ||
                $0 ~ ("^-A (PREROUTING|OUTPUT) -p tcp -m tcp --dport (443|5222) -m set --match-set " net " dst -j REDIRECT --to-ports? [0-9]+$") ||
                $0 ~ ("^-A OUTPUT -m mark --mark (0x31|0x40000000) -m comment --comment " common " -j RETURN$"))
                print
        }
    ' "$work/current"
}

family_hooks() {
    printf '%s\n' "-A PREROUTING -m comment --comment $OWNER -j $CHAIN"
    printf '%s\n' "-A OUTPUT -m mark ! --mark $OUTBOUND_MARK -m comment --comment $OWNER -j $CHAIN"
}

family_rules() {
    for cidr in $cidrs; do
        for port in $TCP_PORTS; do
            printf '%s\n' "-A $CHAIN -d $cidr -p tcp -m tcp --dport $port -j REDIRECT --to-ports $PORT"
        done
    done
    printf '%s\n' "$DC_MAP_RECORDS" | awk -v family="$family" -v chain="$CHAIN" -v mask="$mask" -v listener="$PORT" '
        NF == 2 && ((family == 4) == (index($1, ":") == 0)) {
            print "-A " chain " -d " $1 "/" mask " -p tcp -m tcp --dport " $2 " -j REDIRECT --to-ports " listener
        }
    '
    printf '%s\n' "-A $CHAIN -m comment --comment $OWNER -j RETURN"
}

family_restore() {
    "${table}-restore" --noflush < "$work/transaction" 2> "$work/error"
}

# В старой версии отсутствие IPv6 REDIRECT могло оставлять REJECT в filter.
# Снимаем только точные правила той версии и не трогаем остальные цепочки.
legacy_ip6_reject_clear() {
    command -v ip6tables >/dev/null 2>&1 || return 0
    if ! list_rules 6 filter > "$work/filter" 2> "$work/error"; then
        if grep -qx filter /proc/net/ip6_tables_names 2>/dev/null; then
            cat "$work/error" >&2
            return 1
        fi
        return 0
    fi
    awk -v set="$SET6" '
        $0 == "-A FORWARD -p tcp -m set --match-set " set " dst -j REJECT --reject-with tcp-reset" ||
        $0 == "-A OUTPUT -p tcp -m set --match-set " set " dst -j REJECT --reject-with tcp-reset" {
            sub(/^-A /, "-D ")
            print
        }
    ' "$work/filter" > "$work/rejects" || return 1
    [ -s "$work/rejects" ] || return 0
    { printf '*filter\n'; cat "$work/rejects"; printf 'COMMIT\n'; } > "$work/transaction" || return 1
    if ! ip6tables-restore --noflush < "$work/transaction"; then
        echo "не удалось удалить прежние правила IPv6 REJECT" >&2
        return 1
    fi
}

family_apply() {
    family_tools "$1"
    mode=$2
    if [ "$family" = 6 ] && { [ "$action" = start ] || [ "$mode" = remove ]; }; then
        legacy_ip6_reject_clear || return 1
    fi
    if family_read; then
        :
    else
        code=$?
        if [ "$mode" = remove ]; then
            names=/proc/net/ip_tables_names
            [ "$family" = 4 ] || names=/proc/net/ip6_tables_names
            # Если ядро не загрузило эту таблицу, в ней нет правил на удаление.
            if [ ! -r "$names" ] || ! grep -qx nat "$names"; then return 0; fi
        fi
        report_family unavailable "backend=iptables command=$table -t nat -S exit=$code"
        return 1
    fi

    owned=0
    if grep -Fxq -- "-N $CHAIN" "$work/current"; then
        if ! grep -Fxq -- "-A $CHAIN -m comment --comment $OWNER -j RETURN" "$work/current"; then
            report_family unavailable "backend=iptables chain=$CHAIN: цепочка принадлежит другому компоненту"
            return 1
        fi
        owned=1
    fi
    legacy_rules > "$work/hooks" || return 1
    if [ "$mode" = remove ]; then
        if [ "$owned" = 0 ] && [ ! -s "$work/hooks" ]; then return 0; fi
    else
        family_hooks > "$work/expected-hooks" || return 1
        if [ "$mode" = sync ] && { [ "$owned" = 0 ] || ! cmp -s "$work/hooks" "$work/expected-hooks"; }; then return 0; fi
        family_rules > "$work/desired" || return 1
        awk -v chain="$CHAIN" '$1 == "-A" && $2 == chain' "$work/current" > "$work/current-rules"
        awk '$1 == "-A" && !seen[$2]++ && ($2 == "PREROUTING" || $2 == "OUTPUT")' "$work/current" > "$work/first"
        if cmp -s "$work/hooks" "$work/expected-hooks" &&
            cmp -s "$work/hooks" "$work/first" &&
            cmp -s "$work/desired" "$work/current-rules"; then
            report_family active "backend=iptables matching=exact"
            return 0
        fi
        if [ "$mode" != sync ] && [ -n "${R2O_TG_MANAGER:-}" ]; then
            if "$R2O_TG_MANAGER" exec --root "$ROOT" --component r2o-telegram -- \
                --check-transparent-sockets "$family" 2> "$work/error"; then
                :
            else
                code=$?
                report_family unavailable "backend=iptables command=r2o-telegram --check-transparent-sockets $family exit=$code"
                return 1
            fi
        fi
    fi

    {
        printf '*nat\n'
        if [ "$owned" = 1 ]; then
            printf '%s\n' "-F $CHAIN"
        elif [ "$mode" != remove ]; then
            printf ':%s - [0:0]\n' "$CHAIN"
        fi
        if [ "$mode" != sync ]; then sed 's/^-A /-D /' "$work/hooks"; fi
        if [ "$mode" = remove ]; then
            if [ "$owned" = 1 ]; then printf '%s\n' "-X $CHAIN"; fi
        else
            cat "$work/desired"
            if [ "$mode" != sync ]; then
                sed 's/^-A \([^ ]*\) /-I \1 1 /' "$work/expected-hooks"
            fi
        fi
        printf 'COMMIT\n'
    } > "$work/transaction" || return 1
    if family_restore; then
        if [ "$mode" != remove ]; then report_family active "backend=iptables matching=exact"; fi
        return 0
    else
        code=$?
        report_family unavailable "backend=iptables command=${table}-restore --noflush exit=$code"
        return 1
    fi
}

ipt_stop() {
    result=0
    family_apply 4 remove || result=1
    family_apply 6 remove || result=1
    return "$result"
}

ipt_apply() {
    active=0
    family_apply 4 "$1" && active=1
    family_apply 6 "$1" && active=1
    [ "$active" = 1 ]
}

start() {
    if [ "$FW" = nft ]; then
        nft_up || return 1
        if ! ipt_stop; then
            nft_stop
            return 1
        fi
    else
        nft_stop || return 1
        ipt_apply apply
    fi
}

heal() {
    if [ "$FW" = nft ]; then
        nft_installed || nft_up
    else
        ipt_apply apply
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
            if (pairs >= 1024 || NF != 2 || $2 !~ /^[0-9]+$/ || !($2 in allowed_port)) {
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

# Синхронизация карты, watchdog и init используют один lock. Никакие hooks
# не создаются из фонового обновления карты до подтверждения listener в init.
RUNTIME=${R2O_RUNTIME_DIR:-/tmp/r2o}
umask 077
mkdir -p "$RUNTIME"
work=$RUNTIME/telegram-firewall.lock
attempt=0
while ! mkdir "$work" 2>/dev/null; do
    pid=$(cat "$work/pid" 2>/dev/null) || pid=
    case "$pid" in
        ''|*[!0-9]*) ;;
        *) if ! kill -0 "$pid" 2>/dev/null && mkdir "$work/reap" 2>/dev/null; then
               rm -f "$work/pid" "$work/error" "$work/current" "$work/result" \
                   "$work/hooks" "$work/desired" "$work/expected-hooks" "$work/first" \
                   "$work/current-rules" "$work/transaction" "$work/filter" "$work/rejects" "$work/nft-rules"
               rmdir "$work/reap"
               if rmdir "$work" 2>/dev/null; then continue; fi
           fi ;;
    esac
    attempt=$((attempt + 1))
    [ "$attempt" -lt 30 ] || { echo "Telegram firewall: занята блокировка $work" >&2; exit 1; }
    sleep 0.1 2>/dev/null || sleep 1
done
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM
printf '%s\n' "$$" > "$work/pid"

action=${1:-}
DC_MAP_RECORDS=
case "$action" in
    start|heal|sync-dc-map)
        if [ -e "$DC_MAP_ENDPOINTS" ]; then
            if [ ! -f "$DC_MAP_ENDPOINTS" ] || ! DC_MAP_RECORDS=$(manifest_records); then
                echo "манифест Telegram DC повреждён; действующие правила сохранены" >&2
                exit 1
            fi
        fi ;;
esac

case "${1:-}" in
    start) start ;;
    heal) heal ;;
    stop)
        result=0
        stop || result=$?
        if [ "$result" = 0 ]; then
            rm -f "$RUNTIME/telegram-firewall.ipv4" "$RUNTIME/telegram-firewall.ipv6"
        fi
        exit "$result" ;;
    sync-dc-map)
        [ -n "$DC_MAP_RECORDS" ] || exit 0
        if [ "$FW" = nft ]; then
            if nft_owned; then nft_sync_dc_map; fi
        else
            ipt_apply sync
        fi ;;
    *) echo "использование: $0 {start|heal|stop|sync-dc-map}" >&2; exit 2 ;;
esac
