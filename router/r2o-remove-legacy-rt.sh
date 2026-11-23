#!/bin/sh
# Одноразовое снятие правил и записей, оставленных установленным ранее RuTracker-прокси.
set -eu

ROOT=${R2O_DIR:-/opt/r2o}
CONF=${R2O_CONFIG:-$ROOT/config}
[ ! -L "$ROOT" ] || exit 1
[ -d "$ROOT" ] || exit 0
[ ! -L "$CONF" ] || { printf '%s\n' 'r2o миграция RuTracker: конфигурация является ссылкой' >&2; exit 1; }
# shellcheck disable=SC1090 # путь конфигурации задаётся владельцем установки
[ ! -r "$CONF" ] || . "$CONF"
STATE=${R2O_STATE_DIR:-${STATE_DIR:-$ROOT/state}}/rt-dns
RUN=${R2O_RUN_DIR:-$ROOT/run}
SENTINEL=${R2O_RT_SENTINEL:-203.0.113.171}
NDMC=${R2O_RT_DNS_NDMC_BIN:-ndmc}
UCI=${R2O_RT_DNS_UCI_BIN:-uci}
DNS_INIT=${R2O_RT_DNS_INIT:-/etc/init.d/dnsmasq}
UCI_CONFIG_DIR=${R2O_RT_DNS_UCI_CONFIG_DIR:-/etc/config}
PIDFILE=$RUN/rt-dns.pid
DNSCONF=$STATE/dnsmasq.conf
OWNED=$STATE/owned.tsv
REQUEST=$STATE/request
BACKEND_FILE=$STATE/backend
LEGACY_BACKUP=$RUN/r2o-rt-filter-aaaa.prev
LEGACY_PLAN=$STATE/legacy.tsv
LEGACY_SECTION=$STATE/legacy-section
LEGACY_ALLOWED=$STATE/legacy-deltas
RUNTIME=${R2O_RUNTIME_DIR:-/tmp/r2o}
PROC=${R2O_PROC:-/proc}
PORT=${R2O_RT_PROXY_PORT:-1445}
MARK=${R2O_RT_MARK:-${MARK:-45}}
WORK=
PAUSE_HZ=1
PAUSE_MODE=seconds
TAB=$(printf '\t')
settings='^[[:space:]]*(export[[:space:]]+)?R2O_RT_(PROXY|PROXY_BIN|PROXY_PORT|DOMAINS|SENTINEL|MARK|DIRECT_ECH_DOMAINS|ECH_DIRECT_IP|FIREWALL|FIREWALL_LOCK|DNS|DNSMASQ_BIN|DNS_(PORT|QUERY_ADDRESS|QUERY_PORT|NDMC_BIN|UCI_BIN|NC_BIN|INIT|UCI_CONFIG_DIR))='


if ! [ -d "$STATE" ] && ! [ -L "$STATE" ] && ! [ -e "$PIDFILE" ] && ! [ -L "$PIDFILE" ] &&
    ! [ -e "$RUN/r2o-rt-proxy.pid" ] && ! [ -L "$RUN/r2o-rt-proxy.pid" ] &&
    ! [ -e "$LEGACY_BACKUP" ] && ! [ -e "$RUNTIME/r2o-rt-proxy.health" ] && ! [ -e "$ROOT/log/rt-proxy.log" ] &&
    ! grep -Eq "$settings" "$CONF" 2>/dev/null; then
    for old_adapter in "$ROOT"/releases/*/router/r2o-rt-firewall.sh; do
        [ -f "$old_adapter" ] && break
    done
    [ -f "$old_adapter" ] || exit 0
fi

say() { printf 'r2o миграция RuTracker: %s\n' "$*" >&2; }

valid_ip() {
    printf '%s\n' "$1" | awk -F. 'NF != 4 { exit 1 }
        { for (i=1; i<=4; i++) if ($i !~ /^[0-9]+$/ || length($i)>3 || $i+0>255) exit 1 }'
}

valid_port() {
    case "$1" in ''|*[!0-9]*|0*) return 1 ;; esac
    [ "${#1}" -le 5 ] && [ "$1" -le 65535 ]
}

valid_domain() {
    [ "${#1}" -le 253 ] || return 1
    printf '%s\n' "$1" | awk -F. 'NF < 2 { exit 1 }
        { for (i=1; i<=NF; i++) if (length($i)>63 || $i !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/) exit 1 }'
}

pause() {
    case "$PAUSE_MODE" in
        usleep) usleep 50000 ;;
        fractional) sleep 0.05 ;;
        *) sleep 1 ;;
    esac
}

select_clock() {
    if command -v usleep >/dev/null 2>&1; then
        PAUSE_MODE=usleep
        PAUSE_HZ=20
    elif sleep 0.001 2>/dev/null; then
        PAUSE_MODE=fractional
        PAUSE_HZ=20
    fi
}

alive() {
    kill -0 "$1" 2>/dev/null || return 1
    if [ -r "/proc/$1/stat" ]; then
        IFS= read -r process_stat <"/proc/$1/stat" || return 1
        case "${process_stat##*) }" in Z\ *|X\ *) return 1 ;; esac
    fi
    return 0
}

monotonic_ticks() {
    # /proc/uptime даёт монотонное время с сотыми без fork и внешнего date.
    IFS=' ' read -r clock_uptime _clock_idle </proc/uptime || return 1
    clock_seconds=${clock_uptime%.*}
    clock_fraction=${clock_uptime#*.}
    case "$clock_seconds" in ''|*[!0-9]*) return 1 ;; esac
    case "$clock_fraction" in [0-9][0-9]) ;; *) return 1 ;; esac
    # Префикс 1 исключает восьмеричное толкование 08/09 в POSIX shell.
    CLOCK_TICKS=$((clock_seconds * 100 + 1$clock_fraction - 100))
}

bounded() {
    bounded_output=$1
    shift
    bounded_seconds=5
    if [ "${1:-}" = --timeout ]; then bounded_seconds=$2; shift 2; fi
    bounded_deadline=
    if monotonic_ticks; then bounded_deadline=$((CLOCK_TICKS + bounded_seconds * 100)); fi
    "$@" >"$bounded_output" 2>&1 &
    bounded_pid=$!
    bounded_step=0
    while alive "$bounded_pid"; do
        if [ -n "$bounded_deadline" ]; then
            monotonic_ticks && [ "$CLOCK_TICKS" -lt "$bounded_deadline" ] || break
        else
            [ "$bounded_step" -lt "$((bounded_seconds * PAUSE_HZ))" ] || break
        fi
        pause
        bounded_step=$((bounded_step + 1))
    done
    if alive "$bounded_pid"; then
        kill -TERM "$bounded_pid" 2>/dev/null || true
        pause
        kill -KILL "$bounded_pid" 2>/dev/null || true
        wait "$bounded_pid" 2>/dev/null || true
        return 124
    fi
    wait "$bounded_pid"
}

ndm() {
    bounded "$WORK/ndm-output" env LD_LIBRARY_PATH= "$NDMC" -c "$1"
}

ndm_read() {
    ndm 'show running-config' || { say 'NDM не ответил на чтение конфигурации'; return 1; }
    [ -s "$WORK/ndm-output" ] || { say 'NDM вернул пустую конфигурацию'; return 1; }
    # В разных версиях CLI порт и кавычки печатаются немного по-разному.
    sed 's/"//g; s/[[:space:]]*:[[:space:]]*/:/g; s/^[[:space:]]*//; s/[[:space:]]*$//' \
        "$WORK/ndm-output" | awk '{$1=$1; print}' >"$WORK/ndm-config"
    grep -Eq '^(system |interface |hostname |ip |!|service |dns-proxy)' "$WORK/ndm-config" || {
        say 'ответ NDM не похож на running-config'
        return 1
    }
}

uci_do() { "$UCI" -c "$UCI_CONFIG_DIR" "$@"; }

uci_read() {
    uci_do -X -q show dhcp >"$WORK/uci-config" || { say 'не удалось прочитать UCI dhcp'; return 1; }
    sed -n 's/^dhcp\.\([A-Za-z0-9_]*\)=dnsmasq$/\1/p' "$WORK/uci-config" >"$WORK/sections"
    [ -s "$WORK/sections" ] || { say 'в UCI отсутствуют секции dnsmasq'; return 1; }
}

list_has() {
    list_value=$(uci_do -q get "$1" 2>/dev/null || true)
    for list_item in $list_value; do
        [ "$list_item" != "$2" ] || return 0
    done
    return 1
}

uci_pending_owned() {
    # Чужой незавершённый сеанс LuCI/uci не должен сохраняться нашим commit.
    # Собственные add_list/del_list после оборванной операции можно откатить.
    uci_do -q changes dhcp >"$WORK/uci-pending" || return 1
    while IFS= read -r pending_line; do
        pending_allowed=0
        if [ -f "$LEGACY_ALLOWED" ] && grep -Fqx -- "$pending_line" "$LEGACY_ALLOWED"; then
            pending_allowed=1
        fi
        if [ -f "$OWNED" ]; then
            while IFS="$TAB" read -r pending_kind pending_key pending_value; do
                [ "$pending_kind" = uci ] || continue
                case "$pending_line" in
                    "$pending_key+='$pending_value'"|"$pending_key-='$pending_value'") pending_allowed=1; break ;;
                esac
            done <"$OWNED"
        fi
        [ "$pending_allowed" = 1 ] || {
            say 'в UCI есть чужие несохранённые изменения dhcp; они оставлены без commit'
            return 1
        }
    done <"$WORK/uci-pending"
}

legacy_allow() {
    [ -f "$LEGACY_ALLOWED" ] && grep -Fqx -- "$1" "$LEGACY_ALLOWED" && return 0
    printf '%s\n' "$1" >>"$LEGACY_ALLOWED"
}

legacy_exact() {
    [ "$(uci_do -q get "dhcp.$1" 2>/dev/null || true)" = hostrecord ] &&
        [ "$(uci_do -q get "dhcp.$1.name" 2>/dev/null || true)" = "$2" ] &&
        [ "$(uci_do -q get "dhcp.$1.ip" 2>/dev/null || true)" = "$3" ] &&
        [ "$(uci_do -q show "dhcp.$1" | wc -l)" -eq 3 ]
}

legacy_clear() {
    # Старый S99 не имел журнала отдельных server-значений. Мигрируется только
    # точная пара старой секции hostrecord и local/server, при наличии сохранённого
    # старым R2O filter_aaaa. Изменённые секции владельца остаются нетронутыми.
    [ -f "$LEGACY_BACKUP" ] || return 0
    legacy_previous=$(cat "$LEGACY_BACKUP") || return 1
    case "$legacy_previous" in ''|0|1) ;; *) say 'повреждена старая копия filter_aaaa'; return 1 ;; esac
    uci_read && uci_pending_owned || return 1
    if [ ! -f "$LEGACY_PLAN" ]; then
        head -n 1 "$WORK/sections" >"$LEGACY_SECTION" || return 1
        : >"$WORK/legacy-plan"
        for legacy_name in $(sed -n 's/^dhcp\.\(r2o_rt_[A-Za-z0-9_]*\)=hostrecord$/\1/p' "$WORK/uci-config"); do
            legacy_domain=$(uci_do -q get "dhcp.$legacy_name.name" 2>/dev/null || true)
            valid_domain "$legacy_domain" || continue
            legacy_expected_name=r2o_rt_$(printf '%s' "$legacy_domain" | tr -c 'a-z0-9' '_')
            [ "$legacy_name" = "$legacy_expected_name" ] || continue
            legacy_ip=$SENTINEL
            case " ${R2O_RT_DIRECT_ECH_DOMAINS:-rutracker.org www.rutracker.org} " in
                *" $legacy_domain "*) legacy_ip=${R2O_RT_ECH_DIRECT_IP:-172.67.182.196} ;;
            esac
            valid_ip "$legacy_ip" || return 1
            if legacy_exact "$legacy_name" "$legacy_domain" "$legacy_ip"; then
                printf '%s\t%s\t%s\n' "$legacy_name" "$legacy_domain" "$legacy_ip" >>"$WORK/legacy-plan"
            else
                say "изменённая старая секция $legacy_name сохранена"
            fi
        done
        mv "$WORK/legacy-plan" "$LEGACY_PLAN" || return 1
    fi
    legacy_dnsmasq=$(cat "$LEGACY_SECTION") || return 1
    case "$legacy_dnsmasq" in ''|*[!A-Za-z0-9_]*) return 1 ;; esac
    [ "$(uci_do -q get "dhcp.$legacy_dnsmasq" 2>/dev/null || true)" = dnsmasq ] || return 1
    : >"$WORK/legacy-preserved"
    while IFS="$TAB" read -r legacy_name legacy_domain legacy_ip; do
        valid_domain "$legacy_domain" && valid_ip "$legacy_ip" || return 1
        case "$legacy_name" in r2o_rt_*) ;; *) return 1 ;; esac
        if uci_do -q get "dhcp.$legacy_name" >/dev/null 2>&1; then
            if ! legacy_exact "$legacy_name" "$legacy_domain" "$legacy_ip"; then
                printf '%s\n' "$legacy_domain" >>"$WORK/legacy-preserved"
                continue
            fi
            legacy_allow "-dhcp.$legacy_name" && uci_do delete "dhcp.$legacy_name" || return 1
        fi
        legacy_key=dhcp.$legacy_dnsmasq.server
        legacy_value=/$legacy_domain/
        if list_has "$legacy_key" "$legacy_value"; then
            legacy_allow "$legacy_key-='$legacy_value'" && uci_do -q del_list "$legacy_key=$legacy_value" || return 1
        fi
    done <"$LEGACY_PLAN"
    legacy_filter=dhcp.$legacy_dnsmasq.filter_aaaa
    if [ "$(uci_do -q get "$legacy_filter" 2>/dev/null || true)" = 1 ] && [ "$legacy_previous" != 1 ]; then
        if [ -n "$legacy_previous" ]; then
            legacy_allow "$legacy_filter='$legacy_previous'" && uci_do set "$legacy_filter=$legacy_previous" || return 1
        else
            legacy_allow "-$legacy_filter" && uci_do -q delete "$legacy_filter" || return 1
        fi
    fi
    uci_pending_owned && uci_do commit dhcp || return 1
    bounded "$WORK/legacy-reload" --timeout 20 "$DNS_INIT" reload || return 1
    while IFS="$TAB" read -r legacy_name legacy_domain legacy_ip; do
        grep -Fxq "$legacy_domain" "$WORK/legacy-preserved" && continue
        legacy_exact "$legacy_name" "$legacy_domain" "$legacy_ip" && return 1
        list_has "dhcp.$legacy_dnsmasq.server" "/$legacy_domain/" && return 1
    done <"$LEGACY_PLAN"
    rm -f "$LEGACY_BACKUP" "$LEGACY_PLAN" "$LEGACY_SECTION" "$LEGACY_ALLOWED"
}

clear_owned() {
    legacy_clear || return 1
    if [ -f "$BACKEND_FILE" ]; then
        clear_backend=$(cat "$BACKEND_FILE") || return 1
    elif [ -s "$OWNED" ]; then
        clear_backend=$(cut -f1 "$OWNED" | sed 's/^ndm-\(host\|server\)$/keenetic/; s/^uci$/openwrt/' | sort -u)
        case "$clear_backend" in
            keenetic|openwrt) ;;
            *) say 'платформа в неполном журнале DNS не определена'; return 1 ;;
        esac
    else
        return 0
    fi
    case "$clear_backend" in
        keenetic) ndm_read || return 1 ;;
        openwrt) uci_read && uci_pending_owned || return 1 ;;
        *) say 'неизвестный backend в журнале'; return 1 ;;
    esac
    clear_failed=0
    clear_changed=0
    [ -f "$OWNED" ] || : >"$OWNED"
    awk '{row[NR]=$0} END {for(i=NR;i>0;i--) print row[i]}' "$OWNED" >"$WORK/reverse"
    while IFS="$TAB" read -r own_kind own_key own_value; do
        case "$own_kind" in
            ndm-host)
                [ "$clear_backend" = keenetic ] && valid_domain "$own_key" && valid_ip "$own_value" || return 1
                if grep -Fqx "ip host $own_key $own_value" "$WORK/ndm-config"; then
                    ndm "no ip host $own_key $own_value" || { say "NDM не удалил ip host $own_key"; cat "$WORK/ndm-output" >&2; clear_failed=1; }
                    clear_changed=1
                fi ;;
            ndm-server)
                [ "$clear_backend" = keenetic ] && valid_domain "$own_key" || return 1
                case "$own_value" in 127.0.0.1:*) valid_port "${own_value#*:}" || return 1 ;; *) return 1 ;; esac
                if grep -Fqx "ip name-server $own_value $own_key" "$WORK/ndm-config"; then
                    ndm "no ip name-server $own_value $own_key" || { say "NDM не удалил ip name-server для $own_key"; cat "$WORK/ndm-output" >&2; clear_failed=1; }
                    clear_changed=1
                fi ;;
            uci)
                [ "$clear_backend" = openwrt ] || return 1
                printf '%s\n' "$own_key" | grep -Eq '^dhcp\.[A-Za-z0-9_]+\.(address|server)$' || return 1
                [ -n "$own_value" ] || return 1
                if list_has "$own_key" "$own_value"; then
                    uci_do -q del_list "$own_key=$own_value" || { say "UCI не удалил $own_key=$own_value"; clear_failed=1; }
                    clear_changed=1
                fi ;;
            '') ;;
            *) say 'неизвестная запись ownership'; return 1 ;;
        esac
    done <"$WORK/reverse"
    if [ "$clear_backend" = keenetic ]; then
        if [ "$clear_changed" = 1 ] || [ -s "$OWNED" ]; then
            if ! ndm 'system configuration save' || grep -Eiq '(^|[[:space:]])(error|failed|invalid)([[:space:]:]|$)' "$WORK/ndm-output"; then
                say 'NDM не сохранил изменение DNS'
                cat "$WORK/ndm-output" >&2
                clear_failed=1
            fi
        fi
        [ "$clear_failed" = 0 ] || return 1
        ndm_read || return 1
        while IFS="$TAB" read -r own_kind own_key own_value; do
            case "$own_kind" in
                ndm-host) if grep -Fqx "ip host $own_key $own_value" "$WORK/ndm-config"; then fail "в NDM остался ip host $own_key"; return 1; fi ;;
                ndm-server) if grep -Fqx "ip name-server $own_value $own_key" "$WORK/ndm-config"; then fail "в NDM остался ip name-server для $own_key"; return 1; fi ;;
            esac
        done <"$OWNED"
    else
        # Повторный clear повторяет reload, если предыдущий reload завершился ошибкой.
        if [ -s "$OWNED" ]; then
            uci_pending_owned || return 1
            uci_do commit dhcp || { say 'не удалось сохранить изменения UCI dhcp'; return 1; }
            if ! bounded "$WORK/dnsmasq-reload" --timeout 20 "$DNS_INIT" reload; then
                say "не удалось перечитать конфигурацию dnsmasq через $DNS_INIT"
                cat "$WORK/dnsmasq-reload" >&2
                return 1
            fi
            uci_read || return 1
            while IFS="$TAB" read -r own_kind own_key own_value; do
                if [ "$own_kind" = uci ] && list_has "$own_key" "$own_value"; then
                    say "в UCI осталось $own_key=$own_value"
                    return 1
                fi
            done <"$OWNED"
        fi
        [ "$clear_failed" = 0 ] || return 1
    fi
    return 0
}

PRE=R2O_RT_PRE
OUT=R2O_RT_OUT
OWNER=r2o-rt-managed
HOOK=r2o-rt-hook
TABLE=r2o_rt
fail() { say "$*"; return 1; }

canonical() {
    awk '
        function number(s, n, i, d) {
            if (s !~ /^0[xX][0-9a-fA-F]+$/) return s
            n = 0
            for (i = 3; i <= length(s); i++) {
                d = index("0123456789abcdef", tolower(substr(s, i, 1))) - 1
                n = n * 16 + d
            }
            return sprintf("%.0f", n)
        }
        {
            gsub(/[{};\"]/, " ")
            for (i = 1; i <= NF; i++) {
                value = number($i)
                if ($i == "dstnat") {
                    value = -100
                    if ($(i+1) == "-" && $(i+2) ~ /^[0-9]+$/) { value -= $(i+2); i += 2 }
                    else if ($(i+1) == "+" && $(i+2) ~ /^[0-9]+$/) { value += $(i+2); i += 2 }
                }
                printf "%s%s", count++ ? " " : "", value
            }
        }
        END { if (count) printf "\n" }
    '
}

ipt_read() {
    IPT=$(iptables -t nat -S 2>/dev/null) || return 1
}

ipt_chain_exists() { printf '%s\n' "$IPT" | grep -Fqx -- "-N $1"; }

ipt_chain_rules() { printf '%s\n' "$IPT" | awk -v chain="$1" '$1 == "-A" && $2 == chain'; }

ipt_hook() { printf '%s %s -m comment --comment %s -j %s\n' "$1" "$2" "$HOOK" "$3"; }

ipt_hook_count() {
    hook_line=$(ipt_hook -A "$1" "$2")
    printf '%s\n' "$IPT" | tr -d '"' | awk -v rule="$hook_line" '$0 == rule { n++ } END { print n+0 }'
}

ipt_owned() {
    for chain in "$PRE" "$OUT"; do
        if ipt_chain_exists "$chain"; then
            if [ "$(ipt_chain_rules "$chain" | canonical)" != "$(ipt_expected "$chain" | canonical)" ]; then
                fail "цепь $chain принадлежит другому компоненту"; return 1
            fi
        fi
    done
    # Чужие ссылки не удаляем даже тогда, когда они указывают на нашу цепь.
    if ! printf '%s\n' "$IPT" | tr -d '"' | awk -v pre="$PRE" -v out="$OUT" -v marker="$HOOK" '
        $1 == "-A" {
            for (i = 3; i < NF; i++) if ($i == "-j" && ($(i+1) == pre || $(i+1) == out)) {
                parent = $(i+1) == pre ? "PREROUTING" : "OUTPUT"
                expected = "-A " parent " -m comment --comment " marker " -j " $(i+1)
                if ($0 != expected) exit 1
            }
        }'; then fail 'обнаружена чужая ссылка на цепь RuTracker'; return 1; fi
}

ipt_redirect() {
    printf '%s\n' "-A $1 -d $SENTINEL/32 -p tcp -m tcp --dport 443 -j REDIRECT --to-ports $PORT"
}

ipt_expected() {
    if [ "$1" = "$OUT" ] && [ "$MARK" != 0 ]; then
        printf '%s\n' "-A $OUT -m mark --mark $MARK -j RETURN"
    fi
    ipt_redirect "$1"
    printf '%s\n' "-A $1 -m comment --comment $OWNER -j RETURN"
}

ipt_unhook_rules() {
    for parent in PREROUTING OUTPUT; do
        if [ "$parent" = PREROUTING ]; then target=$PRE; else target=$OUT; fi
        count=$(ipt_hook_count "$parent" "$target")
        while [ "$count" -gt 0 ]; do
            ipt_hook -D "$parent" "$target"
            count=$((count - 1))
        done
    done
}

ipt_stop_loaded() {
    ipt_owned || return 1
    if ! ipt_chain_exists "$PRE" && ! ipt_chain_exists "$OUT" &&
        [ "$(ipt_hook_count PREROUTING "$PRE")" -eq 0 ] && [ "$(ipt_hook_count OUTPUT "$OUT")" -eq 0 ]; then return 0; fi
    {
        printf '*nat\n'
        ipt_unhook_rules
        for chain in "$PRE" "$OUT"; do
            if ipt_chain_exists "$chain"; then printf -- '-F %s\n-X %s\n' "$chain" "$chain"; fi
        done
        printf 'COMMIT\n'
    } > "$RULES" || return 1
    iptables-restore --noflush < "$RULES"
}

nft_read() {
    if ! nft list tables >"$WORK/nft-tables" 2>"$WORK/nft-error"; then
        case "${R2O_FW:-}:${clear_backend:-}:${R2O_PLATFORM:-}" in
            nft:*|*:openwrt:*|*:*:openwrt) cat "$WORK/nft-error" >&2; return 1 ;;
        esac
        return 0
    fi
    if grep -Fqx "table ip $TABLE" "$WORK/nft-tables"; then
        NFT_IP=$(nft -n list table ip "$TABLE") || return 1
    fi
    if grep -Fqx "table inet $TABLE" "$WORK/nft-tables"; then
        NFT_INET=$(nft -n list table inet "$TABLE") || return 1
    fi
}

nft_ruleset() {
    cat <<EOF
table ip $TABLE {
    chain prerouting {
        type nat hook prerouting priority -101; policy accept;
        ip daddr $SENTINEL tcp dport 443 redirect to :$PORT
        return comment "$OWNER"
    }
    chain output {
        type nat hook output priority -101; policy accept;
EOF
    [ "$MARK" = 0 ] || printf '        meta mark %s return\n' "$MARK"
    cat <<EOF
        ip daddr $SENTINEL tcp dport 443 redirect to :$PORT
        return comment "$OWNER"
    }
}
EOF
}

nft_legacy_expected() {
    cat <<EOF
table inet $TABLE {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
        ip daddr $SENTINEL tcp dport 443 redirect to :$PORT
    }
    chain output {
        type nat hook output priority -100; policy accept;
        ip daddr $SENTINEL tcp dport 443 redirect to :$PORT
    }
}
EOF
}

nft_owned() {
    if [ -n "$NFT_IP" ]; then
        # Marker именно правила, а не table userdata: он поддерживается
        # ядрами 4.9. Признаём только две свои цепи с отдельным marker в каждой.
        if ! printf '%s\n' "$NFT_IP" | awk -v owner="$OWNER" '
            depth == 1 && NF && $1 != "chain" && $1 != "}" { exit 1 }
            $1 == "chain" {
                chain = $2
                if (chain != "prerouting" && chain != "output") exit 1
                chains++
            }
            $1 == "return" && $2 == "comment" {
                marker = $3
                gsub(/[";]/, "", marker)
                if (marker == owner) owned[chain]++
            }
            { line = $0; depth += gsub(/\{/, "", line) - gsub(/\}/, "", line) }
            END { if (chains != 2 || owned["prerouting"] != 1 || owned["output"] != 1) exit 1 }
        '; then fail "таблица ip $TABLE принадлежит другому компоненту"; return 1; fi
    fi
    if [ -n "$NFT_IP" ] &&
        [ "$(printf '%s\n' "$NFT_IP" | canonical)" != "$(nft_ruleset | canonical)" ]; then
        fail "в таблице ip $TABLE обнаружены несовпадающие правила"; return 1
    fi
    # Старая версия не ставила marker. Признаём только её точную структуру,
    # включая обе цепи и текущие sentinel/port; лишнее правило запрещает миграцию.
    if [ -n "$NFT_INET" ] &&
        [ "$(printf '%s\n' "$NFT_INET" | canonical)" != "$(nft_legacy_expected | canonical)" ]; then
        fail "таблица inet $TABLE не соответствует прежним правилам RuTracker"; return 1
    fi
}

nft_stop_loaded() {
    nft_owned || return 1
    [ -n "$NFT_IP$NFT_INET" ] || return 0
    {
        [ -z "$NFT_IP" ] || printf 'delete table ip %s\n' "$TABLE"
        [ -z "$NFT_INET" ] || printf 'delete table inet %s\n' "$TABLE"
        :
    } > "$RULES" || return 1
    nft -f "$RULES"
}


remove_firewall() {
    IPT=
    NFT_IP=
    NFT_INET=
    if command -v iptables >/dev/null 2>&1; then
        ipt_read || {
            [ "${R2O_PLATFORM:-}" != keenetic ] || { say 'iptables не прочитал таблицу nat'; return 1; }
        }
    fi
    if command -v nft >/dev/null 2>&1; then
        nft_read || return 1
    fi
    ipt_owned && nft_owned || return 1
    RULES=$WORK/rules
    ipt_stop_loaded || { say 'не удалось удалить собственные цепи iptables'; return 1; }
    nft_stop_loaded || { say 'не удалось удалить собственные таблицы nftables'; return 1; }
}

process_matches() {
    process_kind=$1
    process_id=$2
    alive "$process_id" && [ -r "$PROC/$process_id/cmdline" ] || return 1
    process_args=$(tr '\000' '\n' <"$PROC/$process_id/cmdline") || return 1
    if [ "$process_kind" = dns ]; then
        printf '%s\n' "$process_args" | grep -Fxq -- "--conf-file=$DNSCONF"
        return
    fi
    process_exe=$(readlink "$PROC/$process_id/exe") || return 1
    process_exe=${process_exe% (deleted)}
    case "$process_exe" in
        "$ROOT"/releases/*/builds/r2o-telegram-linux-*)
            printf '%s\n' "$process_args" | grep -Fxq -- --rt-proxy ;;
        *)
            [ -n "${R2O_RT_PROXY_BIN:-}" ] &&
                [ "$(readlink -f "$R2O_RT_PROXY_BIN")" = "$process_exe" ] &&
                printf '%s\n' "$process_args" | grep -Fxq -- "--listen=:$PORT" ;;
    esac
}

stop_owned() {
    stop_kind=$1
    stop_file=$2
    if [ -f "$stop_file" ]; then
        stop_id=$(cat "$stop_file") || return 1
        case "$stop_id" in
            ''|*[!0-9]*|0|1) say "неверный PID $stop_file"; return 1 ;;
        esac
        if alive "$stop_id" && ! process_matches "$stop_kind" "$stop_id"; then
            say "PID $stop_id из $stop_file сейчас принадлежит другому процессу"
        fi
    fi
    # После сбоя PID-файл мог не появиться. Проверяем точную команду в /proc.
    for stop_path in "$PROC"/[0-9]*/cmdline; do
        stop_id=${stop_path%/cmdline}
        stop_id=${stop_id##*/}
        [ -r "$stop_path" ] && process_matches "$stop_kind" "$stop_id" || continue
        kill -TERM "$stop_id" 2>/dev/null || { ! alive "$stop_id" || return 1; }
        stop_step=0
        while alive "$stop_id" && [ "$stop_step" -lt "$((2 * PAUSE_HZ))" ]; do
            pause
            stop_step=$((stop_step + 1))
        done
        if alive "$stop_id" && process_matches "$stop_kind" "$stop_id"; then
            kill -KILL "$stop_id" 2>/dev/null || { ! alive "$stop_id" || return 1; }
        fi
    done
    rm -f "$stop_file"
}

remove_proxy_settings() {
    [ -f "$CONF" ] || return 0
    grep -Eq "$settings" "$CONF" || return 0
    config_tmp=$(mktemp "$CONF.r2o-migrate.XXXXXX") || return 1
    if cp -p "$CONF" "$config_tmp" && sed -E "/$settings/d" "$CONF" >"$config_tmp" &&
        mv -f "$config_tmp" "$CONF"; then
        return 0
    fi
    rm -f "$config_tmp"
    return 1
}

cleanup_work() {
    [ -z "$WORK" ] || rm -rf "$WORK"
}
trap cleanup_work EXIT
trap 'exit 1' HUP INT TERM
umask 077
WORK=$(mktemp -d "${TMPDIR:-/tmp}/r2o-legacy-rt.XXXXXX") || exit 1
select_clock
for path in "$STATE" "$RUN" "$OWNED" "$BACKEND_FILE" "$REQUEST" "$DNSCONF" "$PIDFILE" "$LEGACY_BACKUP" "$LEGACY_PLAN" "$LEGACY_SECTION" "$LEGACY_ALLOWED" "$RUN/r2o-rt-proxy.pid"; do
    if [ -L "$path" ]; then say "символьная ссылка в следах установки: $path"; exit 1; fi
done
# Сначала проверяем следы прежних операций и снимаем настройки, затем останавливаем процессы.
for path in "$RUN/rt-dns.lock" "$RUN/rt-firewall.lock" "$RUN/rt-proxy.lock"; do
    [ ! -L "$path" ] || { say "символьная ссылка вместо блокировки: $path"; exit 1; }
    lock_pid=$(cat "$path/pid" 2>/dev/null || true)
    case "$lock_pid" in ''|*[!0-9]*) ;; *)
        if alive "$lock_pid"; then say "ещё выполняется старая операция $path"; exit 1; fi ;;
    esac
done
if [ -s "$REQUEST" ]; then
    journal_ip=$(sed -n '2p' "$REQUEST")
    if valid_ip "$journal_ip"; then SENTINEL=$journal_ip; fi
fi
valid_ip "$SENTINEL" && valid_port "$PORT" || { say 'неверный адрес или порт в прежних настройках'; exit 1; }
case "$MARK" in 0x*|0X*) MARK=$(printf '%u' "$MARK") || exit 1 ;; esac
case "$MARK" in ''|*[!0-9]*) say 'неверная метка прежнего прокси'; exit 1 ;; esac
clear_owned || { say 'не удалось снять DNS; журнал сохранён для повторной попытки'; exit 1; }
remove_firewall || { say 'не удалось снять перенаправления; журнал сохранён для повторной попытки'; exit 1; }
if [ -d "$STATE" ] || [ -f "$PIDFILE" ] || [ -f "$RUN/r2o-rt-proxy.pid" ] ||
    [ -f "$RUNTIME/r2o-rt-proxy.health" ] || [ -e "$ROOT/log/rt-proxy.log" ]; then
    stop_owned dns "$PIDFILE" && stop_owned proxy "$RUN/r2o-rt-proxy.pid" ||
        { say 'не удалось остановить прежний процесс; журнал сохранён для повторной попытки'; exit 1; }
fi
remove_proxy_settings || { say "не удалось убрать прежние настройки из $CONF"; exit 1; }
rm -f "$OWNED" "$REQUEST" "$BACKEND_FILE" "$DNSCONF" "$STATE/dnsmasq.log" \
    "$RUNTIME/r2o-rt-proxy.health" "$ROOT/log/rt-proxy.log"
if [ -d "$STATE" ]; then rmdir "$STATE" 2>/dev/null || true; fi
for path in "$RUN/rt-dns.lock" "$RUN/rt-firewall.lock" "$RUN/rt-proxy.lock"; do
    [ ! -d "$path" ] || { rm -f "$path/pid"; rmdir "$path" 2>/dev/null || true; }
done
