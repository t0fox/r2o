#!/bin/sh
# Перехват HTTPS sentinel для RuTracker: Keenetic/fw3 и OpenWrt fw4.
set -eu

ROOT=${R2O_DIR:-/opt/r2o}
CONF=${R2O_CONFIG:-$ROOT/config}
# Явные параметры вызова важнее сохранённой конфигурации.
env_sentinel=${R2O_RT_SENTINEL:-}
env_port=${R2O_RT_PROXY_PORT:-}
env_mark=${R2O_RT_MARK:-}
env_backend=${R2O_FW:-}
# shellcheck disable=SC1090 # Путь задаёт владелец установки.
[ ! -r "$CONF" ] || . "$CONF"
SENTINEL=${env_sentinel:-${R2O_RT_SENTINEL:-${RT_SENTINEL:-203.0.113.171}}}
PORT=${env_port:-${R2O_RT_PROXY_PORT:-${RT_PROXY_PORT:-1445}}}
MARK=${env_mark:-${R2O_RT_MARK:-${MARK:-45}}}
FW=${env_backend:-${R2O_FW:-}}
LOCK=${R2O_RT_FIREWALL_LOCK:-$ROOT/run/rt-firewall.lock}
PRE=R2O_RT_PRE
OUT=R2O_RT_OUT
OWNER=r2o-rt-managed
HOOK=r2o-rt-hook
TABLE=r2o_rt
RULES=
LOCKED=0

fail() { printf 'r2o rt-firewall: %s\n' "$*" >&2; return 1; }

valid_ipv4() (
    case "$1" in ''|*[!0-9.]*|.*|*.|*..*) return 1 ;; esac
    IFS=.
    set -f
    # shellcheck disable=SC2086 # Разделяем проверенный IPv4 на октеты.
    set -- $1
    [ "$#" -eq 4 ] || return 1
    for octet do
        case "$octet" in ''|0[0-9]*|????*) return 1 ;; esac
        [ "$octet" -le 255 ] || return 1
    done
)

uint() {
    case "$1" in ''|*[!0-9]*|???????????*) return 1 ;; esac
    [ "$1" -le "$2" ]
}

valid_ipv4 "$SENTINEL" || { fail 'неверный R2O_RT_SENTINEL'; exit 2; }
uint "$PORT" 65535 && [ "$PORT" -gt 0 ] || { fail 'неверный R2O_RT_PROXY_PORT'; exit 2; }
case "$MARK" in
    0x*|0X*)
        case "${MARK#??}" in ''|*[!0-9a-fA-F]*) fail 'неверный R2O_RT_MARK'; exit 2 ;; esac
        MARK=$(printf '%u' "$MARK") || exit 2 ;;
esac
uint "$MARK" 4294967295 || { fail 'неверный R2O_RT_MARK'; exit 2; }
while [ "${MARK#0}" != "$MARK" ]; do MARK=${MARK#0}; done
MARK=${MARK:-0}
while [ "${PORT#0}" != "$PORT" ]; do PORT=${PORT#0}; done

if [ -z "$FW" ]; then
    FW=iptables
    if command -v nft >/dev/null 2>&1 && { [ "${R2O_PLATFORM:-}" = openwrt ] || {
        [ -z "${R2O_PLATFORM:-}" ] && [ -f "${R2O_OPENWRT_RELEASE:-/etc/openwrt_release}" ] &&
            ! { [ -d /opt/etc/ndm ] && [ -x /opt/bin/opkg ]; }
    }; }; then FW=nft; fi
fi
case "$FW" in nft|iptables) ;; *) fail "неизвестный R2O_FW: $FW"; exit 2 ;; esac

cleanup() {
    [ -z "$RULES" ] || rm -f "$RULES"
    if [ "$LOCKED" = 1 ] && [ "$(cat "$LOCK/pid" 2>/dev/null || true)" = "$$" ]; then
        rm -f "$LOCK/pid"
        rmdir "$LOCK" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

lock() {
    mkdir -p "$(dirname "$LOCK")" || return 1
    lock_attempt=0
    while ! mkdir "$LOCK" 2>/dev/null; do
        lock_pid=$(cat "$LOCK/pid" 2>/dev/null || true)
        case "$lock_pid" in
            ''|*[!0-9]*) ;;
            *) if ! kill -0 "$lock_pid" 2>/dev/null; then
                rm -f "$LOCK/pid"
                rmdir "$LOCK" 2>/dev/null || true
                continue
            fi ;;
        esac
        [ "$lock_attempt" -lt 100 ] || { fail 'операция firewall уже выполняется'; return 1; }
        lock_attempt=$((lock_attempt + 1))
        sleep 0.1 2>/dev/null || sleep 1
    done
    LOCKED=1
    printf '%s\n' "$$" > "$LOCK/pid" || return 1
    RULES=$(mktemp "${TMPDIR:-/tmp}/r2o-rt-rules.XXXXXX") || return 1
}

# nft и iptables печатают метки в разных числовых форматах. Сравниваем
# токены без счётчиков; никакая строка вывода firewall не исполняется shell.
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
            marker="-A $chain -m comment --comment $OWNER -j RETURN"
            if ! ipt_chain_rules "$chain" | tr -d '"' | grep -Fqx -- "$marker"; then
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

ipt_status_loaded() {
    ipt_owned || return 1
    [ "$(ipt_hook_count PREROUTING "$PRE")" -eq 1 ] || return 1
    [ "$(ipt_hook_count OUTPUT "$OUT")" -eq 1 ] || return 1
    for chain in "$PRE" "$OUT"; do
        [ "$(ipt_chain_rules "$chain" | canonical)" = "$(ipt_expected "$chain" | canonical)" ] || return 1
    done
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

ipt_apply() {
    command -v iptables-restore >/dev/null 2>&1 || { fail 'нет iptables-restore'; return 1; }
    ipt_read && ipt_owned || return 1
    ipt_status_loaded && return 0
    {
        printf '*nat\n:%s - [0:0]\n:%s - [0:0]\n' "$PRE" "$OUT"
        printf -- '-F %s\n-F %s\n' "$PRE" "$OUT"
        ipt_unhook_rules
        ipt_expected "$PRE"
        ipt_expected "$OUT"
        ipt_hook -I PREROUTING "$PRE"
        ipt_hook -I OUTPUT "$OUT"
        printf 'COMMIT\n'
    } > "$RULES" || return 1
    # Один COMMIT меняет только свои цепи/ссылки. Отказ любого правила
    # оставляет прежнюю nat-таблицу; --noflush есть и в Keenetic 1.4.21.
    iptables-restore --noflush < "$RULES" || return 1
    ipt_read && ipt_status_loaded
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
    NFT_IP=$(nft -n list table ip "$TABLE" 2>/dev/null || true)
    NFT_INET=$(nft -n list table inet "$TABLE" 2>/dev/null || true)
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
    # Старая версия не ставила marker. Признаём только её точную структуру,
    # включая обе цепи и текущие sentinel/port; лишнее правило запрещает миграцию.
    if [ -n "$NFT_INET" ] &&
        [ "$(printf '%s\n' "$NFT_INET" | canonical)" != "$(nft_legacy_expected | canonical)" ]; then
        fail "таблица inet $TABLE не соответствует прежним правилам RuTracker"; return 1
    fi
}

nft_status_loaded() {
    nft_owned || return 1
    [ -z "$NFT_INET" ] && [ -n "$NFT_IP" ] || return 1
    [ "$(printf '%s\n' "$NFT_IP" | canonical)" = "$(nft_ruleset | canonical)" ]
}

nft_apply() {
    nft_read
    nft_owned || return 1
    nft_status_loaded && return 0
    {
        [ -z "$NFT_INET" ] || printf 'delete table inet %s\n' "$TABLE"
        [ -z "$NFT_IP" ] || printf 'delete table ip %s\n' "$TABLE"
        nft_ruleset
    } > "$RULES" || return 1
    nft -f "$RULES" || return 1
    nft_read
    nft_status_loaded
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

case "${1:-}" in
    apply)
        lock || exit 1
        if [ "$FW" = nft ]; then nft_apply; else ipt_apply; fi ;;
    status)
        if [ "$FW" = nft ]; then nft_read; nft_status_loaded
        else ipt_read && ipt_status_loaded; fi ;;
    stop)
        lock || exit 1
        # Остановить и прежний backend после смены fw3/fw4, не трогая чужие
        # таблицы. До первой мутации проверяем владение обоими backend.
        IPT=
        NFT_IP=
        NFT_INET=
        if command -v iptables >/dev/null 2>&1; then ipt_read || { [ "$FW" != iptables ] || exit 1; }; fi
        if command -v nft >/dev/null 2>&1; then nft_read; fi
        ipt_owned && nft_owned || exit 1
        ipt_stop_loaded && nft_stop_loaded ;;
    *) echo "использование: $0 {apply|status|stop}" >&2; exit 2 ;;
esac
