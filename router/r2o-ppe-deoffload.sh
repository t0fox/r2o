#!/bin/sh
set -eu

R2O_PPE_DEOFFLOAD=${R2O_PPE_DEOFFLOAD:-}
R2O_PPE_CONNSKIP=${R2O_PPE_CONNSKIP:-30}
R2O_PPE_HTTP_CONNSKIP=${R2O_PPE_HTTP_CONNSKIP:-1000000}
R2O_PPE_TARGET=${R2O_PPE_TARGET:-PPE}
R2O_PPE_TAG=${R2O_PPE_TAG:-r2o-ppe}
R2O_PPE_TCP_PORTS=${R2O_PPE_TCP_PORTS:-${PORTS:-0:65535}}
R2O_PPE_VOICE_PORTS=${R2O_PPE_VOICE_PORTS:-${VOICE_PORTS:-50000:50099,1400,3478:3481,5349,19294:19344}}
R2O_PPE_UDP_PORTS=${R2O_PPE_UDP_PORTS:-443,$R2O_PPE_VOICE_PORTS}
R2O_PPE_HTTP_PORTS=${R2O_PPE_HTTP_PORTS:-${HTTP_KEEPALIVE_PORTS:-80}}
R2O_PPE_PROC=${R2O_PPE_PROC:-/proc/net}
R2O_PPE_CONFIG=${R2O_PPE_CONFIG:-${R2O_CONFIG:-/opt/r2o/config}}
R2O_PPE_BINDS=${R2O_PPE_BINDS:-/proc/driver/hw_nat/foe/binds}

r2o_ppe_load_flag() {
    [ -n "$R2O_PPE_DEOFFLOAD" ] && return 0
    if [ -r "$R2O_PPE_CONFIG" ]; then
        R2O_PPE_DEOFFLOAD=$(awk -F= '
            /^[[:space:]]*R2O_PPE_DEOFFLOAD=/ {
                found=1
                value=$2
                gsub(/[\047"[:space:]]/, "", value)
            }
            END { if (found) print value }
        ' "$R2O_PPE_CONFIG")
    fi
    R2O_PPE_DEOFFLOAD=${R2O_PPE_DEOFFLOAD:-1}
}

r2o_ppe_valid_ports() (
    case "$1" in ''|*[!0-9:,]*) return 1 ;; esac
    set -f
    IFS=,
    # shellcheck disable=SC2086 # split only on commas after restricting characters above
    set -- $1
    [ "$#" -gt 0 ] || return 1
    _r2o_slots=0
    for _r2o_item do
        case "$_r2o_item" in
            *:*)
                _r2o_start=${_r2o_item%%:*}
                _r2o_end=${_r2o_item#*:}
                case "$_r2o_end" in *:*) return 1 ;; esac
                [ -n "$_r2o_start" ] && [ -n "$_r2o_end" ] || return 1
                [ "$_r2o_start" -le 65535 ] && [ "$_r2o_end" -le 65535 ] || return 1
                [ "$_r2o_start" -lt "$_r2o_end" ] || return 1
                _r2o_slots=$((_r2o_slots + 2))
                ;;
            *)
                [ "$_r2o_item" -le 65535 ] || return 1
                _r2o_slots=$((_r2o_slots + 1))
                ;;
        esac
        [ "$_r2o_slots" -le 15 ] || return 1
    done
)

r2o_ppe_valid_config() {
    r2o_ppe_load_flag
    case "$R2O_PPE_DEOFFLOAD" in 0|1) ;; *) return 1 ;; esac
    case "$R2O_PPE_TARGET" in ''|*[!A-Za-z0-9_]*) return 1 ;; esac
    case "$R2O_PPE_TAG" in ''|*[!A-Za-z0-9_-]*) return 1 ;; esac
    case "$R2O_PPE_CONNSKIP:$R2O_PPE_HTTP_CONNSKIP" in *[!0-9:]*) return 1 ;; esac
    [ "${#R2O_PPE_CONNSKIP}" -le 9 ] && [ "$R2O_PPE_CONNSKIP" -gt 0 ] || return 1
    [ "${#R2O_PPE_HTTP_CONNSKIP}" -le 9 ] && [ "$R2O_PPE_HTTP_CONNSKIP" -gt 0 ] || return 1
    r2o_ppe_valid_ports "$R2O_PPE_TCP_PORTS" || return 1
    r2o_ppe_valid_ports "$R2O_PPE_UDP_PORTS" || return 1
    r2o_ppe_valid_ports "$R2O_PPE_HTTP_PORTS"
}

_r2o_ppe_ipt() {
    _r2o_ppe_tool=$1
    shift
    "$_r2o_ppe_tool" -w "$@" 2>/dev/null || "$_r2o_ppe_tool" "$@" 2>/dev/null
}

r2o_ppe_available() {
    case "$1" in
        iptables) _r2o_ppe_targets=$R2O_PPE_PROC/ip_tables_targets ;;
        ip6tables) _r2o_ppe_targets=$R2O_PPE_PROC/ip6_tables_targets ;;
        *) return 1 ;;
    esac
    command -v "$1" >/dev/null 2>&1 && grep -qx "$R2O_PPE_TARGET" "$_r2o_ppe_targets" 2>/dev/null
}

_r2o_ppe_rules() {
    _r2o_ppe_tail="-m connskip --connskip $R2O_PPE_CONNSKIP -m comment --comment $R2O_PPE_TAG -j $R2O_PPE_TARGET"
    for _r2o_ppe_proto in tcp udp; do
        if [ "$_r2o_ppe_proto" = tcp ]; then _r2o_ppe_ports=$R2O_PPE_TCP_PORTS
        else _r2o_ppe_ports=$R2O_PPE_UDP_PORTS; fi
        printf 'PREROUTING|-p %s -m multiport --dports %s %s\n' "$_r2o_ppe_proto" "$_r2o_ppe_ports" "$_r2o_ppe_tail"
        printf 'FORWARD|-p %s -m multiport --dports %s %s\n' "$_r2o_ppe_proto" "$_r2o_ppe_ports" "$_r2o_ppe_tail"
        printf 'FORWARD|-p %s -m multiport --sports %s %s\n' "$_r2o_ppe_proto" "$_r2o_ppe_ports" "$_r2o_ppe_tail"
    done
    _r2o_ppe_tail="-m connskip --connskip $R2O_PPE_HTTP_CONNSKIP -m comment --comment $R2O_PPE_TAG -j $R2O_PPE_TARGET"
    printf 'PREROUTING|-p tcp -m multiport --dports %s %s\n' "$R2O_PPE_HTTP_PORTS" "$_r2o_ppe_tail"
    printf 'FORWARD|-p tcp -m multiport --dports %s %s\n' "$R2O_PPE_HTTP_PORTS" "$_r2o_ppe_tail"
}

_r2o_ppe_owned() {
    for _r2o_ppe_chain in PREROUTING FORWARD; do
        _r2o_ppe_ipt "$1" -t mangle -S "$_r2o_ppe_chain" |
            awk -v chain="$_r2o_ppe_chain" -v tag="$R2O_PPE_TAG" '
                $1 == "-A" && $2 == chain {
                    for (i = 3; i < NF; i++)
                        if ($i == "--comment" && ($(i + 1) == tag || $(i + 1) == "\"" tag "\"")) {
                            sub(/^-A [^ ]+ /, "")
                            print chain "|" $0
                            break
                        }
                }'
    done
}

_r2o_ppe_remove_family() {
    _r2o_ppe_owned "$1" | while IFS='|' read -r _r2o_ppe_chain _r2o_ppe_args; do
        [ -n "$_r2o_ppe_chain" ] || continue
        # shellcheck disable=SC2086 # iptables -S returns shell-style rule words
        _r2o_ppe_ipt "$1" -t mangle -D "$_r2o_ppe_chain" $_r2o_ppe_args || true
    done
}

r2o_ppe_remove() {
    for _r2o_ppe_tool in iptables ip6tables; do
        command -v "$_r2o_ppe_tool" >/dev/null 2>&1 || continue
        _r2o_ppe_remove_family "$_r2o_ppe_tool"
    done
}

_r2o_ppe_count() {
    _r2o_ppe_owned "$1" | grep -c . || true
}

_r2o_ppe_ensure_family() {
    _r2o_ppe_rc=0
    while IFS='|' read -r _r2o_ppe_chain _r2o_ppe_args; do
        [ -n "$_r2o_ppe_chain" ] || continue
        # shellcheck disable=SC2086 # iptables rule arguments are validated port lists
        if ! _r2o_ppe_ipt "$1" -t mangle -C "$_r2o_ppe_chain" $_r2o_ppe_args; then
            # shellcheck disable=SC2086 # iptables rule arguments are validated port lists
            _r2o_ppe_ipt "$1" -t mangle -I "$_r2o_ppe_chain" $_r2o_ppe_args || _r2o_ppe_rc=1
        fi
    done <<RULES
$(_r2o_ppe_rules)
RULES
    return "$_r2o_ppe_rc"
}

r2o_ppe_ensure() {
    r2o_ppe_valid_config || { echo "r2o-ppe: неверная конфигурация" >&2; return 1; }
    if [ "$R2O_PPE_DEOFFLOAD" = 0 ]; then
        r2o_ppe_remove
        return 3
    fi
    r2o_ppe_available iptables || return 2
    _r2o_ppe_ensure_family iptables || return 1
    if r2o_ppe_available ip6tables; then
        _r2o_ppe_ensure_family ip6tables || return 1
    fi
    return 0
}

r2o_ppe_status() {
    r2o_ppe_valid_config || { echo "  PPE: неверная конфигурация"; return 1; }
    if [ "$R2O_PPE_DEOFFLOAD" = 0 ]; then
        echo "  PPE: выключена настройкой R2O_PPE_DEOFFLOAD=0"
    elif ! r2o_ppe_available iptables; then
        echo "  PPE: недоступна — в прошивке нет цели $R2O_PPE_TARGET"
    else
        _r2o_ppe_want=$(printf '%s\n' "$(_r2o_ppe_rules)" | grep -c .)
        _r2o_ppe_n4=$(_r2o_ppe_count iptables)
        _r2o_ppe_line="IPv4: $_r2o_ppe_n4 из $_r2o_ppe_want правил"
        _r2o_ppe_full=1
        [ "$_r2o_ppe_n4" -ge "$_r2o_ppe_want" ] || _r2o_ppe_full=0
        if r2o_ppe_available ip6tables; then
            _r2o_ppe_n6=$(_r2o_ppe_count ip6tables)
            _r2o_ppe_line="$_r2o_ppe_line, IPv6: $_r2o_ppe_n6 из $_r2o_ppe_want"
            [ "$_r2o_ppe_n6" -ge "$_r2o_ppe_want" ] || _r2o_ppe_full=0
        fi
        if [ "$_r2o_ppe_full" = 1 ]; then
            echo "  PPE: включена ($_r2o_ppe_line, первые $R2O_PPE_CONNSKIP пакетов)"
        else
            echo "  PPE: установлена не полностью ($_r2o_ppe_line)"
        fi
        echo "  PPE: после окна connskip поток может снова уйти в аппаратный путь; существующие bindings не сбрасываются"
    fi
    if [ -r "$R2O_PPE_BINDS" ]; then
        _r2o_ppe_binds=$(grep -cv '^[[:space:]]*PPE[0-9]*:[[:space:]]*$' "$R2O_PPE_BINDS" 2>/dev/null || true)
        echo "  PPE binds: ${_r2o_ppe_binds:-0} записей в $R2O_PPE_BINDS"
    else
        echo "  PPE binds: нет ($R2O_PPE_BINDS не читается)"
    fi
}

case "${1:-}" in
    ensure) r2o_ppe_ensure ;;
    remove) r2o_ppe_remove ;;
    status)
        shift
        [ "$#" -le 1 ] || { echo "usage: $0 status [IPv4-address]" >&2; exit 2; }
        r2o_ppe_status
        ;;
    *) echo "usage: $0 {ensure|remove|status [IPv4-address]}" >&2; exit 2 ;;
esac
