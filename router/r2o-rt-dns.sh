#!/bin/sh
# DNS RuTracker: собственные записи и маршруты без глобального отключения IPv6.
# Keenetic: штатный NDM + отдельный dnsmasq; OpenWrt: штатный UCI/dnsmasq.
set -u

ROOT=${R2O_DIR:-/opt/r2o}
CONF=${R2O_CONFIG:-$ROOT/config}
# shellcheck disable=SC1090 # путь конфигурации задаётся владельцем установки
[ ! -r "$CONF" ] || . "$CONF"
STATE=${R2O_STATE_DIR:-${STATE_DIR:-$ROOT/state}}/rt-dns
RUN=${R2O_RUN_DIR:-$ROOT/run}
SENTINEL=${R2O_RT_SENTINEL:-203.0.113.171}
DOMAINS=${R2O_RT_DOMAINS:-"rutracker.org www.rutracker.org rutracker.wiki api.rutracker.cc rep.rutracker.cc static.rutracker.cc"}
PORT=${R2O_RT_DNS_PORT:-5354}
QUERY_ADDRESS=${R2O_RT_DNS_QUERY_ADDRESS:-127.0.0.1}
QUERY_PORT=${R2O_RT_DNS_QUERY_PORT:-53}
DNSMASQ=${R2O_RT_DNSMASQ_BIN:-dnsmasq}
NDMC=${R2O_RT_DNS_NDMC_BIN:-ndmc}
UCI=${R2O_RT_DNS_UCI_BIN:-uci}
NC=${R2O_RT_DNS_NC_BIN:-nc}
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
LOCK=$RUN/rt-dns.lock
WORK=
LOCKED=0
PAUSE_HZ=1
PAUSE_MODE=seconds
TAB=$(printf '\t')

say() { printf 'r2o rt-dns: %s\n' "$*" >&2; }
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

# Ограничивается именно дочерняя команда, без /bin/sh -c и его argv-обёртки NDM.
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
    uci_do -X -q show dhcp >"$WORK/uci-config" || return 1
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
remember() {
    # Журнал пишется перед изменением: следующий clear восстановит и оборванный apply.
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OWNED"
}
owned_has() {
    [ -f "$OWNED" ] && grep -Fqx "$(printf '%s\t%s\t%s' "$1" "$2" "$3")" "$OWNED"
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
    bounded "$WORK/legacy-reload" --timeout 20 "$DNS_INIT" reload && dns_ready || return 1
    while IFS="$TAB" read -r legacy_name legacy_domain legacy_ip; do
        grep -Fxq "$legacy_domain" "$WORK/legacy-preserved" && continue
        legacy_exact "$legacy_name" "$legacy_domain" "$legacy_ip" && return 1
        list_has "dhcp.$legacy_dnsmasq.server" "/$legacy_domain/" && return 1
    done <"$LEGACY_PLAN"
    rm -f "$LEGACY_BACKUP" "$LEGACY_PLAN" "$LEGACY_SECTION" "$LEGACY_ALLOWED"
}

dns_running() {
    [ -s "$PIDFILE" ] || return 1
    dns_pid=$(cat "$PIDFILE") || return 1
    case "$dns_pid" in ''|*[!0-9]*) return 1 ;; esac
    alive "$dns_pid" || return 1
    [ -r "/proc/$dns_pid/cmdline" ] || return 1
    tr '\000' '\n' <"/proc/$dns_pid/cmdline" | grep -Fxq -- "--conf-file=$DNSCONF"
}
dns_stop() {
    if dns_running; then
        kill -TERM "$dns_pid" 2>/dev/null || return 1
        dns_step=0
        while alive "$dns_pid" && [ "$dns_step" -lt "$((2 * PAUSE_HZ))" ]; do
            pause
            dns_step=$((dns_step + 1))
        done
        if alive "$dns_pid"; then
            kill -KILL "$dns_pid" 2>/dev/null || return 1
        fi
    elif [ -s "$PIDFILE" ]; then
        dns_other=$(cat "$PIDFILE")
        case "$dns_other" in ''|*[!0-9]*) ;; *)
            if alive "$dns_other"; then
                say 'PID DNS принадлежит другому процессу; он не остановлен'
                return 1
            fi ;;
        esac
    fi
    rm -f "$PIDFILE"
}
render_dns() {
    cat <<EOF
# r2o-rt-dns-v1
port=$PORT
listen-address=127.0.0.1
bind-interfaces
no-hosts
no-resolv
no-poll
cache-size=0
local-ttl=0
pid-file=$PIDFILE
log-facility=$STATE/dnsmasq.log
EOF
    while IFS= read -r render_domain; do
        printf 'address=/%s/%s\nlocal=/%s/\n' "$render_domain" "$SENTINEL" "$render_domain"
    done <"$WORK/domains"
}
dns_start() {
    render_dns >"$WORK/dnsmasq.conf"
    if [ -f "$DNSCONF" ] && ! cmp -s "$WORK/dnsmasq.conf" "$DNSCONF"; then
        say 'локальная конфигурация DNS изменена; сначала требуется clear'
        return 1
    fi
    dns_running && return 0
    dns_stop || return 1
    cp "$WORK/dnsmasq.conf" "$DNSCONF" || return 1
    bounded "$WORK/dnsmasq-test" "$DNSMASQ" --test "--conf-file=$DNSCONF" || return 1
    bounded "$WORK/dnsmasq-start" "$DNSMASQ" "--conf-file=$DNSCONF" || {
        say 'dnsmasq не запустился; проверьте rt-dns/dnsmasq.log и занятость порта'
        return 1
    }
    dns_running
}

# DNS-over-TCP доступен даже в минимальном BusyBox nc из Entware.
# Проверяется DNS-пакет целиком, а не текст nslookup или только наличие процесса.
dns_response_complete() {
    [ -s "$WORK/response" ] || return 1
    probe_size=$(wc -c <"$WORK/response")
    [ "$probe_size" -ge 2 ] || return 1
    # shellcheck disable=SC2046 # hexdump выдаёт ровно два десятичных байта
    set -- $(hexdump -n 2 -e '1/1 "%u "' "$WORK/response")
    probe_expected=$(($1 * 256 + $2 + 2))
    [ "$probe_expected" -le 4096 ] || { probe_broken=1; return 1; }
    [ "$probe_size" -ge "$probe_expected" ]
}
dns_probe() {
    probe_address=$1
    probe_port=$2
    probe_domain=$3
    probe_type=$4
    probe_mode=${5:-record}
    probe_length=$((${#probe_domain} + 18))
    {
        printf '%b' "\\$(printf '%03o' "$((probe_length / 256))")\\$(printf '%03o' "$((probe_length % 256))")"
        printf '\122\062\001\000\000\001\000\000\000\000\000\000'
        printf '%s' "$probe_domain" | tr '.' '\n' | while IFS= read -r probe_label || [ -n "$probe_label" ]; do
            printf '%b%s' "\\$(printf '%03o' "${#probe_label}")" "$probe_label"
        done
        printf '\000\000'
        printf '%b' "\\$(printf '%03o' "$probe_type")"
        printf '\000\001'
    } >"$WORK/query"
    # Файл создаётся до fork: родитель не должен читать прежний ответ или
    # опережать перенаправление stdout в ещё не запущенном дочернем процессе.
    : >"$WORK/response" || return 1
    "$NC" "$probe_address" "$probe_port" <"$WORK/query" >>"$WORK/response" 2>"$WORK/nc-error" &
    probe_pid=$!
    probe_step=0
    probe_complete=0
    probe_broken=0
    while [ "$probe_step" -lt "$((2 * PAUSE_HZ))" ]; do
        if dns_response_complete; then probe_complete=1; break; fi
        [ "$probe_broken" = 0 ] || break
        if ! alive "$probe_pid"; then
            # После выхода nc файл уже стабилен: повторное чтение закрывает
            # гонку, когда ответ записан между первым чтением и проверкой PID.
            dns_response_complete && probe_complete=1
            break
        fi
        pause
        probe_step=$((probe_step + 1))
    done
    kill -TERM "$probe_pid" 2>/dev/null || true
    kill -KILL "$probe_pid" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
    [ "$probe_complete" = 1 ] || return 1
    hexdump -v -e '1/1 "%u "' "$WORK/response" | awk \
        -v wanted="$probe_type" -v wanted_name="$probe_domain" -v ip="$SENTINEL" -v mode="$probe_mode" '
        { for (i=1;i<=NF;i++) b[++n]=$i }
        function word(p) { return b[p]*256+b[p+1] }
        function read_name(p, l, steps, target, endpos, result, j) {
            name_ok=0; name_follow=0; result=""
            for (steps=0; steps<128 && p<=n; steps++) {
                if(p<15) return ""
                l=b[p]
                if(l==0) {
                    name_follow=(endpos ? endpos : p+1); name_ok=1
                    return tolower(result)
                }
                if(l>=192) {
                    if(p+1>n) return ""
                    target=(l-192)*256+b[p+1]+3
                    if(target<15 || target>=p) return ""
                    if(!endpos) endpos=p+2
                    p=target; continue
                }
                if(l>63 || p+l>n) return ""
                if(length(result)) result=result "."
                for(j=1;j<=l;j++) result=result sprintf("%c",b[p+j])
                if(length(result)>253) return ""
                p+=l+1
            }
            return ""
        }
        END {
            if(n<14 || word(1)+2!=n || word(3)!=21042 || b[5]<128 || word(7)!=1) exit 1
            if(int(b[5]/8)%16!=0 || int(b[5]/2)%2!=0) exit 1
            question_name=read_name(15); p=name_follow
            if(!name_ok || question_name!=wanted_name || p+3>n || word(p)!=wanted || word(p+2)!=1) exit 1
            if(mode=="ready") exit 0
            if(b[6]%16!=0) exit 1
            p+=4; count=word(9)
            if(wanted!=1) { if(count!=0) exit 1; exit 0 }
            if(count!=1) exit 1
            answer_name=read_name(p); p=name_follow
            if(!name_ok || answer_name!=wanted_name || p+13>n || word(p)!=1 || word(p+2)!=1 || word(p+8)!=4) exit 1
            got=b[p+10] "." b[p+11] "." b[p+12] "." b[p+13]
            if(got!=ip) exit 1
        }'
}
dns_ready() {
    # procd reload может завершиться до открытия нового слушателя. Даже clear
    # ждёт настоящий DNS-ответ; код ответа localhost здесь не задаёт политику.
    ready_attempt=0
    while [ "$ready_attempt" -lt 5 ]; do
        dns_probe "$QUERY_ADDRESS" "$QUERY_PORT" localhost 1 ready && return 0
        ready_attempt=$((ready_attempt + 1))
        sleep 1
    done
    say 'DNS-сервис не вернулся после reload; журнал сохранён для повторной очистки'
    return 1
}
verify_dns() {
    # Проверки ограничены восемью одновременными TCP-соединениями. На OpenWrt
    # минимальный sleep умеет только целые секунды: последовательные 24 запроса
    # иначе растянули бы status почти на минуту.
    verify_pids=
    verify_count=0
    verify_index=0
    while IFS= read -r verify_domain; do
        for verify_type in 1 28 64 65; do
            verify_index=$((verify_index + 1))
            verify_job=$WORK/probe.$verify_index
            mkdir "$verify_job" || return 1
            (
                trap - EXIT HUP INT TERM
                WORK=$verify_job
                if dns_probe "$QUERY_ADDRESS" "$QUERY_PORT" "$verify_domain" "$verify_type"; then
                    exit 0
                fi
                say "DNS $QUERY_ADDRESS:$QUERY_PORT не подтвердил $verify_domain, тип $verify_type"
                exit 1
            ) &
            verify_pids="$verify_pids $!"
            verify_count=$((verify_count + 1))
            if [ "$verify_count" -eq 8 ]; then
                verify_wait || return 1
                verify_pids=
                verify_count=0
            fi
        done
    done <"$WORK/domains"
    verify_wait
}
verify_wait() {
    verify_failed=0
    for verify_pid in $verify_pids; do wait "$verify_pid" || verify_failed=1; done
    [ "$verify_failed" = 0 ]
}

ndm_expected() {
    while IFS= read -r expected_domain; do
        grep -Fqx "ip host $expected_domain $SENTINEL" "$WORK/ndm-config" || return 1
        grep -Fqx "ip name-server 127.0.0.1:$PORT $expected_domain" "$WORK/ndm-config" || return 1
    done <"$WORK/domains"
}
ndm_apply() {
    ndm_read || return 1
    # Чужие адреса и маршруты для этих имён не заменяются даже временно.
    while IFS= read -r apply_domain; do
        if awk -v h="$apply_domain" -v ip="$SENTINEL" -v ep="127.0.0.1:$PORT" '
            $1=="ip" && $2=="host" && $3==h && $4!=ip { found=1 }
            $1=="ip" && $2=="name-server" && $4==h && ($3!=ep || NF!=4) { found=1 }
            END { exit !found }' "$WORK/ndm-config"; then
            say "пользовательская DNS-запись или маршрут $apply_domain конфликтует с RuTracker"
            return 1
        fi
    done <"$WORK/domains"
    dns_start || return 1
    while IFS= read -r apply_domain; do
        if ! grep -Fqx "ip host $apply_domain $SENTINEL" "$WORK/ndm-config"; then
            owned_has ndm-host "$apply_domain" "$SENTINEL" || remember ndm-host "$apply_domain" "$SENTINEL" || return 1
            ndm "ip host $apply_domain $SENTINEL" || return 1
        fi
        if ! grep -Fqx "ip name-server 127.0.0.1:$PORT $apply_domain" "$WORK/ndm-config"; then
            owned_has ndm-server "$apply_domain" "127.0.0.1:$PORT" || remember ndm-server "$apply_domain" "127.0.0.1:$PORT" || return 1
            ndm "ip name-server 127.0.0.1:$PORT $apply_domain" || return 1
        fi
    done <"$WORK/domains"
    ndm_read && ndm_expected && verify_dns && ndm 'system configuration save'
}
uci_expected() {
    while IFS= read -r expected_section; do
        while IFS= read -r expected_domain; do
            list_has "dhcp.$expected_section.address" "/$expected_domain/$SENTINEL" || return 1
            list_has "dhcp.$expected_section.server" "/$expected_domain/" || return 1
        done <"$WORK/domains"
    done <"$WORK/sections"
}
uci_apply() {
    uci_read || return 1
    [ -z "$(uci_do -q changes dhcp)" ] || { say 'в UCI уже есть несохранённые изменения dhcp'; return 1; }
    while IFS= read -r apply_section; do
        while IFS= read -r apply_domain; do
            for apply_kind in address server; do
                apply_key=dhcp.$apply_section.$apply_kind
                apply_value=/$apply_domain/
                [ "$apply_kind" != address ] || apply_value=$apply_value$SENTINEL
                for existing_value in $(uci_do -q get "$apply_key" 2>/dev/null || true); do
                    case "$existing_value" in
                        */"$apply_domain"/*)
                            [ "$existing_value" = "$apply_value" ] || {
                                say "пользовательское $apply_key конфликтует с $apply_domain"
                                return 1
                            } ;;
                    esac
                done
            done
        done <"$WORK/domains"
    done <"$WORK/sections"
    # hostrecord/domain имеют приоритет над address; чужой конфликт не скрывается.
    for existing_section in $(sed -n 's/^dhcp\.\([A-Za-z0-9_]*\)=\(hostrecord\|domain\)$/\1/p' "$WORK/uci-config"); do
        for existing_name in $(uci_do -q get "dhcp.$existing_section.name" 2>/dev/null || true); do
            if grep -Fxq "$existing_name" "$WORK/domains"; then
                [ "$(uci_do -q get "dhcp.$existing_section.ip" 2>/dev/null || true)" = "$SENTINEL" ] || {
                    say "пользовательская секция $existing_section задаёт другой адрес $existing_name"
                    return 1
                }
            fi
        done
    done
    uci_changed=0
    while IFS= read -r apply_section; do
        while IFS= read -r apply_domain; do
            for apply_kind in address server; do
                apply_key=dhcp.$apply_section.$apply_kind
                apply_value=/$apply_domain/
                [ "$apply_kind" != address ] || apply_value=$apply_value$SENTINEL
                if ! list_has "$apply_key" "$apply_value"; then
                    owned_has uci "$apply_key" "$apply_value" || remember uci "$apply_key" "$apply_value" || return 1
                    uci_do add_list "$apply_key=$apply_value" || return 1
                    uci_changed=1
                fi
            done
        done <"$WORK/domains"
    done <"$WORK/sections"
    if [ "$uci_changed" = 1 ]; then
        uci_pending_owned && uci_do commit dhcp && bounded "$WORK/dnsmasq-reload" --timeout 20 "$DNS_INIT" reload && dns_ready || return 1
    fi
    uci_read && uci_expected && verify_dns
}

clear_owned() {
    legacy_clear || return 1
    [ -f "$BACKEND_FILE" ] || return 0
    clear_backend=$(cat "$BACKEND_FILE")
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
                    ndm "no ip host $own_key $own_value" || clear_failed=1
                    clear_changed=1
                fi ;;
            ndm-server)
                [ "$clear_backend" = keenetic ] && valid_domain "$own_key" || return 1
                case "$own_value" in 127.0.0.1:*) valid_port "${own_value#*:}" || return 1 ;; *) return 1 ;; esac
                if grep -Fqx "ip name-server $own_value $own_key" "$WORK/ndm-config"; then
                    ndm "no ip name-server $own_value $own_key" || clear_failed=1
                    clear_changed=1
                fi ;;
            uci)
                [ "$clear_backend" = openwrt ] || return 1
                printf '%s\n' "$own_key" | grep -Eq '^dhcp\.[A-Za-z0-9_]+\.(address|server)$' || return 1
                if list_has "$own_key" "$own_value"; then
                    uci_do -q del_list "$own_key=$own_value" || clear_failed=1
                    clear_changed=1
                fi ;;
            '') ;;
            *) say 'неизвестная запись ownership'; return 1 ;;
        esac
    done <"$WORK/reverse"
    if [ "$clear_backend" = keenetic ]; then
        if [ "$clear_changed" = 1 ]; then ndm 'system configuration save' || clear_failed=1; fi
        [ "$clear_failed" = 0 ] || return 1
        ndm_read || return 1
        while IFS="$TAB" read -r own_kind own_key own_value; do
            case "$own_kind" in
                ndm-host) grep -Fqx "ip host $own_key $own_value" "$WORK/ndm-config" && return 1 ;;
                ndm-server) grep -Fqx "ip name-server $own_value $own_key" "$WORK/ndm-config" && return 1 ;;
            esac
        done <"$OWNED"
        dns_stop || return 1
        rm -f "$DNSCONF"
    else
        # Повторный clear повторяет reload, если предыдущий reload завершился ошибкой.
        if [ -s "$OWNED" ]; then
            uci_pending_owned && uci_do commit dhcp && bounded "$WORK/dnsmasq-reload" --timeout 20 "$DNS_INIT" reload && dns_ready || clear_failed=1
        fi
        [ "$clear_failed" = 0 ] || return 1
    fi
    rm -f "$OWNED" "$REQUEST" "$BACKEND_FILE"
}

cleanup() {
    [ -z "$WORK" ] || rm -rf "$WORK"
    if [ "$LOCKED" = 1 ]; then rm -f "$LOCK/pid"; rmdir "$LOCK" 2>/dev/null || true; fi
}

case "${1:-}" in apply|status|clear) ACTION=$1 ;; *) say 'использование: r2o-rt-dns.sh {apply|status|clear}'; exit 2 ;; esac
umask 077
mkdir -p "$STATE" "$RUN" || exit 1
if ! mkdir "$LOCK" 2>/dev/null; then
    lock_pid=$(cat "$LOCK/pid" 2>/dev/null || true)
    case "$lock_pid" in ''|*[!0-9]*) say 'DNS занят незавершённой операцией'; exit 1 ;; esac
    alive "$lock_pid" && { say 'DNS занят другой операцией'; exit 1; }
    rm -f "$LOCK/pid"
    rmdir "$LOCK" 2>/dev/null && mkdir "$LOCK" || exit 1
fi
LOCKED=1
printf '%s\n' "$$" >"$LOCK/pid"
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
WORK=$(mktemp -d "$RUN/rt-dns.XXXXXX") || exit 1
select_clock

if [ "$ACTION" = clear ]; then clear_owned; exit $?; fi
valid_ip "$SENTINEL" && valid_ip "$QUERY_ADDRESS" && valid_port "$PORT" && valid_port "$QUERY_PORT" || {
    say 'неверный IPv4-адрес или порт'; exit 2;
}
# В минимальном OpenWrt tr собран без классов [:space:]/[:upper:].
printf '%s\n' "$DOMAINS" | awk '{for(i=1;i<=NF;i++) print tolower($i)}' | sort -u >"$WORK/domains"
[ -s "$WORK/domains" ] || { say 'список доменов пуст'; exit 2; }
while IFS= read -r domain; do valid_domain "$domain" || { say "неверное доменное имя: $domain"; exit 2; }; done <"$WORK/domains"
command -v "$NC" >/dev/null 2>&1 || { say 'нет nc для проверки фактического DNS-ответа'; exit 1; }
case "${R2O_PLATFORM:-}" in
    keenetic|openwrt) BACKEND=$R2O_PLATFORM ;;
    '') if command -v "$NDMC" >/dev/null 2>&1; then BACKEND=keenetic; else BACKEND=openwrt; fi ;;
    *) say 'неподдерживаемая платформа'; exit 2 ;;
esac
{
    printf '%s\n%s\n%s\n' "$BACKEND" "$SENTINEL" "$PORT"
    cat "$WORK/domains"
} >"$WORK/request"
if [ -f "$REQUEST" ] && ! cmp -s "$REQUEST" "$WORK/request"; then
    say 'DNS-параметры изменились; сначала выполните clear для прежней конфигурации'
    exit 1
fi
if [ "$ACTION" = status ]; then
    [ -f "$REQUEST" ] && [ -f "$BACKEND_FILE" ] || exit 1
    case "$BACKEND" in
        keenetic) dns_running && ndm_read && ndm_expected && verify_dns ;;
        openwrt) uci_read && uci_expected && verify_dns ;;
    esac
    exit $?
fi
[ "$BACKEND" != openwrt ] || legacy_clear || exit 1
printf '%s\n' "$BACKEND" >"$BACKEND_FILE"
cp "$WORK/request" "$REQUEST" || exit 1
[ -f "$OWNED" ] || : >"$OWNED"
case "$BACKEND" in
    keenetic) ndm_apply && exit 0 ;;
    openwrt) uci_apply && exit 0 ;;
esac
say 'применение DNS не завершилось; откатываю только собственные изменения'
clear_owned || say 'откат не завершён; журнал сохранён для повторного clear'
exit 1
