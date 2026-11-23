#!/bin/sh
# Signed OpenWrt/Keenetic bootstrap. Release code is executed only after both
# the pinned Ed25519 manifest signature and its archive SHA-256 are verified.
set -eu

PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}
export PATH

REPO=t0fox/r2o
LATEST=https://github.com/$REPO/releases/latest/download
RELEASE_API=https://api.github.com/repos/$REPO/releases/tags
PUBLIC_KEY_B64='MCowBQYDK2VwAyEAx2b2eh9ZlnOOzizkMWUMNHdDIJNcIc4fO4i1psTUESc='
OPENWRT_RELEASE=${R2O_OPENWRT_RELEASE:-/etc/openwrt_release}
ENTWARE_OPKG=${R2O_ENTWARE_OPKG:-/opt/bin/opkg}
SYSTEM_PATH=/usr/sbin:/usr/bin:/sbin:/bin
NDM_MARKER=${R2O_NDM_PLATFORM_DIR:-/opt/etc/ndm}
export LC_ALL=C
MEMINFO=${R2O_MEMINFO_FILE:-/proc/meminfo}
ROOT=${R2O_DIR:-/opt/r2o}
INIT_DIR=${R2O_INIT_DIR:-/opt/etc/init.d}
NDM_DIR=${R2O_NDM_DIR:-/opt/etc/ndm/netfilter.d}
OPENWRT_INIT_DIR=${R2O_OPENWRT_INIT_DIR:-/etc/init.d}
RUNTIME_DIR=${R2O_RUNTIME_DIR:-/tmp/r2o}
TMP_BASE=${TMPDIR:-/tmp}
PROC_DIR=${R2O_PROC_DIR:-/proc}
NFQUEUE_STATUS_FILE=${R2O_NFQUEUE_STATUS_FILE:-$PROC_DIR/net/netfilter/nfnetlink_queue}
MODULE_DIR=${R2O_SYS_MODULE_DIR:-/sys/module}
MAX_ARCHIVE_BYTES=67108864
MAX_EXPANDED_KB=24576
RAM_RESERVE_KB=16384
DEPENDENCY_RESERVE_KB=2048
LOCAL_MANIFEST=${R2O_LOCAL_MANIFEST:-}
LOCAL_SIGNATURE=${R2O_LOCAL_SIGNATURE:-}
LOCAL_ARCHIVE=${R2O_LOCAL_ARCHIVE:-}
PLATFORM=
ARCH=
CURRENT_RELEASE=
PREVIOUS_RELEASE=
TARGET_RELEASE=
INSTALL_STARTED=0
ROOT_PREEXISTED=0
TMP=
DISK_TMP=
BUNDLE=
ARCHIVE=
BOOTSTRAP_APK=
RT_DNS_INIT_BACKUP=
RT_DNS_INIT_DEST=
RT_DNS_NEW_INIT=

say() { echo "r2o: $*"; }
die() { echo "r2o: $*" >&2; exit 1; }

cleanup() {
    if ! restore_keenetic_rt_dns_init; then
        say "не удалось восстановить init dnsmasq; копия сохранена: $RT_DNS_INIT_BACKUP" >&2
        TMP=
    fi
    disable_new_keenetic_rt_dns_init || say "не удалось отключить новый общий init dnsmasq: $RT_DNS_NEW_INIT" >&2
    [ -z "$TMP" ] || rm -rf "$TMP" 2>/dev/null || true
    [ -z "$DISK_TMP" ] || rm -rf "$DISK_TMP" 2>/dev/null || true
    if [ -n "$BOOTSTRAP_APK" ]; then
        "$APK" del "$BOOTSTRAP_APK" >/dev/null ||
            say "не удалось удалить временные зависимости $BOOTSTRAP_APK"
    fi
}

release_from_slots() {
    release_file=$ROOT/release-slots
    [ -e "$ROOT" ] || return 0
    [ -d "$ROOT" ] && [ ! -L "$ROOT" ] || die "каталог $ROOT должен быть обычным каталогом"
    if [ ! -e "$release_file" ] && [ ! -L "$release_file" ]; then
        [ ! -e "$ROOT/releases" ] && [ ! -e "$ROOT/r2o-manager" ] ||
            die "в $ROOT есть неполная или чужая установка; не меняю её автоматически"
        return 0
    fi
    [ ! -L "$release_file" ] && [ -f "$release_file" ] || die "небезопасный файл $release_file"
    [ "$(sed -n '1p' "$release_file")" = R2O-RELEASE-SLOTS-1 ] ||
        die "неизвестный формат состояния выпусков в $release_file"
    CURRENT_RELEASE=$(sed -n '2p' "$release_file")
    PREVIOUS_RELEASE=$(sed -n '3p' "$release_file")
    case "$CURRENT_RELEASE" in ''|.|..|*[!A-Za-z0-9._-]*) die "повреждён активный выпуск в $release_file" ;; esac
    case "$PREVIOUS_RELEASE" in '' ) ;; .|..|*[!A-Za-z0-9._-]*) die "повреждён предыдущий выпуск в $release_file" ;; esac
}

map_openwrt_arch() {
    case "$1" in
        mipsel_24kc*|mipsel-24kc* ) ARCH=mipsel-openwrt-musl ;;
        aarch64*|arm64* ) ARCH=aarch64-openwrt-musl ;;
        arm_cortex-a[0-9]* ) ARCH=armv7-openwrt-musl ;;
        armv7sf* ) ARCH=armv7-musleabi ;;
        mips_24kc*|mips-24kc* ) ARCH=mips-openwrt-musl ;;
        mips64el*|mipsel64* ) ARCH=mips64el-musl ;;
        x86_64*|amd64* ) ARCH=x86_64-musl ;;
        i686*|i386_pentium4* ) ARCH=i686-musl ;;
        ppc64|ppc64-* ) ARCH=powerpc64-musl ;;
        riscv64* ) ARCH=riscv64-musl ;;
        armv5* ) ARCH=armv5-musleabi ;;
        * ) return 1 ;;
    esac
}

map_keenetic_arch() {
    case "$1" in
        mipsel* ) ARCH=mipsel ;;
        aarch64*|arm64* ) ARCH=aarch64-openwrt-musl ;;
        armv7hf* ) ARCH=armv7-openwrt-musl ;;
        armv5* ) ARCH=armv5-musleabi ;;
        * ) return 1 ;;
    esac
}

detect_platform_and_arch() {
    distribution_arch=
    if [ -f "$OPENWRT_RELEASE" ] && ! { [ -d "$NDM_MARKER" ] && [ -x "$ENTWARE_OPKG" ]; }; then
        PLATFORM=openwrt
        APK=$(PATH=$SYSTEM_PATH command -v apk || true)
        OPKG=$(PATH=$SYSTEM_PATH command -v opkg || true)
        distribution_arch=$(sed -n 's/^DISTRIB_ARCH=//p' "$OPENWRT_RELEASE" | head -n 1 | sed "s/['\"]//g")
        if [ -z "$distribution_arch" ]; then
            if [ -n "$APK" ]; then
                distribution_arch=$("$APK" --print-arch 2>/dev/null | head -n 1 || true)
            elif [ -n "$OPKG" ]; then
                distribution_arch=$("$OPKG" print-architecture 2>/dev/null | awk '$1 == "arch" && $2 != "all" { if ($3 + 0 >= priority) { priority=$3 + 0; arch=$2 } } END { print arch }')
            else
                distribution_arch=$(uname -m 2>/dev/null || true)
            fi
        fi
        map_openwrt_arch "$distribution_arch" || die "неподдерживаемая архитектура OpenWrt: ${distribution_arch:-не определена}"
    elif [ -x "$ENTWARE_OPKG" ]; then
        PLATFORM=keenetic
        APK=
        OPKG=$ENTWARE_OPKG
        package_arch=$("$OPKG" print-architecture 2>/dev/null | awk '$1 == "arch" && $2 != "all" && $2 != "noarch" { if ($3 + 0 >= priority) { priority=$3 + 0; arch=$2 } } END { print arch }')
        if [ -n "$package_arch" ]; then
            distribution_arch=$package_arch
        else
            distribution_arch=$(uname -m 2>/dev/null || true)
        fi
        map_keenetic_arch "$distribution_arch" || die "неподдерживаемая архитектура Keenetic/Entware: ${package_arch:-$distribution_arch}"
    else
        die 'система не распознана как OpenWrt или Keenetic с Entware; на Keenetic сначала установите Entware'
    fi
    case "$ARCH" in
        mipsel|mipsel-openwrt-musl|aarch64-openwrt-musl|armv5-musleabi|armv7-openwrt-musl|armv7-musleabi|mips-openwrt-musl|mips64el-musl|x86_64-musl|i686-musl|powerpc64-musl|riscv64-musl) ;;
        *) die "в выпусках R2O нет ABI $ARCH" ;;
    esac
    say "платформа: $PLATFORM; ABI: $distribution_arch -> $ARCH"
}

storage_anchor() {
    storage_path=${ROOT%/*}
    [ -n "$storage_path" ] || storage_path=/
    while [ ! -d "$storage_path" ]; do
        next_path=${storage_path%/*}
        [ -n "$next_path" ] || next_path=/
        [ "$next_path" != "$storage_path" ] || break
        storage_path=$next_path
    done
    [ -d "$storage_path" ] || die "не удалось найти файловую систему для $ROOT"
    STORAGE_PATH=$storage_path
}

free_kb() {
    free_value=$(df -Pk "$1" 2>/dev/null | awk 'NR == 2 { print $4 }')
    case "$free_value" in ''|*[!0-9]*) die "не удалось определить свободное место на $1" ;; esac
    echo "$free_value"
}

memory_available_kb() {
    [ -r "$MEMINFO" ] || die "не удалось прочитать $MEMINFO для проверки RAM"
    memory_value=$(awk '
        /^MemAvailable:/ { available=$2; found=1 }
        /^MemFree:/ { free=$2 }
        /^Buffers:/ { buffers=$2 }
        /^Cached:/ { cached=$2 }
        /^Shmem:/ { shmem=$2 }
        END {
            if (found) print available
            else if (free != "") {
                value=free+buffers+cached-shmem
                if (value > 0) print value
                else print 0
            }
        }
    ' "$MEMINFO")
    case "$memory_value" in ''|*[!0-9]*) die "не удалось определить свободную RAM из $MEMINFO" ;; esac
    echo "$memory_value"
}

check_install_resources() {
    minimum_flash=$DEPENDENCY_RESERVE_KB
    [ -n "$CURRENT_RELEASE" ] || minimum_flash=$((MAX_EXPANDED_KB + DEPENDENCY_RESERVE_KB))
    [ "$(free_kb "$STORAGE_PATH")" -ge "$minimum_flash" ] ||
        die "нужно не менее $minimum_flash КиБ места во flash для выпуска и зависимостей"
    [ "$(memory_available_kb)" -ge "$RAM_RESERVE_KB" ] ||
        die "для установки нужно не менее $RAM_RESERVE_KB КиБ свободной RAM; освободите память и повторите запуск"
}

install_packages() {
    [ "$#" -gt 0 ] || return 0
    check_install_resources
    say "устанавливаю зависимости: $*"
    if [ -n "$APK" ]; then
        "$APK" -U add "$@" || die "apk не установил зависимости. Проверьте репозитории своей прошивки и выполните: $APK update && $APK add $*"
    elif [ -n "$OPKG" ]; then
        [ "${opkg_index_ready:-0}" = 1 ] || "$OPKG" update ||
            die "opkg не обновил индекс. Проверьте сеть и репозитории, затем выполните: $OPKG update"
        opkg_index_ready=1
        "$OPKG" install "$@" || die "opkg не установил зависимости. Проверьте репозитории и выполните: $OPKG install $*"
    else
        die "не найден штатный apk/opkg. Восстановите менеджер пакетов прошивки и установите: $*"
    fi
}

install_bootstrap_dependencies() {
    bootstrap=
    openssl version >/dev/null 2>&1 || bootstrap="$bootstrap openssl-util"
    curl --version >/dev/null 2>&1 || bootstrap="$bootstrap curl"
    have_ca=0
    for ca_file in /etc/ssl/cert.pem /etc/ssl/certs/ca-certificates.crt /opt/etc/ssl/certs/ca-certificates.crt; do
        [ ! -s "$ca_file" ] || have_ca=1
    done
    if [ "$have_ca" -eq 0 ]; then install_packages ca-bundle; fi
    if [ -n "$bootstrap" ]; then
        # На OpenWrt с apk эти пакеты нужны только до передачи управления менеджеру.
        # shellcheck disable=SC2086
        if [ -n "$APK" ]; then
            BOOTSTRAP_APK=".r2o-bootstrap-$$"
            install_packages --virtual "$BOOTSTRAP_APK" $bootstrap
        else
            install_packages $bootstrap
        fi
    fi
    openssl version >/dev/null || die 'openssl не запускается; переустановите openssl-util'
    curl --version >/dev/null || die 'curl не запускается; переустановите curl'
}

runtime_config() {
    config_path=$1
    if [ -e "$config_path" ] || [ -L "$config_path" ]; then
        [ -f "$config_path" ] && [ ! -L "$config_path" ] || die "небезопасный файл конфигурации $config_path"
    fi
    mode=$(runtime_value MODE apply)
    backend=$(runtime_value FW_BACKEND auto)
    ipv6_enabled=$(runtime_value IPV6_ENABLED 1)
    telegram_enabled=$(runtime_value TG_ENABLED 0)
    telegram_mode=$(runtime_value TG_MODE local)
    rt_proxy_enabled=$(runtime_value R2O_RT_PROXY 1)
    case "$mode" in off|observe|apply) ;; *) die "неверный MODE: $mode" ;; esac
    case "$backend" in
        auto)
            backend=iptables
            if [ "$PLATFORM" = openwrt ] && command -v nft >/dev/null 2>&1; then backend=nft; fi ;;
        nft|iptables) ;;
        *) die "неверный FW_BACKEND: $backend" ;;
    esac
    case "$ipv6_enabled" in 0|1) ;; *) die "неверный IPV6_ENABLED: $ipv6_enabled" ;; esac
    case "$telegram_enabled" in 0|no) telegram_enabled=0 ;; 1|yes) telegram_enabled=1 ;; *) die "неверный TG_ENABLED: $telegram_enabled" ;; esac
    [ "$telegram_mode" = local ] || telegram_enabled=0
    case "$rt_proxy_enabled" in 0|1) ;; *) die "неверный R2O_RT_PROXY: $rt_proxy_enabled" ;; esac
}

runtime_value() {
    value=
    if [ -f "$config_path" ]; then
        value=$(sed -n "s/^[[:space:]]*$1=//p" "$config_path" | tail -n 1 |
            sed "s/[[:space:]]#.*//; s/[[:space:]]*$//; s/['\"]//g")
    fi
    printf '%s\n' "${value:-$2}"
}

need_runtime_tool() {
    tool=$1
    package=$2
    shift 2
    if ! "$tool" "$@" >/dev/null 2>&1; then
        case " $runtime_packages " in *" $package "*) ;; *) runtime_packages="$runtime_packages $package" ;; esac
    fi
}

restore_keenetic_rt_dns_init() {
    [ -n "$RT_DNS_INIT_BACKUP" ] || return 0
    restore_init_tmp=$(mktemp "$RT_DNS_INIT_DEST.r2o.XXXXXX") || return 1
    if ! cp -p "$RT_DNS_INIT_BACKUP" "$restore_init_tmp" || ! mv -f "$restore_init_tmp" "$RT_DNS_INIT_DEST"; then
        rm -f "$restore_init_tmp"
        return 1
    fi
    RT_DNS_INIT_BACKUP=
}

disable_new_keenetic_rt_dns_init() {
    [ -n "$RT_DNS_NEW_INIT" ] || return 0
    if [ -e "$RT_DNS_NEW_INIT" ] || [ -L "$RT_DNS_NEW_INIT" ]; then
        [ -f "$RT_DNS_NEW_INIT" ] && [ ! -L "$RT_DNS_NEW_INIT" ] || return 1
        grep -q '^ENABLED=' "$RT_DNS_NEW_INIT" || return 1
        new_init_tmp=$(mktemp "$RT_DNS_NEW_INIT.r2o.XXXXXX") || return 1
        if ! sed 's/^ENABLED=.*/ENABLED=no/' "$RT_DNS_NEW_INIT" > "$new_init_tmp" \
            || ! chmod 0755 "$new_init_tmp" || ! mv -f "$new_init_tmp" "$RT_DNS_NEW_INIT"; then
            rm -f "$new_init_tmp"
            return 1
        fi
    fi
    RT_DNS_NEW_INIT=
}

install_keenetic_rt_dns() {
    # Пакет нужен для частного listener на 127.0.0.1:5354. Его общий S56
    # не должен при следующей загрузке занять порт штатного DNS Keenetic.
    rt_dns_init=${R2O_ENTWARE_DNSMASQ_INIT:-/opt/etc/init.d/S56dnsmasq}
    if [ -e "$rt_dns_init" ] || [ -L "$rt_dns_init" ]; then
        [ -f "$rt_dns_init" ] && [ ! -L "$rt_dns_init" ] || die "небезопасный init dnsmasq: $rt_dns_init"
        # S56 не является conffile opkg: пакет может заменить даже изменённый
        # владельцем файл. Восстанавливаем его и при ошибке установки пакета.
        rt_dns_backup_candidate=$TMP/dnsmasq-init.before
        cp -p "$rt_dns_init" "$rt_dns_backup_candidate" || die 'не удалось сохранить init dnsmasq'
        RT_DNS_INIT_BACKUP=$rt_dns_backup_candidate
        RT_DNS_INIT_DEST=$rt_dns_init
    else
        RT_DNS_NEW_INIT=$rt_dns_init
    fi
    IPKG_NO_SCRIPT=1 install_packages dnsmasq-full
    restore_keenetic_rt_dns_init || die 'не удалось восстановить существующий init dnsmasq'
    disable_new_keenetic_rt_dns_init || die "не удалось отключить общий автозапуск нового dnsmasq: $rt_dns_init"
    dnsmasq --version >/dev/null 2>&1 || die 'dnsmasq не запускается после установки dnsmasq-full'
}

runtime_failure() {
    tool=$1
    package=$2
    shift 2
    if ! "$tool" "$@" > /dev/null 2>"$TMP/runtime-probe.err"; then
        cat "$TMP/runtime-probe.err" >&2
        if [ -n "$APK" ]; then
            die "$tool: проверка $* не прошла. Проверьте прошивку и пакеты: $APK fix $package"
        elif [ -n "$OPKG" ]; then
            die "$tool: проверка $* не прошла. Проверьте поддержку в прошивке и пакет: $OPKG install --force-reinstall $package"
        else
            die "$tool: проверка $* не прошла. Установите штатный пакет $package"
        fi
    fi
}

try_module() {
    modprobe "$1" >/dev/null 2>&1 && return 0
    [ "$PLATFORM" = keenetic ] || return 0
    firmware_modules=${R2O_MODULES_DIR:-/lib/modules}
    kernel=$(uname -r)
    module_file=$firmware_modules/$1.ko
    if [ ! -f "$module_file" ] && [ -d "$firmware_modules/$kernel" ]; then
        module_file=$(find "$firmware_modules/$kernel" -type f -name "$1.ko" | head -n 1)
    fi
    # Только модули прошивки роутера. Entware поставляет программы, а не ядро Keenetic.
    if [ -f "$module_file" ]; then insmod "$module_file" >/dev/null 2>&1 || true; fi
}

nfqueue_core_ready() { [ -r "$NFQUEUE_STATUS_FILE" ]; }

nfqueue_rule_ready() {
    if [ "$backend" = nft ]; then
        # Транзакция nft -c проверяется ядром без фиксации правил.
        nft_queue_check
    else
        # Для backend iptables-nft ядро использует выражение nft_queue.
        case "$(iptables -V 2>/dev/null)" in
            *nf_tables*) nft_queue_check ;;
            *) grep -qw NFQUEUE "$PROC_DIR/net/ip_tables_targets" || [ -d "$MODULE_DIR/xt_NFQUEUE" ] ;;
        esac
    fi
}

nft_queue_check() {
    printf 'table inet r2o_probe_%s {\n chain probe {\n  queue num 65535 bypass\n }\n}\n' "$$" | nft -c -f -
}

select_command_shell() {
    COMMAND_SHELL=/bin/sh
    if [ "$PLATFORM" = keenetic ]; then
        # /bin/sh в Keenetic — NDM wrapper: после -c он теряет $0 и аргументы.
        # Запускаем непосредственно shell из того же Entware, что и opkg.
        COMMAND_SHELL=${ENTWARE_OPKG%/*}/sh
    fi
    [ -x "$COMMAND_SHELL" ] || die "не найдена оболочка запуска $COMMAND_SHELL; проверьте установку Entware/BusyBox"
    "$COMMAND_SHELL" -c '[ "$#" -eq 1 ] && [ "$1" = r2o-shell-probe ]' r2o-shell r2o-shell-probe ||
        die "оболочка $COMMAND_SHELL не сохраняет аргументы -c; проверьте установку Entware/BusyBox"
}

check_datapath() {
    probe_binary=$1
    [ "$mode" != off ] || return 0
    [ -f "$probe_binary" ] && [ ! -L "$probe_binary" ] ||
        die "не найден datapath для $ARCH: $probe_binary"
    select_command_shell
    # Те же флаги start-stop-daemon, что у службы, но с отдельными PID и журналом.
    if start-stop-daemon -S -b -m -p "$TMP/preflight.pid" -x "$COMMAND_SHELL" -- -c '
        "$1" --offline-self-check >"$2/datapath-probe.log" 2>&1
        printf "%s\n" "$?" >"$2/datapath-probe.done"
    ' sh "$probe_binary" "$TMP"; then :; else
        die "start-stop-daemon не запустил проверку datapath (код $?). Проверьте пакет busybox: ${OPKG:+$OPKG install --force-reinstall busybox}${APK:+$APK fix busybox}"
    fi
    for _ in 1 2 3 4 5; do
        [ ! -s "$TMP/datapath-probe.done" ] || break
        sleep 1
    done
    probe_status=$(cat "$TMP/datapath-probe.done" 2>/dev/null || true)
    if [ "$probe_status" != 0 ]; then
        [ ! -s "$TMP/datapath-probe.log" ] || tail -n 80 "$TMP/datapath-probe.log" >&2
        if [ -n "$probe_status" ]; then
            die "datapath не запустился через start-stop-daemon для $ARCH (код $probe_status): $probe_binary. Проверьте ABI и параметры монтирования командой mount"
        fi
        die "datapath не завершил проверку запуска для $ARCH за 5 с: $probe_binary. Проверьте журнал ядра командой dmesg"
    fi
    # Старые подписанные выпуски проверяются системными пробами выше.
    if "$probe_binary" --help > "$TMP/datapath-help" 2>/dev/null &&
        grep -Fq -- --runtime-preflight "$TMP/datapath-help"; then
        "$probe_binary" --runtime-preflight "$mode" "$ipv6_enabled" ||
            die "ядро или права запуска datapath не прошли проверку; $remedy"
    fi
}

check_runtime_dependencies() {
    [ "$mode" != off ] || return 0
    runtime_packages=
    ipt_package=iptables
    ip6t_package=iptables
    ipt_queue_package=iptables
    if [ "$PLATFORM" = openwrt ]; then
        ipt_package=iptables-zz-legacy
        ip6t_package=ip6tables-zz-legacy
        ipt_queue_package=iptables-mod-nfqueue
    fi
    # Реальный запуск проверяется отдельно, без необязательного флага -t у BusyBox.
    command -v start-stop-daemon >/dev/null 2>&1 || runtime_packages=busybox
    need_runtime_tool ip ip-full -4 -o addr show scope global
    need_runtime_tool conntrack conntrack -V
    if [ "$backend" = nft ]; then
        need_runtime_tool nft nftables-nojson --version
    else
        need_runtime_tool iptables "$ipt_package" -V
        if [ "$rt_proxy_enabled" -eq 1 ]; then need_runtime_tool iptables-restore "$ipt_package" --help; fi
        if [ "$ipv6_enabled" -eq 1 ]; then need_runtime_tool ip6tables "$ip6t_package" -V; fi
        if [ "$telegram_enabled" -eq 1 ]; then need_runtime_tool ipset ipset --version; fi
    fi
    # shellcheck disable=SC2086
    install_packages $runtime_packages
    if [ "$rt_proxy_enabled" -eq 1 ]; then
        if [ "$PLATFORM" = keenetic ]; then
            dnsmasq --version >/dev/null 2>&1 || install_keenetic_rt_dns
        else
            dnsmasq --version >/dev/null 2>&1 || install_packages dnsmasq
        fi
        command -v nc >/dev/null 2>&1 || install_packages netcat
        command -v nc >/dev/null 2>&1 || die 'нет nc для проверки DNS RuTracker'
    fi

    if [ "$backend" = nft ]; then
        rule_module=nft_queue
        rule_package=kmod-nft-queue
    else
        if ! iptables -j NFQUEUE --queue-num 65535 --queue-bypass --help >/dev/null 2>&1; then
            install_packages "$ipt_queue_package"
        fi
        case "$(iptables -V 2>/dev/null)" in
            *nf_tables*)
                rule_module=nft_queue
                rule_package=kmod-nft-queue
                nft --version >/dev/null 2>&1 || install_packages nftables-nojson ;;
            *) rule_module=xt_NFQUEUE; rule_package=kmod-ipt-nfqueue ;;
        esac
    fi
    nfqueue_core_ready || try_module nfnetlink_queue
    nfqueue_rule_ready >/dev/null 2>&1 || try_module "$rule_module"
    conntrack -C >/dev/null 2>&1 || try_module nf_conntrack_netlink
    if [ "$backend" = iptables ] && [ "$telegram_enabled" -eq 1 ]; then
        ipset list -n >/dev/null 2>&1 || try_module ip_set
    fi

    if [ "$PLATFORM" = openwrt ]; then
        kernel_packages=
        nfqueue_core_ready || kernel_packages="$kernel_packages kmod-nfnetlink-queue"
        nfqueue_rule_ready >/dev/null 2>&1 || kernel_packages="$kernel_packages $rule_package"
        conntrack -C >/dev/null 2>&1 || kernel_packages="$kernel_packages kmod-nf-conntrack-netlink"
        if [ "$backend" = iptables ] && [ "$telegram_enabled" -eq 1 ] &&
            ! ipset list -n >/dev/null 2>&1; then
            kernel_packages="$kernel_packages kmod-ipt-ipset"
        fi
        if [ -n "$kernel_packages" ]; then
            # shellcheck disable=SC2086
            install_packages $kernel_packages
            nfqueue_core_ready || try_module nfnetlink_queue
            nfqueue_rule_ready >/dev/null 2>&1 || try_module "$rule_module"
            conntrack -C >/dev/null 2>&1 || try_module nf_conntrack_netlink
        fi
        remedy="${APK:-$OPKG} install kmod-nfnetlink-queue $rule_package kmod-nf-conntrack-netlink"
        [ -z "$APK" ] || remedy="$APK add kmod-nfnetlink-queue $rule_package kmod-nf-conntrack-netlink"
    else
        remedy="проверьте компоненты ядра прошивки командой: modprobe nfnetlink_queue; modprobe $rule_module; modprobe nf_conntrack_netlink"
    fi

    runtime_failure ip ip-full -4 -o addr show scope global
    nfqueue_core_ready || die "NFQUEUE недоступен: $NFQUEUE_STATUS_FILE не читается; $remedy"
    nfqueue_rule_ready || die "цель NFQUEUE для $backend недоступна; $remedy"
    conntrack -C >/dev/null || die "ядро не отвечает на conntrack -C; $remedy"
    if [ "$backend" = iptables ]; then
        runtime_failure iptables "$ipt_queue_package" -j NFQUEUE --queue-num 65535 --queue-bypass --help
        runtime_failure iptables "$ipt_package" -t mangle -S PREROUTING
        if [ "$ipv6_enabled" -eq 1 ]; then
            runtime_failure ip6tables "$ip6t_package" -t mangle -S PREROUTING
        fi
        if [ "$telegram_enabled" -eq 1 ] || [ "$rt_proxy_enabled" -eq 1 ]; then
            runtime_failure iptables "$ipt_package" -t nat -S OUTPUT
        fi
        if [ "$telegram_enabled" -eq 1 ]; then
            runtime_failure ipset ipset list -n
        fi
    fi
}

github_routes() (
    set -f
    printf '%s\n' direct
    count=0
    # shellcheck disable=SC2086
    for mirror in ${R2O_GITHUB_MIRRORS:-}; do
        [ "${#mirror}" -le 512 ] || continue
        case "$mirror" in https://*) ;; *) continue ;; esac
        case "$mirror" in *'#'*|*'@'*) continue ;; esac
        printf '%s\n' "$mirror"
        count=$((count + 1))
        [ "$count" -lt 4 ] || break
    done
)

github_url() {
    case "$1" in
        direct) printf '%s\n' "$2" ;;
        *'{url}'*) printf '%s%s%s\n' "${1%%\{url\}*}" "$2" "${1#*\{url\}}" ;;
        *'{encoded_url}'*)
            encoded=$(printf '%s' "$2" | sed 's/:/%3A/g; s!/!%2F!g') || return 1
            printf '%s%s%s\n' "${1%%\{encoded_url\}*}" "$encoded" "${1#*\{encoded_url\}}" ;;
        *) printf '%s/%s\n' "${1%/}" "$2" ;;
    esac
}

fetch_one() (
    progress=-sS
    [ ! -t 1 ] || progress=--progress-bar
    rm -f "$2"
    # Старые версии curl не ограничивают HTTP-поток неизвестного размера.
    # Системный лимит действует и на stderr, поэтому оставляем место для диагностики.
    file_blocks=$((($3 + 511) / 512))
    [ "$file_blocks" -ge 128 ] || file_blocks=128
    ulimit -f "$file_blocks" 2>/dev/null || true
    curl -q -fL "$progress" --globoff --proto '=https' --proto-redir '=https' \
        --connect-timeout 8 --max-time "$4" --max-redirs 5 --max-filesize "$3" \
        -o "$2" -- "$1" &&
        [ "$(wc -c < "$2")" -le "$3" ]
)

fetch_url() (
    set -f
    for route in $(github_routes); do
        url=$(github_url "$route" "$1") || continue
        if fetch_one "$url" "$2" "$3" "$4" &&
            [ "$(sha256_file "$2")" = "$5" ]; then
            exit 0
        fi
    done
    rm -f "$2"
    exit 1
)

verify_downloaded_manifest() {
    [ -s "$TMP/latest.json.sig" ] && [ "$(wc -c < "$TMP/latest.json.sig")" -eq 64 ] &&
        openssl pkeyutl -verify -pubin -inkey "$TMP/release-public.pem" -rawin \
            -in "$TMP/latest.json" -sigfile "$TMP/latest.json.sig" >/dev/null 2>&1
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    else
        openssl dgst -sha256 -r "$1" | awk '{ print $1 }'
    fi
}

asset_size_from_api() {
    awk -v wanted="$1" '
        /"name"[[:space:]]*:/ {
            name=$0
            sub(/^.*"name"[[:space:]]*:[[:space:]]*"/, "", name)
            sub(/".*/, "", name)
            matched=(name == wanted)
        }
        matched && /"size"[[:space:]]*:/ {
            size=$0
            sub(/^.*"size"[[:space:]]*:[[:space:]]*/, "", size)
            sub(/[^0-9].*$/, "", size)
            print size
            exit
        }
    ' "$2"
}

# GitHub API может быть недоступен, ограничен по частоте или отдавать ответ без
# размера (прокси, кэш, ограничение площадки). Ссылка выпуска на github.com при
# этом работает, и её последний ответ содержит Content-Length архива.
asset_size_from_headers() {
    r2o_size_url=$1
    r2o_headers=$(curl -q -fsSL -I --globoff --proto '=https' --proto-redir '=https' \
        --connect-timeout 8 --max-time 12 --max-redirs 5 -- "$r2o_size_url") || return 1
    printf '%s\n' "$r2o_headers" | awk '
        {
            header = tolower($1)
            value = $2
            gsub(/\r/, "", value)
            if (header == "content-length:" && value ~ /^[0-9]+$/) size = value
        }
        END { print size }
    '
}

verify_archive_listing() {
    tar -tvzf "$ARCHIVE" > "$TMP/archive-listing" || die 'релизный архив имеет неверный формат tar.gz'
    expanded_bytes=$(awk '
        substr($0, 1, 1) == "d" { next }
        substr($0, 1, 1) == "-" && $3 ~ /^[0-9]+$/ { total += $3; next }
        { bad=1 }
        END { if (bad) exit 1; print total+0 }
    ' "$TMP/archive-listing") || die 'архив содержит ссылку, специальный файл или неверный размер'
    [ "$expanded_bytes" -gt 0 ] || die 'релизный архив пуст'
    [ "$expanded_bytes" -le "$((expanded_bound_kb * 1024))" ] ||
        die "распакованный релиз превышает проверенный лимит $expanded_bound_kb КиБ"
    [ -z "$signed_expanded" ] || [ "$expanded_bytes" -eq "$signed_expanded" ] ||
        die 'размер распаковки не совпал с подписанным манифестом'
    tar -tzf "$ARCHIVE" > "$TMP/archive-paths" || die 'не удалось проверить пути релизного архива'
    while IFS= read -r archive_path; do
        case "$archive_path" in
            /*|../*|*/../*|*/..|*\\*) die "небезопасный путь в релизном архиве: $archive_path" ;;
        esac
    done < "$TMP/archive-paths"
    for required in "builds/r2o-manager-linux-$ARCH" router/install.sh router/uninstall.sh router/config.default router/S99r2o.shim router/select-panel-ip.sh; do
        [ "$(grep -Fxc "$required" "$TMP/archive-paths")" -eq 1 ] || die "в подписанном архиве отсутствует единственный $required"
    done
    EXPANDED_KB=$(((expanded_bytes + 1023) / 1024))
}

run_router_install() {
    install_bundle=$1
    install_release=$2
    R2O_DIR=$ROOT R2O_INIT_DIR=$INIT_DIR R2O_NDM_DIR=$NDM_DIR \
        R2O_OPENWRT_INIT_DIR=$OPENWRT_INIT_DIR R2O_OPENWRT_RELEASE=$OPENWRT_RELEASE \
        R2O_RUNTIME_DIR=$RUNTIME_DIR R2O_PLATFORM=$PLATFORM \
        sh "$install_bundle/router/install.sh" "$install_bundle" "$install_release" "$ARCH"
}

show_failed_install_logs() {
    # Первая установка может удалить весь ROOT при откате: выводим причины до него.
    log_dir=$ROOT/log
    shown=0
    if [ -d "$log_dir" ] && [ ! -L "$log_dir" ]; then
        for file in "$log_dir"/r2o-datapath*.log "$log_dir"/r2o-controller*.log "$log_dir"/rt-proxy.log; do
            [ -s "$file" ] && [ ! -L "$file" ] || continue
            printf 'r2o: журнал запуска %s (последние 80 строк, до отката):\n' "$file" >&2
            tail -n 80 "$file" >&2 || true
            shown=1
        done
    fi
    if [ "$shown" -eq 0 ]; then
        kernel_log=$(dmesg 2>/dev/null | grep -E 'r2o-(datapath|controller|manager)' | tail -n 12)
        if [ -n "$kernel_log" ]; then
            printf 'r2o: журналы запуска пусты. Последние сообщения ядра о R2O:\n%s\n' "$kernel_log" >&2
        else
            echo 'r2o: datapath и controller не записали ошибок запуска; если процесс завершился сразу, проверьте журнал ядра: dmesg' >&2
        fi
    fi
}

rollback_failed_install() {
    [ "$INSTALL_STARTED" -eq 1 ] || return 0
    [ -n "$TARGET_RELEASE" ] || return 0
    active_now=
    if [ -f "$ROOT/release-slots" ] && [ ! -L "$ROOT/release-slots" ]; then
        active_now=$(sed -n '2p' "$ROOT/release-slots")
    fi
    if [ "$active_now" != "$TARGET_RELEASE" ]; then
        cleanup_incomplete_first_install
        return 0
    fi
    [ "$ROOT_PREEXISTED" -eq 0 ] || return 0
    new_uninstall=$ROOT/releases/$TARGET_RELEASE/router/uninstall.sh
    if [ -f "$new_uninstall" ] && [ ! -L "$new_uninstall" ]; then
        R2O_DIR=$ROOT R2O_INIT_DIR=$INIT_DIR R2O_OPENWRT_INIT_DIR=$OPENWRT_INIT_DIR \
            R2O_OPENWRT_RELEASE=$OPENWRT_RELEASE R2O_RUNTIME_DIR=$RUNTIME_DIR R2O_NDM_DIR=$NDM_DIR \
            R2O_PLATFORM=$PLATFORM sh "$new_uninstall" --yes >/dev/null 2>&1 ||
            say 'не удалось автоматически очистить неудачную первую установку'
    fi
}

cleanup_incomplete_first_install() {
    [ "$ROOT_PREEXISTED" -eq 0 ] || return 0
    [ -d "$ROOT" ] && [ ! -L "$ROOT" ] || return 0
    [ ! -e "$ROOT/release-slots" ] && [ ! -L "$ROOT/release-slots" ] || return 0

    releases=$ROOT/releases
    if [ -d "$releases" ] && [ ! -L "$releases" ]; then
        failed_release=$releases/$TARGET_RELEASE
        [ ! -d "$failed_release" ] || [ -L "$failed_release" ] || rm -rf "$failed_release"
        for staging in "$releases"/.staging-"$TARGET_RELEASE"-*; do
            [ -e "$staging" ] || [ -L "$staging" ] || continue
            [ -d "$staging" ] && [ ! -L "$staging" ] || continue
            rm -rf "$staging"
        done
        rmdir "$releases" 2>/dev/null || true
    fi

    if [ -f "$ROOT/r2o-manager" ] && [ ! -L "$ROOT/r2o-manager" ]; then
        rm -f "$ROOT/r2o-manager"
    fi
    for partial in "$ROOT"/.manager.lock "$ROOT"/.r2o-manager-* "$ROOT"/.release-slots.*; do
        [ -f "$partial" ] && [ ! -L "$partial" ] || continue
        rm -f "$partial"
    done
    log_dir=$ROOT/log
    if [ -d "$log_dir" ] && [ ! -L "$log_dir" ]; then
        for file in "$log_dir"/r2o-datapath.log "$log_dir"/r2o-datapath[46].log \
            "$log_dir"/r2o-controller.log "$log_dir"/r2o-controller[46].log; do
            [ -f "$file" ] && [ ! -L "$file" ] || continue
            rm -f "$file"
        done
        rmdir "$log_dir" 2>/dev/null || true
    fi
    rmdir "$ROOT" 2>/dev/null || true
    say 'удалены файлы незавершённой первой установки; зависимости системы сохранены'
}

on_exit() {
    exit_code=$1
    trap - EXIT HUP INT TERM
    if [ "$exit_code" -ne 0 ] && [ "$INSTALL_STARTED" -eq 1 ]; then
        show_failed_install_logs || true
        rollback_failed_install || true
    fi
    cleanup
    exit "$exit_code"
}

TMP=$(mktemp -d "$TMP_BASE/r2o-install.XXXXXX") || die "не удалось создать временный каталог в $TMP_BASE"
trap 'on_exit $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(id -u)" = 0 ] || die 'запустите установщик от root'
case "$ROOT" in
    /*/r2o) ;;
    *) die 'каталог установки должен быть абсолютным каталогом r2o, например /opt/r2o' ;;
esac
case "$ROOT" in *'/../'*|*/..|*'/./'*|*/.) die "небезопасный каталог установки: $ROOT" ;; esac
storage_anchor
# Оставшийся после SIGKILL staging на flash убираем, но только старый:
# свежий каталог может принадлежать параллельному установщику.
find "$STORAGE_PATH" -maxdepth 1 -type d -name '.r2o-install.*' -mmin +60 \
    -exec rm -rf {} + 2>/dev/null || true
detect_platform_and_arch
release_from_slots
check_install_resources
if [ -n "$CURRENT_RELEASE" ]; then
    [ -z "$LOCAL_MANIFEST" ] || die 'локальный пакет предназначен для чистой установки'
    [ "$(cat "$ROOT/releases/$CURRENT_RELEASE/router/update-schema" 2>/dev/null)" = R2O-STATE-1 ] ||
        die 'обнаружена legacy-установка; для новой схемы нужна чистая установка базового выпуска'
    [ -x "$ROOT/r2o-manager" ] && [ ! -L "$ROOT/r2o-manager" ] ||
        die 'менеджер установленного выпуска недоступен'
    runtime_config "${R2O_CONFIG:-$ROOT/config}"
    check_runtime_dependencies
    cleanup
    trap - EXIT HUP INT TERM
    R2O_DIR=$ROOT R2O_PLATFORM=$PLATFORM exec "$ROOT/r2o-manager" update-install --root "$ROOT" --service "$INIT_DIR/S99r2o"
fi
if [ -e "$ROOT" ] || [ -L "$ROOT" ]; then ROOT_PREEXISTED=1; fi
install_bootstrap_dependencies
command -v tar >/dev/null 2>&1 || die 'не найдена команда tar'
command -v awk >/dev/null 2>&1 || die 'не найдена команда awk'
command -v df >/dev/null 2>&1 || die 'не найдена команда df'
command -v sha256sum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1 || die 'не найден sha256sum или openssl'
command -v curl >/dev/null 2>&1 || die 'curl отсутствует после установки зависимостей'

say 'загружаю подписанный манифест'
printf '%s\n' '-----BEGIN PUBLIC KEY-----' "$PUBLIC_KEY_B64" '-----END PUBLIC KEY-----' > "$TMP/release-public.pem"
if [ -n "$LOCAL_MANIFEST" ]; then
    [ -f "$LOCAL_MANIFEST" ] && [ ! -L "$LOCAL_MANIFEST" ] ||
        die "локальный манифест не найден или является ссылкой: $LOCAL_MANIFEST"
    LOCAL_SIGNATURE=${LOCAL_SIGNATURE:-$LOCAL_MANIFEST.sig}
    [ -f "$LOCAL_SIGNATURE" ] && [ ! -L "$LOCAL_SIGNATURE" ] ||
        die "локальная подпись не найдена или является ссылкой: $LOCAL_SIGNATURE"
    cp "$LOCAL_MANIFEST" "$TMP/latest.json" || die 'не удалось скопировать локальный манифест'
    cp "$LOCAL_SIGNATURE" "$TMP/latest.json.sig" || die 'не удалось скопировать локальную подпись'
    say "использую локальный подписанный манифест: $LOCAL_MANIFEST"
else
    set -f
    for manifest_route in $(github_routes); do
        if fetch_one "$(github_url "$manifest_route" "$LATEST/latest.json")" "$TMP/latest.json" 65536 15 &&
            fetch_one "$(github_url "$manifest_route" "$LATEST/latest.json.sig")" "$TMP/latest.json.sig" 64 15 &&
            verify_downloaded_manifest; then
            break
        fi
        rm -f "$TMP/latest.json" "$TMP/latest.json.sig"
    done
    set +f
fi
verify_downloaded_manifest ||
    die 'Ed25519 подпись манифеста не совпадает с закреплённым ключом R2O или манифест недоступен'
TARGET_RELEASE=$(sed -n 's/.*"release_id":"\([A-Za-z0-9][A-Za-z0-9._-]*\)".*/\1/p' "$TMP/latest.json")
[ -n "$TARGET_RELEASE" ] || die 'в подписанном манифесте нет безопасного release_id'
expected_sha=$(awk -v architecture="$ARCH" '
    {
        key="\"" architecture "\":{\"sha256\":\""
        position=index($0, key)
        if (position) {
            digest=substr($0, position + length(key))
            sub(/".*/, "", digest)
            print digest
            exit
        }
    }
' "$TMP/latest.json")
case "$expected_sha" in ''|*[!0-9a-f]*) die "в манифесте нет SHA-256 для ABI $ARCH" ;; esac
[ "${#expected_sha}" -eq 64 ] || die "неверная длина SHA-256 для ABI $ARCH"
ASSET=r2o-$ARCH.tar.gz
LATEST=https://github.com/$REPO/releases/download/$TARGET_RELEASE

# Статическая сборка Keenetic может занимать больше места, чем общий лимит.
# Для выбора staging используем размер из подписанного манифеста.
expanded_limit_kb=$MAX_EXPANDED_KB
if [ "$PLATFORM" = keenetic ] && [ "$ARCH" = mipsel ]; then
    expanded_limit_kb=32768
fi
expanded_bound_kb=$MAX_EXPANDED_KB
signed_expanded=$(sed -n "s/.*\"$ARCH\":{\"sha256\":\"$expected_sha\",\"bytes\":[0-9][0-9]*,\"expanded\":\([0-9][0-9]*\).*/\1/p" "$TMP/latest.json")
if [ -n "$signed_expanded" ]; then
    [ "$signed_expanded" -gt 0 ] && [ "$signed_expanded" -le "$((expanded_limit_kb * 1024))" ] ||
        die "подписанный размер распаковки выпуска превышает лимит $expanded_limit_kb КиБ"
    expanded_bound_kb=$(((signed_expanded + 1023) / 1024))
fi

archive_bytes=
if [ -z "$LOCAL_ARCHIVE" ]; then
    archive_bytes=$(sed -n "s/.*\"$ARCH\":{\"sha256\":\"$expected_sha\",\"bytes\":\([0-9][0-9]*\).*/\1/p" "$TMP/latest.json")
    # Для старых выпусков без подписанного размера используем только GitHub.
    if [ -z "$archive_bytes" ] && fetch_one "$RELEASE_API/$TARGET_RELEASE" "$TMP/release-api.json" 1048576 12; then
        archive_bytes=$(asset_size_from_api "$ASSET" "$TMP/release-api.json")
    fi
    case "$archive_bytes" in ''|*[!0-9]*) archive_bytes= ;; esac
    if [ -z "$archive_bytes" ] ||
        [ "$archive_bytes" -le 0 ] || [ "$archive_bytes" -gt "$MAX_ARCHIVE_BYTES" ]; then
        say 'GitHub API не сообщил размер актива; определяю размер по заголовкам загрузки'
        archive_bytes=$(asset_size_from_headers "$LATEST/$ASSET" || true)
    fi
fi
case "$archive_bytes" in ''|*[!0-9]*) archive_bytes= ;; esac

archive_downloaded=0
if [ -n "$LOCAL_ARCHIVE" ]; then
    [ -f "$LOCAL_ARCHIVE" ] && [ ! -L "$LOCAL_ARCHIVE" ] ||
        die "локальный архив не найден или является ссылкой: $LOCAL_ARCHIVE"
    ARCHIVE=$LOCAL_ARCHIVE
    archive_bytes=$(wc -c < "$ARCHIVE" | tr -d ' ')
    case "$archive_bytes" in ''|*[!0-9]*) die "не удалось проверить размер локального архива $LOCAL_ARCHIVE" ;; esac
    archive_downloaded=1
    say "использую локальный архив: $LOCAL_ARCHIVE"
elif [ -z "$archive_bytes" ]; then
    # Без известного размера оставляем резерв flash до выбора схемы размещения.
    say 'размер актива не удалось узнать заранее; скачиваю с ограничением и проверяю фактический размер'
    available_bytes=$((($(free_kb "$STORAGE_PATH") - DEPENDENCY_RESERVE_KB) * 1024))
    [ "$available_bytes" -gt 0 ] || die 'на flash нет места для загрузки архива'
    [ "$available_bytes" -le "$MAX_ARCHIVE_BYTES" ] || available_bytes=$MAX_ARCHIVE_BYTES
    DISK_TMP=$(mktemp -d "$STORAGE_PATH/.r2o-install.XXXXXX") ||
        die "не удалось создать staging на $STORAGE_PATH"
    ARCHIVE=$DISK_TMP/$ASSET
    fetch_url "$LATEST/$ASSET" "$ARCHIVE" "$available_bytes" 180 "$expected_sha" ||
        die 'архив недоступен или SHA-256 архива не совпадает с подписанным манифестом'
    archive_bytes=$(wc -c < "$ARCHIVE" | tr -d ' ')
    case "$archive_bytes" in ''|*[!0-9]*) die "не удалось проверить размер актива $ASSET" ;; esac
    archive_downloaded=1
fi
[ "$archive_bytes" -gt 0 ] && [ "$archive_bytes" -le "$MAX_ARCHIVE_BYTES" ] ||
    die "недопустимый размер актива $ASSET: $archive_bytes байт"
archive_kb=$(((archive_bytes + 1023) / 1024))

memory_kb=$(memory_available_kb)
flash_kb=$(free_kb "$STORAGE_PATH")
ram_both_need=$((archive_kb + expanded_bound_kb + RAM_RESERVE_KB))
ram_bundle_need=$((expanded_bound_kb + RAM_RESERVE_KB))
ram_archive_need=$((archive_kb + RAM_RESERVE_KB))
flash_one=$((expanded_bound_kb + DEPENDENCY_RESERVE_KB))
flash_archive_one=$((archive_kb + expanded_bound_kb + DEPENDENCY_RESERVE_KB))
flash_two=$((expanded_bound_kb * 2 + DEPENDENCY_RESERVE_KB))
flash_archive_two=$((archive_kb + expanded_bound_kb * 2 + DEPENDENCY_RESERVE_KB))
if [ "$memory_kb" -ge "$ram_both_need" ] && [ "$flash_kb" -ge "$flash_one" ]; then
    ARCHIVE_IN_RAM=1; BUNDLE_IN_RAM=1
elif [ "$memory_kb" -ge "$ram_bundle_need" ] && [ "$flash_kb" -ge "$flash_archive_one" ]; then
    ARCHIVE_IN_RAM=0; BUNDLE_IN_RAM=1
elif [ "$memory_kb" -ge "$ram_archive_need" ] && [ "$flash_kb" -ge "$flash_two" ]; then
    ARCHIVE_IN_RAM=1; BUNDLE_IN_RAM=0
elif [ "$memory_kb" -ge "$RAM_RESERVE_KB" ] && [ "$flash_kb" -ge "$flash_archive_two" ]; then
    ARCHIVE_IN_RAM=0; BUNDLE_IN_RAM=0
else
    die "не хватает ресурсов до установки: RAM ${memory_kb} КиБ; flash ${flash_kb} КиБ; архив до ${archive_kb} КиБ, распаковка до ${expanded_bound_kb} КиБ"
fi
if [ "$ARCHIVE_IN_RAM" -eq 1 ]; then
    if [ "$archive_downloaded" -eq 1 ]; then
        if [ -n "$LOCAL_ARCHIVE" ]; then
            cp "$ARCHIVE" "$TMP/$ASSET" || die 'не удалось скопировать локальный архив в RAM'
        else
            mv "$ARCHIVE" "$TMP/$ASSET" || die 'не удалось перенести скачанный архив в RAM'
        fi
    fi
    ARCHIVE=$TMP/$ASSET
fi
if [ "$ARCHIVE_IN_RAM" -eq 0 ] || [ "$BUNDLE_IN_RAM" -eq 0 ]; then
    [ -n "$DISK_TMP" ] ||
        DISK_TMP=$(mktemp -d "$STORAGE_PATH/.r2o-install.XXXXXX") ||
        die "не удалось создать staging на $STORAGE_PATH"
fi
[ -n "$ARCHIVE" ] || ARCHIVE=$DISK_TMP/$ASSET
if [ "$BUNDLE_IN_RAM" -eq 1 ]; then BUNDLE=$TMP/bundle; else BUNDLE=$DISK_TMP/bundle; fi
say "ресурсы проверены: свободно ${memory_kb} КиБ RAM и ${flash_kb} КиБ flash; архив и распаковка размещены безопасно"

if [ "$archive_downloaded" -eq 0 ]; then
    say "скачиваю $ASSET (${archive_kb} КиБ)"
    fetch_url "$LATEST/$ASSET" "$ARCHIVE" "$archive_bytes" 180 "$expected_sha" ||
        die 'архив недоступен или SHA-256 архива не совпадает с подписанным манифестом'
fi
[ "$(wc -c < "$ARCHIVE" | tr -d ' ')" = "$archive_bytes" ] || die "размер актива $ASSET не совпал с ожидаемым"
actual_sha=$(sha256_file "$ARCHIVE")
[ "$actual_sha" = "$expected_sha" ] || die 'SHA-256 архива не совпадает с подписанным манифестом'
verify_archive_listing

# Recheck exact sizes after authentication and before unpacking or activation.
flash_kb=$(free_kb "$STORAGE_PATH")
exact_flash_need=$((EXPANDED_KB + DEPENDENCY_RESERVE_KB))
[ "$BUNDLE_IN_RAM" -eq 1 ] || exact_flash_need=$((exact_flash_need + EXPANDED_KB))
[ "$flash_kb" -ge "$exact_flash_need" ] || die "после загрузки не хватает flash под распаковку и откат: нужно $exact_flash_need КиБ, свободно $flash_kb КиБ"
memory_kb=$(memory_available_kb)
exact_ram_need=$RAM_RESERVE_KB
if [ "$BUNDLE_IN_RAM" -eq 1 ]; then exact_ram_need=$((exact_ram_need + EXPANDED_KB)); fi
[ "$memory_kb" -ge "$exact_ram_need" ] || die "после проверки осталось мало RAM: нужно $exact_ram_need КиБ, доступно $memory_kb КиБ"

mkdir -m 0700 "$BUNDLE" || die 'не удалось создать каталог распаковки'
tar -xzf "$ARCHIVE" -C "$BUNDLE" || die 'не удалось распаковать подписанный выпуск'
for required_file in \
    "$BUNDLE/builds/r2o-manager-linux-$ARCH" "$BUNDLE/router/install.sh" \
    "$BUNDLE/router/uninstall.sh" "$BUNDLE/router/config.default" \
    "$BUNDLE/router/S99r2o.shim" "$BUNDLE/router/001-r2o.sh" "$BUNDLE/router/update-schema" \
    "$BUNDLE/router/r2o-ppe-deoffload.sh" "$BUNDLE/router/select-panel-ip.sh"; do
    [ -f "$required_file" ] && [ ! -L "$required_file" ] || die "в подписанном выпуске отсутствует обычный файл $required_file"
done
[ "$(cat "$BUNDLE/router/update-schema")" = R2O-STATE-1 ] ||
    die "нужен базовый выпуск универсального обновлятора"
[ -x "$BUNDLE/builds/r2o-manager-linux-$ARCH" ] || die "менеджер выпуска $ARCH не исполняемый"

manager=$BUNDLE/builds/r2o-manager-linux-$ARCH
datapath=$BUNDLE/builds/r2o-datapath-linux-$ARCH
"$manager" --version >/dev/null || die "менеджер выпуска $TARGET_RELEASE не запускается для $ARCH"
if [ -f "${R2O_CONFIG:-$ROOT/config}" ] || [ -L "${R2O_CONFIG:-$ROOT/config}" ]; then
    runtime_config "${R2O_CONFIG:-$ROOT/config}"
else
    # Для чистой установки читаем те же настройки и перенос D2K, что применит router/install.sh.
    set -- --root "$TMP/preflight-config" --defaults "$BUNDLE/router/config.default"
    donor=${R2O_DONOR_CONFIG:-/opt/d2k/config}
    if [ -f "$donor" ]; then set -- "$@" --donor-config "$donor"; fi
    mkdir "$TMP/preflight-config"
    "$manager" config-init "$@" >/dev/null || die 'не удалось подготовить конфигурацию для проверки зависимостей'
    runtime_config "$TMP/preflight-config/config"
fi
check_runtime_dependencies
check_datapath "$datapath"
# Пакеты могут занять место, отведённое для следующего слота.
[ "$(free_kb "$STORAGE_PATH")" -ge "$exact_flash_need" ] ||
    die "после установки зависимостей не хватает места для релиза и отката ($exact_flash_need КиБ)"
[ "$(memory_available_kb)" -ge "$RAM_RESERVE_KB" ] ||
    die "после установки зависимостей не хватает RAM ($RAM_RESERVE_KB КиБ)"

INSTALL_STARTED=1
say "устанавливаю подписанный выпуск $TARGET_RELEASE"
if run_router_install "$BUNDLE" "$TARGET_RELEASE"; then :; else
    die "установщик выпуска завершился ошибкой (код $?)"
fi
CURRENT_RELEASE=$(sed -n '2p' "$ROOT/release-slots" 2>/dev/null || true)
[ "$CURRENT_RELEASE" = "$TARGET_RELEASE" ] || die 'менеджер не активировал проверенный выпуск'
INSTALL_STARTED=0
say "установлен подписанный выпуск $TARGET_RELEASE; службы R2O, Telegram и веб-панель запущены"
