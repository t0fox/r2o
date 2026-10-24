#!/bin/sh
# Signed OpenWrt/Keenetic bootstrap. Release code is executed only after both
# the pinned Ed25519 manifest signature and its archive SHA-256 are verified.
set -eu

PATH=/opt/bin:/opt/sbin:/opt/usr/bin:/opt/usr/sbin:/usr/bin:/usr/sbin:/bin:/sbin:${PATH:-}
export PATH

REPO=t0fox/r2o
LATEST=https://github.com/$REPO/releases/latest/download
RELEASE_API=https://api.github.com/repos/$REPO/releases/tags
PUBLIC_KEY_B64='MCowBQYDK2VwAyEAx2b2eh9ZlnOOzizkMWUMNHdDIJNcIc4fO4i1psTUESc='
OPENWRT_RELEASE=${R2O_OPENWRT_RELEASE:-/etc/openwrt_release}
MEMINFO=${R2O_MEMINFO_FILE:-/proc/meminfo}
ROOT=${R2O_DIR:-/opt/r2o}
INIT_DIR=${R2O_INIT_DIR:-/opt/etc/init.d}
NDM_DIR=${R2O_NDM_DIR:-/opt/etc/ndm/netfilter.d}
OPENWRT_INIT_DIR=${R2O_OPENWRT_INIT_DIR:-/etc/init.d}
RUNTIME_DIR=${R2O_RUNTIME_DIR:-/tmp/r2o}
TMP_BASE=${TMPDIR:-/tmp}
NFQUEUE_STATUS_FILE=${R2O_NFQUEUE_STATUS_FILE:-/proc/net/netfilter/nfnetlink_queue}
MODULE_DIR=${R2O_SYS_MODULE_DIR:-/sys/module}
MAX_ARCHIVE_BYTES=67108864
MAX_EXPANDED_KB=24576
RAM_RESERVE_KB=16384
DEPENDENCY_RESERVE_KB=2048
PLATFORM=
ARCH=
CURRENT_RELEASE=
PREVIOUS_RELEASE=
TARGET_RELEASE=
OLD_RELEASE=
INSTALL_STARTED=0
ROOT_PREEXISTED=0
TMP=
DISK_TMP=
BUNDLE=
ARCHIVE=

say() { echo "r2o: $*"; }
die() { echo "r2o: $*" >&2; exit 1; }

cleanup() {
    [ -z "$TMP" ] || rm -rf "$TMP" 2>/dev/null || true
    [ -z "$DISK_TMP" ] || rm -rf "$DISK_TMP" 2>/dev/null || true
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
    if [ -f "$OPENWRT_RELEASE" ]; then
        PLATFORM=openwrt
        distribution_arch=$(sed -n 's/^DISTRIB_ARCH=//p' "$OPENWRT_RELEASE" | head -n 1 | sed "s/['\"]//g")
        if [ -z "$distribution_arch" ]; then
            if command -v apk >/dev/null 2>&1; then
                distribution_arch=$(apk --print-arch 2>/dev/null | head -n 1 || true)
            elif command -v opkg >/dev/null 2>&1; then
                distribution_arch=$(opkg print-architecture 2>/dev/null | awk '$1 == "arch" && $2 != "all" { if ($3 + 0 >= priority) { priority=$3 + 0; arch=$2 } } END { print arch }')
            else
                distribution_arch=$(uname -m 2>/dev/null || true)
            fi
        fi
        map_openwrt_arch "$distribution_arch" || die "неподдерживаемая архитектура OpenWrt: ${distribution_arch:-не определена}"
    elif [ -d /opt/etc/ndm ] || [ -x /opt/bin/opkg ] || command -v opkg >/dev/null 2>&1; then
        PLATFORM=keenetic
        if [ -x /opt/bin/opkg ]; then
            package_arch=$(/opt/bin/opkg print-architecture 2>/dev/null | awk '$1 == "arch" && $2 != "all" && $2 != "noarch" { if ($3 + 0 >= priority) { priority=$3 + 0; arch=$2 } } END { print arch }')
        elif command -v opkg >/dev/null 2>&1; then
            package_arch=$(opkg print-architecture 2>/dev/null | awk '$1 == "arch" && $2 != "all" && $2 != "noarch" { if ($3 + 0 >= priority) { priority=$3 + 0; arch=$2 } } END { print arch }')
        else
            package_arch=
        fi
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
        mipsel|mipsel-openwrt-musl|aarch64-openwrt-musl|armv5-musleabi|armv7-openwrt-musl) ;;
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

install_dependencies() {
    missing=
    command -v openssl >/dev/null 2>&1 || missing="$missing openssl-util"
    have_ca=0
    for ca_file in /etc/ssl/cert.pem /etc/ssl/certs/ca-certificates.crt /opt/etc/ssl/certs/ca-certificates.crt; do
        [ ! -s "$ca_file" ] || have_ca=1
    done
    [ "$have_ca" -eq 1 ] || missing="$missing ca-bundle"
    nfqueue_module=
    if [ "$PLATFORM" = openwrt ]; then
        if { [ "$backend" = nft ] || { [ "$backend" = auto ] && command -v nft >/dev/null 2>&1; }; }; then
            nfqueue_package='kmod-nfnetlink-queue kmod-nft-queue'
            nfqueue_module=nft_queue
        else
            nfqueue_package='kmod-nfnetlink-queue kmod-ipt-nfqueue'
            nfqueue_module=xt_NFQUEUE
        fi
        if [ ! -d "$MODULE_DIR/nfnetlink_queue" ] \
            || [ ! -d "$MODULE_DIR/$nfqueue_module" ] \
            || [ ! -e "$NFQUEUE_STATUS_FILE" ]; then
            missing="$missing $nfqueue_package"
        fi
    fi
    [ -n "$missing" ] || return 0
    [ "$(free_kb "$STORAGE_PATH")" -ge "$((MAX_EXPANDED_KB + DEPENDENCY_RESERVE_KB))" ] ||
        die "для зависимостей и выпуска нужно не менее $((MAX_EXPANDED_KB + DEPENDENCY_RESERVE_KB)) КиБ свободной flash"
    [ "$(memory_available_kb)" -ge 8192 ] || die 'нужно не менее 8 МиБ свободной RAM для установки зависимостей'
    say "проверяю недостающие зависимости:$missing"
    if [ "$PLATFORM" = openwrt ] && command -v apk >/dev/null 2>&1; then
        apk update && apk add $missing || die "не удалось установить зависимости через apk:$missing"
    elif [ "$PLATFORM" = openwrt ] && command -v opkg >/dev/null 2>&1; then
        opkg update && opkg install $missing || die "не удалось установить зависимости через opkg:$missing"
    elif [ -x /opt/bin/opkg ]; then
        /opt/bin/opkg update && /opt/bin/opkg install $missing || die "не удалось установить зависимости через Entware opkg:$missing"
    else
        die "нет штатного менеджера пакетов для установки:$missing"
    fi
    command -v openssl >/dev/null 2>&1 || die 'openssl отсутствует после установки зависимостей'
    if [ -n "$nfqueue_module" ]; then
        command -v modprobe >/dev/null 2>&1 || die 'для загрузки модулей NFQUEUE нужна команда modprobe'
        modprobe nfnetlink_queue || die 'не удалось загрузить модуль nfnetlink_queue после установки kmod-пакета'
        modprobe "$nfqueue_module" || die "не удалось загрузить модуль $nfqueue_module после установки kmod-пакета"
        [ -e "$NFQUEUE_STATUS_FILE" ] || die "после загрузки модулей NFQUEUE отсутствует $NFQUEUE_STATUS_FILE"
    fi
}

check_runtime_dependencies() {
    command -v start-stop-daemon >/dev/null 2>&1 || die 'нужен start-stop-daemon из системного BusyBox или Entware'
    backend=auto
    ipv6_enabled=1
    telegram_enabled=1
    if [ -e "$ROOT/config" ] || [ -L "$ROOT/config" ]; then
        [ ! -L "$ROOT/config" ] && [ -f "$ROOT/config" ] || die "конфигурация должна быть обычным файлом: $ROOT/config"
        backend=$(sed -n 's/^FW_BACKEND=//p' "$ROOT/config" | head -n 1 | sed "s/['\"]//g")
        ipv6_enabled=$(sed -n 's/^IPV6_ENABLED=//p' "$ROOT/config" | head -n 1 | sed "s/['\"]//g")
        telegram_enabled=$(sed -n 's/^TG_ENABLED=//p' "$ROOT/config" | head -n 1 | sed "s/['\"]//g")
        [ -n "$backend" ] || backend=auto
        [ -n "$ipv6_enabled" ] || ipv6_enabled=1
        [ -n "$telegram_enabled" ] || telegram_enabled=1
    fi
    case "$backend" in auto|nft|iptables) ;; *) die "неподдерживаемый FW_BACKEND в $ROOT/config: $backend" ;; esac
    case "$ipv6_enabled" in 0|1) ;; *) die "неверный IPV6_ENABLED в $ROOT/config: $ipv6_enabled" ;; esac
    case "$telegram_enabled" in 0|1) ;; *) die "неверный TG_ENABLED в $ROOT/config: $telegram_enabled" ;; esac

    if [ "$PLATFORM" = openwrt ]; then
        case "$backend" in
            nft) command -v nft >/dev/null 2>&1 || die 'для FW_BACKEND=nft нужна команда nft'; return 0 ;;
            auto) command -v nft >/dev/null 2>&1 && return 0 ;;
        esac
    elif [ "$backend" = nft ]; then
        command -v nft >/dev/null 2>&1 || die 'для FW_BACKEND=nft нужна команда nft'
        if [ "$telegram_enabled" = 1 ]; then
            command -v iptables >/dev/null 2>&1 || die 'Telegram на Keenetic требует iptables'
            [ "$ipv6_enabled" = 0 ] || command -v ip6tables >/dev/null 2>&1 || die 'Telegram и IPv6 требуют ip6tables'
            command -v ipset >/dev/null 2>&1 || die 'для Telegram с iptables нужен ipset'
        fi
        return 0
    fi
    command -v iptables >/dev/null 2>&1 || die 'для NFQUEUE и Telegram нужен iptables или OpenWrt nft'
    if [ "$ipv6_enabled" = 1 ]; then
        command -v ip6tables >/dev/null 2>&1 || die 'для IPv6 NFQUEUE и Telegram нужен ip6tables'
    fi
    if [ "$telegram_enabled" = 1 ] \
        && { [ "$PLATFORM" != openwrt ] || ! command -v nft >/dev/null 2>&1; }; then
        command -v ipset >/dev/null 2>&1 || die 'для Telegram с iptables нужен ipset'
    fi
}

fetch_url() {
    fetch_url_value=$1
    fetch_output=$2
    fetch_limit=$3
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --proto-redir '=https' --connect-timeout 15 \
            --max-time 600 --max-filesize "$fetch_limit" -o "$fetch_output" "$fetch_url_value" ||
            die "не удалось скачать $fetch_url_value"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 600 -O "$fetch_output" "$fetch_url_value" || die "не удалось скачать $fetch_url_value"
    else
        die 'нужен curl или wget для загрузки выпуска'
    fi
    [ -f "$fetch_output" ] || die "загрузчик не создал $fetch_output"
    fetched_bytes=$(wc -c < "$fetch_output" | tr -d ' ')
    case "$fetched_bytes" in ''|*[!0-9]*) die "не удалось проверить размер $fetch_output" ;; esac
    [ "$fetched_bytes" -le "$fetch_limit" ] || die "загрузка превысила лимит $fetch_limit байт"
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

verify_archive_listing() {
    tar -tvzf "$ARCHIVE" > "$TMP/archive-listing" || die 'релизный архив имеет неверный формат tar.gz'
    expanded_bytes=$(awk '
        substr($0, 1, 1) == "d" { next }
        substr($0, 1, 1) == "-" && $3 ~ /^[0-9]+$/ { total += $3; next }
        { bad=1 }
        END { if (bad) exit 1; print total+0 }
    ' "$TMP/archive-listing") || die 'архив содержит ссылку, специальный файл или неверный размер'
    [ "$expanded_bytes" -gt 0 ] || die 'релизный архив пуст'
    [ "$expanded_bytes" -le "$((MAX_EXPANDED_KB * 1024))" ] || die 'распакованный релиз превышает проверенный лимит 24 МиБ'
    tar -tzf "$ARCHIVE" > "$TMP/archive-paths" || die 'не удалось проверить пути релизного архива'
    while IFS= read -r archive_path; do
        case "$archive_path" in
            /*|../*|*/../*|*/..|*\\*) die "небезопасный путь в релизном архиве: $archive_path" ;;
        esac
    done < "$TMP/archive-paths"
    for required in "builds/r2o-manager-linux-$ARCH" router/install.sh router/uninstall.sh router/config.default router/S99r2o.shim; do
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
    if [ -n "$OLD_RELEASE" ]; then
        if "$ROOT/r2o-manager" rollback --root "$ROOT" >/dev/null 2>&1; then
            old_bundle=$ROOT/releases/$OLD_RELEASE
            if [ -d "$old_bundle" ] && [ ! -L "$old_bundle" ]; then
                run_router_install "$old_bundle" "$OLD_RELEASE" ||
                    say "откат к $OLD_RELEASE выполнен, но восстановить службу автоматически не удалось"
            fi
        else
            say "не удалось выполнить автоматический откат к $OLD_RELEASE; сохраните данные и проверьте $ROOT/release-slots"
        fi
    else
        new_uninstall=$ROOT/releases/$TARGET_RELEASE/router/uninstall.sh
        if [ -f "$new_uninstall" ] && [ ! -L "$new_uninstall" ]; then
            R2O_DIR=$ROOT R2O_INIT_DIR=$INIT_DIR R2O_OPENWRT_INIT_DIR=$OPENWRT_INIT_DIR \
                R2O_OPENWRT_RELEASE=$OPENWRT_RELEASE R2O_RUNTIME_DIR=$RUNTIME_DIR R2O_NDM_DIR=$NDM_DIR \
                R2O_PLATFORM=$PLATFORM sh "$new_uninstall" --yes >/dev/null 2>&1 ||
                say 'не удалось автоматически очистить неудачную первую установку'
        fi
    fi
}

cleanup_incomplete_first_install() {
    [ -z "$OLD_RELEASE" ] && [ "$ROOT_PREEXISTED" -eq 0 ] || return 0
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
    rmdir "$ROOT" 2>/dev/null || true
    say 'удалены файлы незавершённой первой установки; зависимости системы сохранены'
}

on_exit() {
    exit_code=$1
    trap - EXIT HUP INT TERM
    if [ "$exit_code" -ne 0 ]; then rollback_failed_install || true; fi
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
detect_platform_and_arch
release_from_slots
if [ -e "$ROOT" ] || [ -L "$ROOT" ]; then ROOT_PREEXISTED=1; fi
check_runtime_dependencies
OLD_RELEASE=$CURRENT_RELEASE

# The package staging area can need a second copy while the existing manager
# commits it. Check that lower bound before installing any missing dependency.
[ "$(free_kb "$STORAGE_PATH")" -ge "$((MAX_EXPANDED_KB + DEPENDENCY_RESERVE_KB))" ] ||
        die "нужно не менее $((MAX_EXPANDED_KB + DEPENDENCY_RESERVE_KB)) КиБ места во flash для выпуска и зависимостей"
install_dependencies
command -v tar >/dev/null 2>&1 || die 'не найдена команда tar'
command -v awk >/dev/null 2>&1 || die 'не найдена команда awk'
command -v df >/dev/null 2>&1 || die 'не найдена команда df'
command -v sha256sum >/dev/null 2>&1 || command -v openssl >/dev/null 2>&1 || die 'не найден sha256sum или openssl'
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || die 'нужен curl или wget'

say 'загружаю подписанный манифест'
fetch_url "$LATEST/latest.json" "$TMP/latest.json" 65536
fetch_url "$LATEST/latest.json.sig" "$TMP/latest.json.sig" 64
[ "$(wc -c < "$TMP/latest.json.sig" | tr -d ' ')" = 64 ] || die 'подпись манифеста имеет неверный размер'
printf '%s\n' '-----BEGIN PUBLIC KEY-----' "$PUBLIC_KEY_B64" '-----END PUBLIC KEY-----' > "$TMP/release-public.pem"
openssl pkeyutl -verify -pubin -inkey "$TMP/release-public.pem" -rawin \
    -in "$TMP/latest.json" -sigfile "$TMP/latest.json.sig" >/dev/null 2>&1 ||
    die 'Ed25519 подпись манифеста не совпадает с закреплённым ключом R2O'
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

if [ "$CURRENT_RELEASE" = "$TARGET_RELEASE" ]; then
    active_bundle=$ROOT/releases/$CURRENT_RELEASE
    [ -d "$active_bundle" ] && [ ! -L "$active_bundle" ] || die "активный выпуск $CURRENT_RELEASE отсутствует"
    [ -f "$active_bundle/release-architecture" ] && [ ! -L "$active_bundle/release-architecture" ] ||
        die "нет безопасного описания ABI у активного выпуска $CURRENT_RELEASE"
    [ -f "$active_bundle/router/install.sh" ] && [ ! -L "$active_bundle/router/install.sh" ] ||
        die "нет безопасного установщика у активного выпуска $CURRENT_RELEASE"
    active_arch=$(cat "$active_bundle/release-architecture")
    [ "$active_arch" = "$ARCH" ] || die "установлен ABI $active_arch, а устройство определено как $ARCH"
    say "уже установлен актуальный выпуск $TARGET_RELEASE; проверяю службы и интеграцию через router/install.sh"
    run_router_install "$active_bundle" "$TARGET_RELEASE" || die 'не удалось восстановить текущую установку'
    exit 0
fi

fetch_url "$RELEASE_API/$TARGET_RELEASE" "$TMP/release-api.json" 1048576
archive_bytes=$(asset_size_from_api "$ASSET" "$TMP/release-api.json")
case "$archive_bytes" in ''|*[!0-9]*) die "GitHub не сообщил размер актива $ASSET" ;; esac
[ "$archive_bytes" -gt 0 ] && [ "$archive_bytes" -le "$MAX_ARCHIVE_BYTES" ] ||
    die "недопустимый размер актива $ASSET: $archive_bytes байт"
archive_kb=$(((archive_bytes + 1023) / 1024))

memory_kb=$(memory_available_kb)
flash_kb=$(free_kb "$STORAGE_PATH")
ram_both_need=$((archive_kb + MAX_EXPANDED_KB + RAM_RESERVE_KB))
ram_bundle_need=$((MAX_EXPANDED_KB + RAM_RESERVE_KB))
ram_archive_need=$((archive_kb + RAM_RESERVE_KB))
flash_one=$((MAX_EXPANDED_KB + DEPENDENCY_RESERVE_KB))
flash_archive_one=$((archive_kb + MAX_EXPANDED_KB + DEPENDENCY_RESERVE_KB))
flash_two=$((MAX_EXPANDED_KB * 2 + DEPENDENCY_RESERVE_KB))
flash_archive_two=$((archive_kb + MAX_EXPANDED_KB * 2 + DEPENDENCY_RESERVE_KB))
if [ "$memory_kb" -ge "$ram_both_need" ] && [ "$flash_kb" -ge "$flash_one" ]; then
    ARCHIVE_IN_RAM=1; BUNDLE_IN_RAM=1
elif [ "$memory_kb" -ge "$ram_bundle_need" ] && [ "$flash_kb" -ge "$flash_archive_one" ]; then
    ARCHIVE_IN_RAM=0; BUNDLE_IN_RAM=1
elif [ "$memory_kb" -ge "$ram_archive_need" ] && [ "$flash_kb" -ge "$flash_two" ]; then
    ARCHIVE_IN_RAM=1; BUNDLE_IN_RAM=0
elif [ "$memory_kb" -ge "$RAM_RESERVE_KB" ] && [ "$flash_kb" -ge "$flash_archive_two" ]; then
    ARCHIVE_IN_RAM=0; BUNDLE_IN_RAM=0
else
    die "не хватает ресурсов до установки: RAM ${memory_kb} КиБ; flash ${flash_kb} КиБ; архив до ${archive_kb} КиБ, распаковка до ${MAX_EXPANDED_KB} КиБ"
fi
if [ "$ARCHIVE_IN_RAM" -eq 1 ]; then ARCHIVE=$TMP/$ASSET; else :; fi
if [ "$ARCHIVE_IN_RAM" -eq 0 ] || [ "$BUNDLE_IN_RAM" -eq 0 ]; then
    DISK_TMP=$(mktemp -d "$STORAGE_PATH/.r2o-install.XXXXXX") || die "не удалось создать staging на $STORAGE_PATH"
fi
[ -n "$ARCHIVE" ] || ARCHIVE=$DISK_TMP/$ASSET
if [ "$BUNDLE_IN_RAM" -eq 1 ]; then BUNDLE=$TMP/bundle; else BUNDLE=$DISK_TMP/bundle; fi
say "ресурсы проверены: свободно ${memory_kb} КиБ RAM и ${flash_kb} КиБ flash; архив и распаковка размещены безопасно"

fetch_url "$LATEST/$ASSET" "$ARCHIVE" "$archive_bytes"
[ "$(wc -c < "$ARCHIVE" | tr -d ' ')" = "$archive_bytes" ] || die "размер актива $ASSET не совпал с GitHub"
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
    "$BUNDLE/router/S99r2o.shim" "$BUNDLE/router/001-r2o.sh" \
    "$BUNDLE/router/r2o-ppe-deoffload.sh"; do
    [ -f "$required_file" ] && [ ! -L "$required_file" ] || die "в подписанном выпуске отсутствует обычный файл $required_file"
done
[ -x "$BUNDLE/builds/r2o-manager-linux-$ARCH" ] || die "менеджер выпуска $ARCH не исполняемый"

OLD_RELEASE=$CURRENT_RELEASE
INSTALL_STARTED=1
say "устанавливаю подписанный выпуск $TARGET_RELEASE"
run_router_install "$BUNDLE" "$TARGET_RELEASE" || die 'установщик выпуска завершился ошибкой'
CURRENT_RELEASE=$(sed -n '2p' "$ROOT/release-slots" 2>/dev/null || true)
[ "$CURRENT_RELEASE" = "$TARGET_RELEASE" ] || die 'менеджер не активировал проверенный выпуск'
INSTALL_STARTED=0
say "установлен подписанный выпуск $TARGET_RELEASE; службы R2O, Telegram и Lava запущены"
