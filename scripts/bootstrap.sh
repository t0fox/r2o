#!/bin/sh
set -eu
set -f

# Контрольную сумму этого файла закрепляет сценарий GitHub Pages.
INSTALL_SHA256='3c4549d2526047c3ffdc974ae0cf0939a24919d848a723829f7e3c7e0cb06efb'
source_url=https://raw.githubusercontent.com/t0fox/r2o/${R2O_BOOTSTRAP_REF:-main}/scripts/install.sh
export PATH="/opt/bin:/opt/sbin:$PATH"
# Прямой GitHub первым, затем резервные HTTPS-зеркала с проверкой SHA-256.
# Явно заданный список при необходимости заменяет зеркала по умолчанию.
: "${R2O_GITHUB_MIRRORS:=https://ghfast.top/ https://ghproxy.net/ https://gh-proxy.com/}"
export R2O_GITHUB_MIRRORS

if ! command -v curl >/dev/null 2>&1; then
    if [ -f "${R2O_OPENWRT_RELEASE:-/etc/openwrt_release}" ]; then
        if command -v apk >/dev/null 2>&1; then
            apk update && apk add curl ca-bundle || exit 1
        else
            opkg update && opkg install curl ca-bundle || exit 1
        fi
    elif [ -x /opt/bin/opkg ]; then
        /opt/bin/opkg update && /opt/bin/opkg install curl ca-bundle || exit 1
    else
        echo 'r2o: нужен OpenWrt или Keenetic с установленным Entware' >&2
        exit 1
    fi
fi

installer=$(mktemp "${TMPDIR:-/tmp}/r2o-bootstrap.XXXXXX")
trap 'rm -f "$installer"' EXIT
trap 'exit 1' HUP INT TERM
encoded=$(printf '%s' "$source_url" | sed 's/:/%3A/g; s!/!%2F!g')
attempts=0
# shellcheck disable=SC2086
for mirror in direct ${R2O_GITHUB_MIRRORS:-}; do
    [ "${#mirror}" -le 512 ] || continue
    case "$mirror" in direct|https://*) ;; *) continue ;; esac
    case "$mirror" in *'#'*|*'@'*) continue ;; esac
    case "$mirror" in
        direct) url=$source_url ;;
        *'{url}'*) url=${mirror%%\{url\}*}$source_url${mirror#*\{url\}} ;;
        *'{encoded_url}'*) url=${mirror%%\{encoded_url\}*}$encoded${mirror#*\{encoded_url\}} ;;
        *) url=${mirror%/}/$source_url ;;
    esac
    rm -f "$installer"
    if (ulimit -f 256 2>/dev/null || true; exec curl -q -fsSL --globoff --proto '=https' --proto-redir '=https' \
        --connect-timeout 8 --max-time 20 --max-redirs 5 --max-filesize 131072 \
        -o "$installer" -- "$url") &&
        [ "$(wc -c < "$installer")" -le 131072 ] &&
        printf '%s  %s\n' "$INSTALL_SHA256" "$installer" | sha256sum -c - >/dev/null 2>&1; then
        sh "$installer" "$@"
        exit $?
    fi
    attempts=$((attempts + 1))
    [ "$attempts" -lt 5 ] || break
done
echo 'r2o: установщик недоступен или его SHA-256 отличается от закреплённой' >&2
exit 1
