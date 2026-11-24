#!/bin/sh
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
platform=${1:?Укажите keenetic или openwrt}
output=${2:?Укажите новый путь к тестовому диску}
probe=${3:?Укажите probe нужной архитектуры}
candidate=${4:?Укажите каталог распакованного кандидата}
tag=${5:?Укажите идентификатор кандидата}
published=${6:?Укажите исходный архив опубликованного выпуска}
published_tag=${7:?Укажите идентификатор опубликованного выпуска}
[ ! -e "$output" ] && [ ! -L "$output" ] || { echo 'Выходной диск уже существует' >&2; exit 2; }
case "$tag $published_tag" in *[!A-Za-z0-9._\ -]*) exit 2 ;; esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
opt=$work/opt
mkdir -p "$opt/lab"
case "$platform" in
    keenetic)
        arch=mipsel
        base=${8:?Укажите исходное дерево OPKG Keenetic с bin и feed}
        cp -a "$base/bin" "$base/feed" "$opt/"
        cp "$base/lab/opkg.conf" "$opt/lab/"
        cp "$base/lab/xtables-legacy-multi" "$opt/lab/"
        mkdir -p "$opt/etc/ndm/netfilter.d" "$opt/etc/init.d"
        install -m755 "$here/keenetic-initrc" "$opt/etc/initrc"
        install -m755 "$here/keenetic-rpdb.sh" "$opt/lab/keenetic-rpdb.sh"
        if [ -n "${R2O_LAB_TLS_DIR:-}" ]; then
            cp -a "$R2O_LAB_TLS_DIR" "$opt/lab/tls"
            install -m644 "$here/tls-origin.py" "$opt/lab/tls-origin.py"
            install -m755 "$here/keenetic-discovery.sh" "$opt/lab/keenetic-discovery.sh"
        fi
        backend=iptables
        ;;
    openwrt) arch=x86_64-musl; backend=auto ;;
    *) exit 2 ;;
esac
for name in lifecycle.sh network.sh soak.sh; do
    install -m755 "$here/$name" "$opt/lab/$name"
    if [ "$platform" = openwrt ]; then
        sed -i '1s@^#!.*@#!/bin/sh@' "$opt/lab/$name"
    fi
done
cp -a "$candidate" "$opt/lab/bundle"
cp "$published" "$opt/lab/published.tar.gz"
install -m755 "$probe" "$opt/lab/probe"
printf 'LAB_ARCH=%s\nLAB_CANDIDATE=%s\nLAB_PUBLISHED=%s\n' "$arch" "$tag" "$published_tag" >"$opt/lab/settings"
sed -e 's/^AUTOUPDATE=.*/AUTOUPDATE=0/' -e 's/^PANEL_LISTEN=.*/PANEL_LISTEN=/' \
    -e 's/^TG_ENABLED=.*/TG_ENABLED=0/' -e 's/^PORTS=.*/PORTS=443/' \
    -e 's/^R2O_FLOW_CAPACITY=.*/R2O_FLOW_CAPACITY=64/' \
    -e "s/^FW_BACKEND=.*/FW_BACKEND=$backend/" "$here/../../router/config.default" >"$opt/lab/config"
"${MKE2FS:-mke2fs}" -F -q -t ext4 -L R2OLAB -O '^orphan_file,^metadata_csum_seed' \
    -d "$opt" "$work/opt.ext4" 192M
if [ "$platform" = keenetic ]; then
    python3 "$here/partition-opt.py" "$work/opt.ext4" "$output"
else
    mv "$work/opt.ext4" "$output"
fi
