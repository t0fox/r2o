#!/bin/sh
# Живой D2O-oracle: собрать detect/d2k-detect под aarch64/musl и запустить
# его на роутере. Локально рождённые пакеты роутера не проходят через
# R2O PREROUTING, поэтому classifier измеряет линию, а не R2O-обход.
#
# ВАЖНО: если DNS на роутере подменяет имя на sentinel (rutracker.org ->
# 10.171.171.171), передавайте IP:порт из публичного DNS. Иначе oracle
# измерит rt-proxy, а не прямую линию.
#
# Использование:
#   scripts/r2o-live-d2o-detect.sh HOST:PORT SNI [флаги d2k-detect...]
# Примеры:
#   scripts/r2o-live-d2o-detect.sh www.linkedin.com:443 www.linkedin.com \
#       --repeats 3 --timeout 6000 --progress --json
#   scripts/r2o-live-d2o-detect.sh 172.67.182.196:443 rutracker.org \
#       --repeats 3 --timeout 6000 --progress --json
#
# Переменные:
#   R2O_DONOR_ROOT       каталог D2O (по умолчанию ../d2o)
#   R2O_OPENWRT_SDK      OpenWrt aarch64-musl SDK
#   R2O_ROUTER           SSH-адрес роутера (root@192.168.1.1)
#   R2O_D2O_DETECT_BIN   готовый aarch64-бинарник вместо сборки
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/r2o}/d2o}
SDK=${R2O_OPENWRT_SDK:-/home/kirill/.cache/r2o/openwrt/openwrt-aarch64-musl-sdk}
ROUTER=${R2O_ROUTER:-root@192.168.1.1}
CC=$SDK/bin/aarch64-openwrt-linux-musl-gcc

if [ "$#" -lt 2 ]; then
    sed -n '2,25p' "$0" >&2
    exit 2
fi

TARGET=$1
SNI=$2
shift 2

BIN=${R2O_D2O_DETECT_BIN:-}
TMP=
cleanup() {
    [ -z "$TMP" ] || rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM

if [ -z "$BIN" ]; then
    [ -d "$D2O_ROOT/detect" ] || { echo "нет D2O: $D2O_ROOT" >&2; exit 2; }
    [ -x "$CC" ] || { echo "нет OpenWrt SDK gcc: $CC" >&2; exit 2; }
    TMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-d2o-detect.XXXXXX")
    BIN=$TMP/d2k-detect
    make -s -C "$D2O_ROOT/core" hello_profiles.inc
    "$CC" -std=c99 -O2 -Wall -Wextra -Werror \
        -I"$D2O_ROOT/detect/include" -I"$D2O_ROOT/core/include" \
        -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core" \
        -static -o "$BIN" \
        "$D2O_ROOT/detect/main.c" "$D2O_ROOT/detect/classify.c" \
        "$D2O_ROOT/detect/poison.c" "$D2O_ROOT/detect/props.c" \
        "$D2O_ROOT/detect/raw.c" "$D2O_ROOT/detect/trigger.c" \
        "$D2O_ROOT/detect/response.c" \
        "$D2O_ROOT/core/measured.c" "$D2O_ROOT/core/hello.c" \
        "$D2O_ROOT/core/plantlv.c" "$D2O_ROOT/core/quic.c" \
        "$D2O_ROOT/core/quicwire.c" "$D2O_ROOT/core/crypto.c" \
        "$D2O_ROOT/datapath/plan_parse.c" "$D2O_ROOT/datapath/plan_apply.c" \
        "$D2O_ROOT/datapath/wire.c" -lpthread
fi

ssh -o BatchMode=yes "$ROUTER" "cat > /tmp/d2k-detect" <"$BIN"
ssh -o BatchMode=yes "$ROUTER" "chmod 755 /tmp/d2k-detect"
exec ssh -o BatchMode=yes "$ROUTER" /tmp/d2k-detect classify "$TARGET" \
    --sni "$SNI" --mark 0x2e "$@"
