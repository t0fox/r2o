#!/bin/sh
set -eu

ROOT=${R2O_DIR:-/opt/r2o}
INIT_DIR=${R2O_INIT_DIR:-/opt/etc/init.d}
OPENWRT_INIT_DIR=${R2O_OPENWRT_INIT_DIR:-/etc/init.d}
OPENWRT_RELEASE=${R2O_OPENWRT_RELEASE:-/etc/openwrt_release}
RUNTIME_DIR=${R2O_RUNTIME_DIR:-/tmp/r2o}
NDM_DIR=${R2O_NDM_DIR:-/opt/etc/ndm/netfilter.d}
YES=0

usage() {
    echo "использование: $0 [--root КАТАЛОГ] [--init-dir КАТАЛОГ] [--openwrt-init-dir КАТАЛОГ] [--yes]" >&2
}

fail() {
    echo "r2o uninstall: $*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            [ "$#" -ge 2 ] || { usage; exit 2; }
            ROOT=$2
            shift 2
            ;;
        --init-dir)
            [ "$#" -ge 2 ] || { usage; exit 2; }
            INIT_DIR=$2
            shift 2
            ;;
        --openwrt-init-dir)
            [ "$#" -ge 2 ] || { usage; exit 2; }
            OPENWRT_INIT_DIR=$2
            shift 2
            ;;
        --yes)
            YES=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done

case "$ROOT" in
    /*) ;;
    *) fail "каталог установки должен быть абсолютным" ;;
esac
case "$ROOT" in
    /|*/..|*/../*|*/./*|*/.) fail "небезопасный каталог установки" ;;
esac
[ "$(basename "$ROOT")" = r2o ] || fail "каталог установки должен называться r2o"
[ ! -L "$ROOT" ] || fail "каталог установки отсутствует или является ссылкой"
[ -d "$ROOT" ] || fail "каталог установки отсутствует или является ссылкой"
[ ! -L "$ROOT/releases" ] || fail "каталог выпусков отсутствует или является ссылкой"
[ -d "$ROOT/releases" ] || fail "каталог выпусков отсутствует или является ссылкой"
[ ! -L "$ROOT/release-slots" ] || fail "файл активного выпуска отсутствует или является ссылкой"
[ -f "$ROOT/release-slots" ] || fail "файл активного выпуска отсутствует или является ссылкой"
[ "$(sed -n '1p' "$ROOT/release-slots")" = R2O-RELEASE-SLOTS-1 ] || fail "файл активного выпуска не принадлежит R2O"

if [ "$YES" -ne 1 ]; then
    [ -t 0 ] || fail "для удаления без терминала укажите --yes"
    printf 'Остановить R2O и удалить %s, включая config, каталог решений и журналы? [y/N] ' "$ROOT" >&2
    IFS= read -r answer || exit 1
    case "$answer" in y|Y|yes|YES) ;; *) echo "удаление отменено" >&2; exit 1 ;; esac
fi

INIT_SCRIPT=$INIT_DIR/S99r2o
ACTIVE=$(sed -n '2p' "$ROOT/release-slots")
case "$ACTIVE" in
    ''|.|..|*[!A-Za-z0-9._-]*) fail "идентификатор активного выпуска повреждён" ;;
esac
ACTIVE_SCRIPT=$ROOT/releases/$ACTIVE/router/S99r2o
ACTIVE_NDM_HOOK=$ROOT/releases/$ACTIVE/router/001-r2o.sh
OWNED_SHIM=0
if [ -e "$INIT_SCRIPT" ]; then
    [ ! -L "$INIT_SCRIPT" ] || fail "shim автозапуска изменён или является ссылкой"
    [ -f "$INIT_SCRIPT" ] || fail "shim автозапуска изменён или является ссылкой"
    EXPECTED_SHIM=$ROOT/releases/$ACTIVE/router/S99r2o.shim
    [ ! -L "$EXPECTED_SHIM" ] || fail "shim активного выпуска отсутствует"
    [ -f "$EXPECTED_SHIM" ] || fail "shim активного выпуска отсутствует"
    cmp -s "$INIT_SCRIPT" "$EXPECTED_SHIM" || fail "shim автозапуска не совпадает с активным выпуском"
    [ -x "$INIT_SCRIPT" ] || fail "shim автозапуска не исполняемый"
    OWNED_SHIM=1
    "$INIT_SCRIPT" stop
elif [ ! -L "$ACTIVE_SCRIPT" ] && [ -f "$ACTIVE_SCRIPT" ] && [ -x "$ACTIVE_SCRIPT" ]; then
    R2O_DIR=$ROOT "$ACTIVE_SCRIPT" stop
else
    fail "не найден адаптер службы для безопасной остановки"
fi

if [ -f "$OPENWRT_RELEASE" ] || [ "${R2O_PLATFORM:-}" = openwrt ]; then
    OPENWRT_SERVICE=$OPENWRT_INIT_DIR/r2o
    if [ -f "$OPENWRT_SERVICE" ] && grep -Fq 'OpenWrt host-side waiter' "$OPENWRT_SERVICE"; then
        if [ -x "$OPENWRT_SERVICE" ]; then
            "$OPENWRT_SERVICE" disable
        fi
        rm -f "$OPENWRT_SERVICE"
    fi
fi

if [ "$OWNED_SHIM" = 1 ]; then
    rm -f "$INIT_SCRIPT"
fi

NDM_HOOK=$NDM_DIR/001-r2o.sh
if [ -e "$NDM_HOOK" ] || [ -L "$NDM_HOOK" ]; then
    if [ ! -L "$NDM_HOOK" ] && [ -f "$NDM_HOOK" ] \
        && [ ! -L "$ACTIVE_NDM_HOOK" ] && [ -f "$ACTIVE_NDM_HOOK" ] \
        && cmp -s "$NDM_HOOK" "$ACTIVE_NDM_HOOK"; then
        rm -f "$NDM_HOOK"
    else
        echo "r2o uninstall: изменённый или чужой NDM hook сохранён: $NDM_HOOK" >&2
    fi
fi

case "$RUNTIME_DIR" in
    /*/r2o|/*/r2o-runtime)
        [ "$RUNTIME_DIR" != / ] || fail "небезопасный runtime-каталог"
        [ ! -L "$RUNTIME_DIR" ] || fail "небезопасный runtime-каталог"
        if [ -e "$RUNTIME_DIR" ] && [ ! -d "$RUNTIME_DIR" ]; then
            fail "runtime-путь не является каталогом"
        fi
        [ ! -e "$RUNTIME_DIR" ] || rm -rf "$RUNTIME_DIR"
        ;;
    *) fail "runtime-каталог должен быть отдельной папкой r2o" ;;
esac

rm -rf "$ROOT"
echo "R2O остановлен и удалён из $ROOT (включая конфигурацию, каталог решений и журналы)"
