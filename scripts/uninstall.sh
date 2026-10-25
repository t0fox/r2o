#!/bin/sh
# Dispatch to the uninstaller shipped with the active installed release.
set -eu

ROOT=${R2O_DIR:-/opt/r2o}

case "$ROOT" in
    /*) ;;
    *) echo "r2o uninstall: каталог установки должен быть абсолютным" >&2; exit 1 ;;
esac
case "$ROOT" in
    /|*/..|*/../*|*/./*|*/.) echo "r2o uninstall: небезопасный каталог установки" >&2; exit 1 ;;
esac
[ "$(basename "$ROOT")" = r2o ] || { echo "r2o uninstall: каталог установки должен называться r2o" >&2; exit 1; }
[ ! -L "$ROOT" ] && [ -d "$ROOT" ] || { echo "r2o uninstall: каталог установки отсутствует или является ссылкой" >&2; exit 1; }
[ ! -L "$ROOT/releases" ] && [ -d "$ROOT/releases" ] || { echo "r2o uninstall: каталог выпусков отсутствует или является ссылкой" >&2; exit 1; }
[ ! -L "$ROOT/release-slots" ] && [ -f "$ROOT/release-slots" ] || { echo "r2o uninstall: файл активного выпуска отсутствует или является ссылкой" >&2; exit 1; }
[ "$(sed -n '1p' "$ROOT/release-slots")" = R2O-RELEASE-SLOTS-1 ] || {
    echo "r2o uninstall: файл активного выпуска не принадлежит R2O" >&2
    exit 1
}

ACTIVE=$(sed -n '2p' "$ROOT/release-slots")
case "$ACTIVE" in
    ''|.|..|*[!A-Za-z0-9._-]*) echo "r2o uninstall: идентификатор активного выпуска повреждён" >&2; exit 1 ;;
esac

UNINSTALLER=$ROOT/releases/$ACTIVE/router/uninstall.sh
[ ! -L "$UNINSTALLER" ] && [ -f "$UNINSTALLER" ] || {
    echo "r2o uninstall: деинсталлятор активного выпуска отсутствует или является ссылкой" >&2
    exit 1
}

if [ ! -t 0 ] && ( : </dev/tty ) 2>/dev/null; then
    exec sh "$UNINSTALLER" --root "$ROOT" "$@" </dev/tty
fi
exec sh "$UNINSTALLER" --root "$ROOT" "$@"
