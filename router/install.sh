#!/bin/sh
set -eu

BUNDLE=${1:?использование: install.sh КАТАЛОГ ИД_ВЫПУСКА АРХИТЕКТУРА}
RELEASE_ID=${2:?использование: install.sh КАТАЛОГ ИД_ВЫПУСКА АРХИТЕКТУРА}
ARCH=${3:?использование: install.sh КАТАЛОГ ИД_ВЫПУСКА АРХИТЕКТУРА}
ROOT=${R2O_DIR:-/opt/r2o}
INIT_DIR=${R2O_INIT_DIR:-/opt/etc/init.d}
MANAGER=$BUNDLE/builds/r2o-manager-linux-$ARCH

[ -d "$BUNDLE" ] && [ ! -L "$BUNDLE" ] || { echo "каталог выпуска должен быть обычным каталогом" >&2; exit 2; }
[ -x "$MANAGER" ] && [ ! -L "$MANAGER" ] || { echo "в выпуске нет исполняемого менеджера для $ARCH" >&2; exit 2; }
[ -f "$BUNDLE/router/S99r2o.shim" ] && [ -f "$BUNDLE/router/config.default" ] || {
    echo "в выпуске отсутствуют файлы адаптера роутера" >&2
    exit 2
}

"$MANAGER" install-local --root "$ROOT" --bundle "$BUNDLE" \
    --release-id "$RELEASE_ID" --architecture "$ARCH"

mkdir -p "$ROOT" "$INIT_DIR"
DONOR_CONFIG=${R2O_DONOR_CONFIG:-/opt/d2k/config}
if [ -f "$DONOR_CONFIG" ]; then
    CONFIG_INIT_RESULT=$("$MANAGER" config-init --root "$ROOT" --defaults "$BUNDLE/router/config.default" \
        --donor-config "$DONOR_CONFIG"
    )
else
    CONFIG_INIT_RESULT=$("$MANAGER" config-init --root "$ROOT" --defaults "$BUNDLE/router/config.default")
fi
printf '%s\n' "$CONFIG_INIT_RESULT"

STATE_DIR=$(printf '%s\n' "$CONFIG_INIT_RESULT" | sed -n 's/.*"state_dir":"\([^"]*\)".*/\1/p')
DONOR_STATE_DIR=$(printf '%s\n' "$CONFIG_INIT_RESULT" | sed -n 's/.*"donor_state_dir":"\([^"]*\)".*/\1/p')
DONOR_STATE_DIR=${DONOR_STATE_DIR:-/opt/d2k/state}
DONOR_CATALOG=${R2O_DONOR_CATALOG:-$DONOR_STATE_DIR/catalog.json}
if [ -n "${R2O_TARGET_CATALOG:-}" ]; then
    TARGET_CATALOG=$R2O_TARGET_CATALOG
elif [ -n "$STATE_DIR" ]; then
    TARGET_CATALOG=$STATE_DIR/catalog.json
else
    TARGET_CATALOG=
fi
if [ -n "$TARGET_CATALOG" ] && [ -f "$DONOR_CATALOG" ] && [ ! -e "$TARGET_CATALOG" ]; then
    if ! "$MANAGER" exec --root "$ROOT" --component r2o-controller -- \
        --import-donor-catalog "$DONOR_CATALOG" "$TARGET_CATALOG"; then
        echo "r2o: каталог донора не перенесён; исходный файл сохранён" >&2
    fi
fi
cp "$BUNDLE/router/S99r2o.shim" "$INIT_DIR/S99r2o.new.$$"
chmod 0755 "$INIT_DIR/S99r2o.new.$$"
mv -f "$INIT_DIR/S99r2o.new.$$" "$INIT_DIR/S99r2o"

if [ -f /etc/openwrt_release ] || [ "${R2O_PLATFORM:-}" = openwrt ]; then
    cp "$BUNDLE/router/openwrt-init" /etc/init.d/r2o.new.$$
    chmod 0755 /etc/init.d/r2o.new.$$
    mv -f /etc/init.d/r2o.new.$$ /etc/init.d/r2o
    /etc/init.d/r2o enable
fi

"$INIT_DIR/S99r2o" start
