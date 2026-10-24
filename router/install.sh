#!/bin/sh
set -eu

BUNDLE=${1:?использование: install.sh КАТАЛОГ ИД_ВЫПУСКА АРХИТЕКТУРА}
RELEASE_ID=${2:?использование: install.sh КАТАЛОГ ИД_ВЫПУСКА АРХИТЕКТУРА}
ARCH=${3:?использование: install.sh КАТАЛОГ ИД_ВЫПУСКА АРХИТЕКТУРА}
ROOT=${R2O_DIR:-/opt/r2o}
INIT_DIR=${R2O_INIT_DIR:-/opt/etc/init.d}
NDM_DIR=${R2O_NDM_DIR:-/opt/etc/ndm/netfilter.d}
OPENWRT_INIT_DIR=${R2O_OPENWRT_INIT_DIR:-/etc/init.d}
NDM_HOOK=$NDM_DIR/001-r2o.sh
INIT_SHIM=$INIT_DIR/S99r2o
OPENWRT_SERVICE=$OPENWRT_INIT_DIR/r2o
MANAGER=$BUNDLE/builds/r2o-manager-linux-$ARCH

matches_release_file() {
    candidate=$1
    relative_file=$2
    for old_file in "$ROOT"/releases/*/router/"$relative_file"; do
        if [ -f "$old_file" ] && [ ! -L "$old_file" ] && cmp -s "$candidate" "$old_file"; then
            return 0
        fi
    done
    return 1
}

check_owned_file() {
    destination=$1
    source=$2
    relative_file=$3
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        if [ -L "$destination" ] || [ ! -f "$destination" ]; then
            echo "файл интеграции занят небезопасным объектом: $destination" >&2
            exit 2
        fi
        if ! cmp -s "$destination" "$source" && ! matches_release_file "$destination" "$relative_file"; then
            echo "чужой файл интеграции сохранён: $destination" >&2
            exit 2
        fi
    fi
}

# shellcheck disable=SC2015 # fail unless both validations succeed
[ -d "$BUNDLE" ] && [ ! -L "$BUNDLE" ] || { echo "каталог выпуска должен быть обычным каталогом" >&2; exit 2; }
# shellcheck disable=SC2015 # fail unless both validations succeed
[ -x "$MANAGER" ] && [ ! -L "$MANAGER" ] || { echo "в выпуске нет исполняемого менеджера для $ARCH" >&2; exit 2; }
# shellcheck disable=SC2015 # fail unless both required files exist
[ -f "$BUNDLE/router/S99r2o.shim" ] && [ -f "$BUNDLE/router/config.default" ] || {
    echo "в выпуске отсутствуют файлы адаптера роутера" >&2
    exit 2
}
if [ -L "$BUNDLE/router/001-r2o.sh" ] || [ ! -f "$BUNDLE/router/001-r2o.sh" ] \
    || [ -L "$BUNDLE/router/r2o-ppe-deoffload.sh" ] || [ ! -f "$BUNDLE/router/r2o-ppe-deoffload.sh" ]; then
    echo "в выпуске отсутствует адаптер NDM или PPE" >&2
    exit 2
fi

if [ -e "$ROOT" ] || [ -L "$ROOT" ]; then
    if [ -L "$ROOT" ] || [ ! -d "$ROOT" ]; then
        echo "каталог установки должен быть обычным каталогом: $ROOT" >&2
        exit 2
    fi
fi
if [ -e "$INIT_DIR" ] || [ -L "$INIT_DIR" ]; then
    if [ -L "$INIT_DIR" ] || [ ! -d "$INIT_DIR" ]; then
        echo "каталог автозапуска должен быть обычным каталогом: $INIT_DIR" >&2
        exit 2
    fi
fi
check_owned_file "$INIT_SHIM" "$BUNDLE/router/S99r2o.shim" S99r2o.shim
if [ -e "$ROOT/releases" ] || [ -L "$ROOT/releases" ]; then
    if [ -L "$ROOT/releases" ] || [ ! -d "$ROOT/releases" ]; then
        echo "каталог выпусков должен быть обычным каталогом: $ROOT/releases" >&2
        exit 2
    fi
fi

INSTALL_NDM_HOOK=0
if [ -e "$NDM_DIR" ] || [ -L "$NDM_DIR" ]; then
    if [ -L "$NDM_DIR" ] || [ ! -d "$NDM_DIR" ]; then
        echo "каталог NDM должен быть обычным каталогом" >&2
        exit 2
    fi
    if [ -e "$NDM_HOOK" ] || [ -L "$NDM_HOOK" ]; then
        if [ -L "$NDM_HOOK" ] || [ ! -f "$NDM_HOOK" ]; then
            echo "файл NDM hook уже занят небезопасным объектом: $NDM_HOOK" >&2
            exit 2
        fi
        NDM_OWNED=0
        if cmp -s "$NDM_HOOK" "$BUNDLE/router/001-r2o.sh"; then
            NDM_OWNED=1
        elif [ -d "$ROOT/releases" ]; then
            for OLD_HOOK in "$ROOT"/releases/*/router/001-r2o.sh; do
                if [ -f "$OLD_HOOK" ] && [ ! -L "$OLD_HOOK" ] && cmp -s "$NDM_HOOK" "$OLD_HOOK"; then
                    NDM_OWNED=1
                    break
                fi
            done
        fi
        [ "$NDM_OWNED" = 1 ] || {
            echo "файл NDM hook уже принадлежит другому владельцу: $NDM_HOOK" >&2
            exit 2
        }
    fi
    INSTALL_NDM_HOOK=1
fi

if [ -f /etc/openwrt_release ] || [ "${R2O_PLATFORM:-}" = openwrt ]; then
    if [ -L "$OPENWRT_INIT_DIR" ] || [ ! -d "$OPENWRT_INIT_DIR" ]; then
        echo "каталог служб OpenWrt должен быть обычным каталогом: $OPENWRT_INIT_DIR" >&2
        exit 2
    fi
    check_owned_file "$OPENWRT_SERVICE" "$BUNDLE/router/openwrt-init" openwrt-init
fi

INSTALL_LOCAL=1
SLOTS=$ROOT/release-slots
if [ -e "$SLOTS" ] || [ -L "$SLOTS" ]; then
    if [ -L "$SLOTS" ] || [ ! -f "$SLOTS" ] \
        || [ "$(sed -n '1p' "$SLOTS")" != R2O-RELEASE-SLOTS-1 ]; then
        echo "файл активного выпуска небезопасен или повреждён: $SLOTS" >&2
        exit 2
    fi
    CURRENT=$(sed -n '2p' "$SLOTS")
    case "$CURRENT" in ''|.|..|*[!A-Za-z0-9._-]*) echo "идентификатор активного выпуска повреждён" >&2; exit 2 ;; esac
    if [ "$CURRENT" = "$RELEASE_ID" ]; then
        ACTIVE_BUNDLE=$ROOT/releases/$RELEASE_ID
        if [ -L "$ACTIVE_BUNDLE" ] || [ ! -d "$ACTIVE_BUNDLE" ] \
            || [ -L "$ACTIVE_BUNDLE/release-architecture" ] \
            || [ ! -f "$ACTIVE_BUNDLE/release-architecture" ] \
            || [ "$(cat "$ACTIVE_BUNDLE/release-architecture")" != "$ARCH" ]; then
            echo "активный выпуск $RELEASE_ID не соответствует ABI $ARCH" >&2
            exit 2
        fi
        INSTALL_LOCAL=0
    fi
fi

if [ "$INSTALL_LOCAL" = 1 ]; then
    "$MANAGER" install-local --root "$ROOT" --bundle "$BUNDLE" \
        --release-id "$RELEASE_ID" --architecture "$ARCH"
else
    echo "r2o: выпуск $RELEASE_ID уже активен; восстанавливаю конфигурацию и интеграцию служб"
fi

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
SHIM_TMP=$INIT_DIR/.S99r2o.new.$$
cp "$BUNDLE/router/S99r2o.shim" "$SHIM_TMP"
chmod 0755 "$SHIM_TMP"
mv -f "$SHIM_TMP" "$INIT_SHIM"

if [ "$INSTALL_NDM_HOOK" = 1 ]; then
    NDM_TMP=$(mktemp "$NDM_DIR/.001-r2o.sh.XXXXXX")
    cp "$BUNDLE/router/001-r2o.sh" "$NDM_TMP"
    chmod 0755 "$NDM_TMP"
    mv -f "$NDM_TMP" "$NDM_HOOK"
    echo "r2o: установлен NDM hook в $NDM_HOOK"
fi

if [ -f /etc/openwrt_release ] || [ "${R2O_PLATFORM:-}" = openwrt ]; then
    OPENWRT_TMP=$OPENWRT_INIT_DIR/.r2o.new.$$
    cp "$BUNDLE/router/openwrt-init" "$OPENWRT_TMP"
    chmod 0755 "$OPENWRT_TMP"
    mv -f "$OPENWRT_TMP" "$OPENWRT_SERVICE"
    "$OPENWRT_SERVICE" enable
fi

"$INIT_SHIM" start
