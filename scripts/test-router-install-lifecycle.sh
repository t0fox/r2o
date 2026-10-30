#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
MANAGER_BIN=${R2O_MANAGER_BIN:-$ROOT/target/release/r2o-manager}
[ -x "$MANAGER_BIN" ] || { echo "не найден менеджер для проверки установки: $MANAGER_BIN" >&2; exit 1; }
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
BUNDLE=$TEMP/bundle
INSTALL_ROOT=$TEMP/opt/r2o
INIT_DIR=$TEMP/opt/etc/init.d
OPENWRT_INIT_DIR=$TEMP/openwrt-init.d
NDM_DIR=$TEMP/opt/etc/ndm/netfilter.d
OPENWRT_RELEASE=$TEMP/openwrt_release
RUNTIME_DIR=$TEMP/r2o-runtime
OFF_CONFIG=$TEMP/off.conf
EVENTS=$TEMP/uninstall-events
FIREWALL=$TEMP/firewall
TG_FIREWALL=$TEMP/tg-firewall
TEST_BIN=$TEMP/bin
mkdir -p "$BUNDLE/builds" "$BUNDLE/router" "$INIT_DIR" "$OPENWRT_INIT_DIR" "$NDM_DIR" "$RUNTIME_DIR" "$TEST_BIN"
printf 'MODE=off\nTG_ENABLED=0\n' > "$OFF_CONFIG"
printf 'DISTRIB_ID="OpenWrt"\n' > "$OPENWRT_RELEASE"
cat > "$TEST_BIN/ip" <<'EOF'
#!/bin/sh
[ "$*" = '-4 -o addr show scope global' ] || exit 2
cat <<'ADDRS'
9: ppp0 inet 198.51.100.11/24 scope global ppp0
10: br1 inet 10.1.30.1/24 scope global br1
11: br0 inet 192.168.1.1/24 scope global br0
ADDRS
EOF
cat > "$FIREWALL" <<EOF
#!/bin/sh
if [ "\$1" = ipv6-enabled ]; then . "\$R2O_CONFIG"; printf '%s\\n' "\${IPV6_ENABLED:-1}"; exit 0; fi
printf 'firewall:%s\\n' "\$1" >> "$EVENTS"
EOF
cat > "$TG_FIREWALL" <<EOF
#!/bin/sh
printf 'telegram-firewall:%s\\n' "\$1" >> "$EVENTS"
EOF
cat > "$OPENWRT_INIT_DIR/r2o" <<EOF
#!/bin/sh
# OpenWrt host-side waiter
printf 'openwrt:%s\\n' "\$1" >> "$EVENTS"
EOF
chmod 0755 "$FIREWALL" "$TG_FIREWALL" "$OPENWRT_INIT_DIR/r2o" "$TEST_BIN/ip"

for component in r2o-datapath r2o-controller r2o-panel r2o-telegram r2o-manager r2o-fetch; do
    destination=$BUNDLE/builds/$component-linux-testhost
    if [ "$component" = r2o-manager ]; then
        cp "$MANAGER_BIN" "$destination"
    else
        printf '#!/bin/sh\nexit 0\n' > "$destination"
    fi
    chmod 0755 "$destination"
done
cp -R "$ROOT/router/." "$BUNDLE/router/"
cp "$OPENWRT_INIT_DIR/r2o" "$BUNDLE/router/openwrt-init"
chmod 0755 "$BUNDLE/router/S99r2o" "$BUNDLE/router/S99r2o.shim"
chmod 0755 "$BUNDLE/router/openwrt-init"

install_release() {
    if ! PATH="$TEST_BIN:$PATH" \
        R2O_DIR="$INSTALL_ROOT" \
        R2O_INIT_DIR="$INIT_DIR" \
        R2O_NDM_DIR="$NDM_DIR" \
        R2O_CONFIG="$OFF_CONFIG" \
        R2O_PLATFORM=local \
            sh "$ROOT/router/install.sh" "$BUNDLE" "$1" testhost >"$TEMP/$1.log" 2>&1; then
        cat "$TEMP/$1.log" >&2
        return 1
    fi
}

printf '# foreign NDM hook\n' > "$NDM_DIR/001-r2o.sh"
if R2O_DIR="$INSTALL_ROOT" \
    R2O_INIT_DIR="$INIT_DIR" \
    R2O_NDM_DIR="$NDM_DIR" \
    R2O_CONFIG="$OFF_CONFIG" \
    R2O_PLATFORM=local \
        sh "$ROOT/router/install.sh" "$BUNDLE" r2o-install-conflict testhost \
        >"$TEMP/conflict.log" 2>&1; then
    echo "установка перезаписала чужой NDM hook" >&2
    exit 1
fi
grep -qx '# foreign NDM hook' "$NDM_DIR/001-r2o.sh" || {
    echo "проверка конфликта повредила чужой NDM hook" >&2
    exit 1
}
[ ! -e "$INSTALL_ROOT/release-slots" ] || {
    echo "конфликт NDM обнаружен после изменения активного выпуска" >&2
    exit 1
}
rm "$NDM_DIR/001-r2o.sh"

install_release r2o-install-test1
[ "$(sed -n '2p' "$INSTALL_ROOT/release-slots")" = r2o-install-test1 ] || {
    echo "чистая установка не активировала выпуск" >&2
    exit 1
}
[ -x "$INIT_DIR/S99r2o" ] || { echo "не установлен shim автозапуска" >&2; exit 1; }
cmp "$BUNDLE/router/001-r2o.sh" "$NDM_DIR/001-r2o.sh" || {
    echo "не установлен NDM hook из выпуска" >&2
    exit 1
}
grep -qx 'PROBE_MARK=46' "$INSTALL_ROOT/config" || {
    echo "конфигурация не приняла штатный PROBE_MARK" >&2
    exit 1
}
grep -qx 'ONLY_MARK=' "$INSTALL_ROOT/config" || {
    echo "конфигурация не приняла штатный ONLY_MARK" >&2
    exit 1
}
grep -qx 'PANEL_LISTEN=192.168.1.1:8090' "$INSTALL_ROOT/config" || {
    echo "первая установка не выбрала частный адрес br0 для панели" >&2
    exit 1
}
sed 's/^PANEL_LISTEN=.*/PANEL_LISTEN=0.0.0.0:8090/' \
    "$INSTALL_ROOT/config" > "$TEMP/config.manual"
mv "$TEMP/config.manual" "$INSTALL_ROOT/config"
cp "$INSTALL_ROOT/config" "$TEMP/config.before-upgrade"

install_release r2o-install-test2
[ "$(sed -n '2p' "$INSTALL_ROOT/release-slots")" = r2o-install-test2 ] || {
    echo "обновление не активировало новый выпуск" >&2
    exit 1
}
[ "$(sed -n '3p' "$INSTALL_ROOT/release-slots")" = r2o-install-test1 ] || {
    echo "обновление не сохранило предыдущий выпуск" >&2
    exit 1
}
cmp "$TEMP/config.before-upgrade" "$INSTALL_ROOT/config"
grep -qx 'PANEL_LISTEN=0.0.0.0:8090' "$INSTALL_ROOT/config" || {
    echo "обновление перезаписало явно настроенный PANEL_LISTEN" >&2
    exit 1
}

"$INSTALL_ROOT/r2o-manager" rollback --root "$INSTALL_ROOT" >/dev/null
[ "$(sed -n '2p' "$INSTALL_ROOT/release-slots")" = r2o-install-test1 ] || {
    echo "откат не восстановил предыдущий выпуск" >&2
    exit 1
}

R2O_DIR="$INSTALL_ROOT" \
R2O_CONFIG="$OFF_CONFIG" \
R2O_INIT="$INIT_DIR/S99r2o" \
R2O_RUNTIME_DIR="$RUNTIME_DIR" \
R2O_FIREWALL="$FIREWALL" \
R2O_TG_FIREWALL="$TG_FIREWALL" \
    "$INIT_DIR/S99r2o" settings-restart
grep -qx 'firewall:down' "$EVENTS" || {
    echo "settings-restart не остановил datapath в режиме off" >&2
    exit 1
}
grep -qx 'telegram-firewall:stop' "$EVENTS" || {
    echo "settings-restart не перезагрузил конфигурацию Telegram" >&2
    exit 1
}

R2O_DIR="$INSTALL_ROOT" \
R2O_INIT_DIR="$INIT_DIR" \
R2O_CONFIG="$OFF_CONFIG" \
R2O_OPENWRT_INIT_DIR="$OPENWRT_INIT_DIR" \
R2O_NDM_DIR="$NDM_DIR" \
R2O_OPENWRT_RELEASE="$OPENWRT_RELEASE" \
R2O_RUNTIME_DIR="$RUNTIME_DIR" \
R2O_FIREWALL="$FIREWALL" \
R2O_TG_FIREWALL="$TG_FIREWALL" \
    sh "$ROOT/router/uninstall.sh" --yes
[ ! -e "$INSTALL_ROOT" ] || { echo "удаление оставило каталог выпуска" >&2; exit 1; }
[ ! -e "$INIT_DIR/S99r2o" ] || { echo "удаление оставило shim автозапуска" >&2; exit 1; }
[ ! -e "$OPENWRT_INIT_DIR/r2o" ] || { echo "удаление оставило службу OpenWrt" >&2; exit 1; }
[ ! -e "$NDM_DIR/001-r2o.sh" ] || { echo "удаление оставило NDM hook R2O" >&2; exit 1; }
[ ! -e "$RUNTIME_DIR" ] || { echo "удаление оставило runtime-каталог" >&2; exit 1; }
grep -qx 'firewall:down' "$EVENTS" || { echo "удаление не сняло firewall R2O" >&2; exit 1; }
grep -qx 'telegram-firewall:stop' "$EVENTS" || { echo "удаление не сняло Telegram firewall" >&2; exit 1; }
grep -qx 'openwrt:disable' "$EVENTS" || { echo "удаление не отключило OpenWrt автозапуск" >&2; exit 1; }

install_release r2o-install-test3
printf '\n# owner customization\n' >> "$NDM_DIR/001-r2o.sh"
R2O_DIR="$INSTALL_ROOT" \
R2O_INIT_DIR="$INIT_DIR" \
R2O_CONFIG="$OFF_CONFIG" \
R2O_NDM_DIR="$NDM_DIR" \
R2O_OPENWRT_INIT_DIR="$OPENWRT_INIT_DIR" \
R2O_OPENWRT_RELEASE="$OPENWRT_RELEASE" \
R2O_RUNTIME_DIR="$RUNTIME_DIR" \
R2O_FIREWALL="$FIREWALL" \
R2O_TG_FIREWALL="$TG_FIREWALL" \
    sh "$ROOT/router/uninstall.sh" --yes
grep -q '^# owner customization$' "$NDM_DIR/001-r2o.sh" || {
    echo "удаление затёрло изменённый NDM hook" >&2
    exit 1
}
echo "Проверены чистая установка, обновление, откат и удаление с сохранением изменённого NDM hook"
