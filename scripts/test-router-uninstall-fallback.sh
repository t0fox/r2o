#!/bin/sh
# B40: uninstall без shim/активного адаптера продолжает аварийную очистку.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    [ -z "${sleep_pid:-}" ] || kill "$sleep_pid" 2>/dev/null || true
    rm -rf "$TEMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

# В аварийной установке нет соседних адаптеров из рабочего checkout.
# Отдельная копия проверяет удаление по PID без доступа к firewall хоста;
# ошибки DNS/firewall ниже задаются адаптерами самого активного выпуска.
UNINSTALL=$TEMP/uninstall.sh
cp "$ROOT/router/uninstall.sh" "$UNINSTALL"

install_root=$TEMP/r2o
mkdir -p "$install_root/releases/test/router" "$install_root/run" "$TEMP/init" "$TEMP/openwrt-init"
printf 'R2O-RELEASE-SLOTS-1\ntest\n' > "$install_root/release-slots"
/bin/sleep 30 &
sleep_pid=$!
printf '%s\n' "$sleep_pid" > "$install_root/run/r2o-datapath4.pid"

env R2O_INIT_DIR="$TEMP/init" R2O_OPENWRT_INIT_DIR="$TEMP/openwrt-init" \
    R2O_OPENWRT_RELEASE="$TEMP/missing-openwrt-release" \
    R2O_RUNTIME_DIR="$TEMP/r2o-runtime" R2O_NDM_DIR="$TEMP/ndm" \
    sh "$UNINSTALL" --root "$install_root" --yes

[ ! -e "$install_root" ] || { echo "uninstall оставил каталог установки" >&2; exit 1; }
if kill -0 "$sleep_pid" 2>/dev/null; then
    echo "uninstall не остановил процесс из PID-файла" >&2
    exit 1
fi
sleep_pid=

# Ошибка очистки DNS должна сохранить живой прокси и ownership до повтора.
# Здесь проверяется порядок удаления, сетевые проверки выполняются отдельно.
mkdir -p "$install_root/releases/test/router" "$install_root/run" "$install_root/state/rt-dns"
printf 'R2O-RELEASE-SLOTS-1\ntest\n' > "$install_root/release-slots"
printf 'retained DNS ownership\n' > "$install_root/state/rt-dns/owned.tsv"
cat > "$install_root/releases/test/router/r2o-rt-dns.sh" <<'EOF'
#!/bin/sh
[ "$1" = clear ] || exit 2
exit 1
EOF
chmod 0755 "$install_root/releases/test/router/r2o-rt-dns.sh"
/bin/sleep 60 &
sleep_pid=$!
printf '%s\n' "$sleep_pid" > "$install_root/run/r2o-rt-proxy.pid"
if env R2O_INIT_DIR="$TEMP/init" R2O_OPENWRT_INIT_DIR="$TEMP/openwrt-init" \
    R2O_OPENWRT_RELEASE="$TEMP/missing-openwrt-release" \
    R2O_RUNTIME_DIR="$TEMP/r2o-runtime" R2O_NDM_DIR="$TEMP/ndm" \
    sh "$UNINSTALL" --root "$install_root" --yes > "$TEMP/blocked.log" 2>&1; then
    echo 'uninstall удалил установку после ошибки очистки DNS' >&2
    exit 1
fi
kill -0 "$sleep_pid" || { echo 'uninstall остановил прокси до очистки DNS' >&2; exit 1; }
grep -Fxq 'retained DNS ownership' "$install_root/state/rt-dns/owned.tsv" || {
    echo 'uninstall потерял журнал DNS после ошибки' >&2; exit 1;
}
grep -q 'журнал сохранены' "$TEMP/blocked.log" || { cat "$TEMP/blocked.log" >&2; exit 1; }
sed 's/^exit 1$/exit 0/' "$install_root/releases/test/router/r2o-rt-dns.sh" > "$TEMP/clear-fixed"
cat "$TEMP/clear-fixed" > "$install_root/releases/test/router/r2o-rt-dns.sh"
cat > "$install_root/releases/test/router/r2o-rt-firewall.sh" <<'EOF'
#!/bin/sh
[ "$1" = stop ] || exit 2
exit 1
EOF
chmod 0755 "$install_root/releases/test/router/r2o-rt-firewall.sh"
if env R2O_INIT_DIR="$TEMP/init" R2O_OPENWRT_INIT_DIR="$TEMP/openwrt-init" \
    R2O_OPENWRT_RELEASE="$TEMP/missing-openwrt-release" \
    R2O_RUNTIME_DIR="$TEMP/r2o-runtime" R2O_NDM_DIR="$TEMP/ndm" \
    sh "$UNINSTALL" --root "$install_root" --yes > "$TEMP/firewall-blocked.log" 2>&1; then
    echo 'uninstall проигнорировал ошибку очистки firewall' >&2; exit 1
fi
kill -0 "$sleep_pid" || { echo 'uninstall остановил процесс до очистки firewall' >&2; exit 1; }
[ -f "$install_root/release-slots" ] || { echo 'uninstall удалил установку с оставшимся firewall' >&2; exit 1; }
sed 's/^exit 1$/exit 0/' "$install_root/releases/test/router/r2o-rt-firewall.sh" > "$TEMP/firewall-fixed"
cat "$TEMP/firewall-fixed" > "$install_root/releases/test/router/r2o-rt-firewall.sh"
env R2O_INIT_DIR="$TEMP/init" R2O_OPENWRT_INIT_DIR="$TEMP/openwrt-init" \
    R2O_OPENWRT_RELEASE="$TEMP/missing-openwrt-release" \
    R2O_RUNTIME_DIR="$TEMP/r2o-runtime" R2O_NDM_DIR="$TEMP/ndm" \
    sh "$UNINSTALL" --root "$install_root" --yes
[ ! -e "$install_root" ] || { echo 'повторный uninstall сохранил очищенную установку' >&2; exit 1; }
if kill -0 "$sleep_pid" 2>/dev/null; then
    echo 'повторный uninstall не остановил процесс' >&2; exit 1
fi
sleep_pid=
echo 'uninstall проверил аварийную остановку, сохранение при ошибке DNS и успешный повтор'
