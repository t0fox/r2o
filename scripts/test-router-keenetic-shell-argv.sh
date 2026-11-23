#!/bin/sh
# shellcheck disable=SC2034 # Эти переменные читают извлечённые функции службы.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TEMP=$(mktemp -d)
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
fail() { printf 'Keenetic shell argv: %s\n' "$*" >&2; exit 1; }
SSD=$(command -v start-stop-daemon) || fail 'нужен настоящий start-stop-daemon'
SH_BIN=$(command -v sh)
BASE_PATH=$PATH
mkdir -p "$TEMP/opt/bin" "$TEMP/firmware/bin"
ln -s "$SH_BIN" "$TEMP/opt/bin/sh"

# Поведение NDM Shell Wrapper 1.0.10 проверено на бинарниках прошивок KN-1910/1913:
# при -c он передаёт только строку команды, при запуске файла сохраняет argv.
cat > "$TEMP/firmware/bin/sh" <<'EOF'
#!/bin/sh
if [ "$1" = -c ]; then exec /bin/sh -c "$2"; fi
exec /bin/sh "$@"
EOF
chmod 0755 "$TEMP/firmware/bin/sh"

wait_for_file() {
    attempt=0
    while [ ! -f "$1" ] && [ "$attempt" -lt 100 ]; do
        attempt=$((attempt + 1))
        sleep 0.05
    done
    [ -f "$1" ] || fail "фоновый процесс не создал $1"
}

# Сначала доказываем, что воспроизводитель действительно теряет аргумент.
R2O_ARGV_RESULT=$TEMP/dropped
export R2O_ARGV_RESULT
# shellcheck disable=SC2016 # Параметр должен раскрыться в дочерней оболочке.
"$SSD" -S -b -m -p "$TEMP/dropped.pid" -x "$TEMP/firmware/bin/sh" -- \
    -c 'printf "%s\n" "$1" > "$R2O_ARGV_RESULT"' r2o-probe 'сохранённый аргумент'
wait_for_file "$R2O_ARGV_RESULT"
[ -z "$(cat "$R2O_ARGV_RESULT")" ] || fail 'воспроизводитель NDM не потерял аргумент'

sed -n '/^select_command_shell() {/,/^}/p; /^check_datapath() {/,/^}/p' \
    "$ROOT/scripts/install.sh" > "$TEMP/installer-functions.sh"
sed -n '/^select_command_shell() {/,/^}/p; /^spawn_logged() {/,/^}/p' \
    "$ROOT/router/S99r2o" > "$TEMP/service-functions.sh"

cat > "$TEMP/datapath" <<'EOF'
#!/bin/sh
case "$1" in
    --offline-self-check)
        [ "$#" -eq 1 ] || exit 71
        printf '%s\n' self-check >> "$R2O_ARGV_RESULT" ;;
    --help) printf '%s\n' fixture ;;
    *) exit 72 ;;
esac
EOF
chmod 0755 "$TEMP/datapath"

for platform in keenetic openwrt; do
    mkdir "$TEMP/$platform"
    (
        # shellcheck disable=SC1091 # Функции извлечены выше из проверяемого файла.
        . "$TEMP/installer-functions.sh"
        die() { printf '%s\n' "$*" >&2; exit 1; }
        PLATFORM=$platform ENTWARE_OPKG=$TEMP/opt/bin/opkg
        mode=apply ARCH=mipsel TMP=$TEMP/$platform
        R2O_ARGV_RESULT=$TMP/calls
        export R2O_ARGV_RESULT
        check_datapath "$TEMP/datapath"
        [ "$(cat "$TMP/datapath-probe.done")" = 0 ] || fail "$platform: нет статуса пробы"
        [ "$(cat "$R2O_ARGV_RESULT")" = self-check ] || fail "$platform: бинарник не проверен"
    )
done

# Неисправная оболочка должна обнаружиться до фонового запуска и тайм-аута.
if (
    # shellcheck disable=SC1091
    . "$TEMP/installer-functions.sh"
    die() { printf '%s\n' "$*" >&2; exit 1; }
    PLATFORM=keenetic ENTWARE_OPKG=$TEMP/firmware/bin/opkg
    mode=apply ARCH=mipsel TMP=$TEMP/rejected
    mkdir "$TMP"
    check_datapath "$TEMP/datapath"
) > "$TEMP/rejected.log" 2>&1; then
    fail 'принята оболочка, теряющая аргументы'
fi
grep -q 'не сохраняет аргументы' "$TEMP/rejected.log" || fail 'нет причины отказа оболочки'
[ ! -e "$TEMP/rejected/preflight.pid" ] || fail 'неисправная оболочка запущена в фоне'

cat > "$TEMP/component" <<'EOF'
#!/bin/sh
printf 'argc=%s\n' "$#"
printf '<%s>\n' "$@"
printf '%s\n' R2O_CHILD_STDERR >&2
: > "$R2O_ARGV_RESULT"
EOF
chmod 0755 "$TEMP/component"
printf '%s\n' 'argc=3' '<alpha beta>' '<literal; $(no-command)>' '<>' R2O_CHILD_STDERR > "$TEMP/expected"

for platform in keenetic openwrt; do
    (
        # shellcheck disable=SC1091
        . "$TEMP/service-functions.sh"
        say() { printf '%s\n' "$*"; }
        PATH=$BASE_PATH
        [ "$platform" != keenetic ] || PATH=$TEMP/opt/bin:$PATH
        export PATH
        R2O_ARGV_RESULT=$TEMP/$platform/component.done
        export R2O_ARGV_RESULT
        # shellcheck disable=SC2016 # Литерал обязан дойти до компонента без исполнения.
        spawn_logged "$TEMP/$platform/component.pid" "$TEMP/$platform/component.log" \
            "$TEMP/component" 'alpha beta' 'literal; $(no-command)' ''
        wait_for_file "$R2O_ARGV_RESULT"
        cmp -s "$TEMP/expected" "$TEMP/$platform/component.log" || fail "$platform: потеряны argv/stdout/stderr"
        [ -s "$TEMP/$platform/component.pid" ] || fail "$platform: настоящий launcher не записал PID"
    )
done

printf '%s\n' 'Проверены NDM-потеря argv, реальный фоновый launcher, preflight и запуск службы через Entware/OpenWrt shell'
