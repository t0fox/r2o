#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
eval "$(sed -n '/^start_controller_both() {/,/^}/p' "$ROOT/router/S99r2o")"

export SOCK4=/test/controller4.sock SOCK6=/test/controller6.sock CATALOG=/test/catalog.json
export RUNTIME=/test/run LOG=/test/log CT_PID=/test/controller.pid MEASURE_MARK=0
unset R2O_CONTROLLER_DNS_FAMILY

spawn_component() {
    # Проверяем окружение дочернего процесса, как при штатном запуске.
    sh -c 'printf "%s|%s\n" "$R2O_CONTROLLER_DNS_FAMILY" "$*"' sh "$@"
}

case "$(IPV6_ENABLED=0 start_controller_both 42)" in
    *' --serve6 '*) exit 1 ;;
    '4|r2o-controller '*' --serve4 '*) ;;
    *) exit 1 ;;
esac
case "$(IPV6_ENABLED=1 start_controller_both 42)" in
    '|r2o-controller '*' --serve4 '*' --serve6 '*) ;;
    *) exit 1 ;;
esac
printf '%s\n' 'Семейства DNS-проверок при запуске контроллера: OK'
