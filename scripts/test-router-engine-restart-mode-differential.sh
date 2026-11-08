#!/bin/sh
# B6: paired C/Rust differential ветвей start/restart/engine-restart при MODE=off.
#
# Ветви извлекаются из закреплённых исходников, а не переписываются: проверяется
# именно то, что исполняет служба. Стенд подменяет только побочные команды.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-b6-restart.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

D2O_SERVICE="$D2O_ROOT/files/S99d2k"
R2O_SERVICE="$ROOT/router/S99r2o"

# C-исходники хранятся с CRLF; \r после "}" ломает разбор ветви в dash.
# Ветвь оборачивается в case: вне case строка "engine-restart)" не является
# самостоятельным оператором.
{
    printf 'case branch in\n'
    sed -n '/^    engine-restart)/,/^        ;;/p' "$D2O_SERVICE" | tr -d '\r'
    printf 'esac\n'
} >"$TEMP/c-engine-restart.sh"
{
    printf 'case branch in\n'
    sed -n '/^    restart) stop && start ;;/p' "$D2O_SERVICE" | tr -d '\r'
    printf 'esac\n'
} >"$TEMP/c-restart.sh"
{
    printf 'case branch in\n'
    sed -n '/^    engine-restart)/,/^        ;;/p' "$R2O_SERVICE" | tr -d '\r'
    printf 'esac\n'
} >"$TEMP/r-engine-restart.sh"
{
    printf 'case branch in\n'
    sed -n '/^    restart) stop && start ;;/p' "$R2O_SERVICE" | tr -d '\r'
    printf 'esac\n'
} >"$TEMP/r-restart.sh"
grep -F 'MODE=off — запуск запрещён' "$D2O_SERVICE" | tr -d '\r' >"$TEMP/c-start-guard.sh"
grep -F 'MODE=off — R2O остаётся остановленным' "$R2O_SERVICE" | tr -d '\r' >"$TEMP/r-start-guard.sh"
sed -n '/^settings_restart() {/,/^}/p' "$R2O_SERVICE" | tr -d '\r' >"$TEMP/r-settings-restart.sh"

for file in c-engine-restart.sh c-restart.sh r-engine-restart.sh r-restart.sh \
    c-start-guard.sh r-start-guard.sh r-settings-restart.sh; do
    [ -s "$TEMP/$file" ] || {
        printf 'Не найдена ожидаемая ветвь: %s\n' "$file" >&2
        exit 1
    }
done

run_branch() {
    impl=$1
    branch=$2
    mode=$3
    (
        # Ветви обязаны вернуть отказ, не роняя стенд: set -e снят только здесь.
        set +e
        MODE=$mode
        say() { :; }
        die() { echo "die"; exit 1; }
        stop() { echo "stop"; return 0; }
        engine_stop() { echo "engine-stop"; return 0; }
        start_engine() {
            if [ "$impl" = c ]; then
                . "$TEMP/c-start-guard.sh"
            else
                . "$TEMP/r-start-guard.sh"
            fi
            echo "engine-start"
            return 0
        }
        engine_start() { start_engine; }
        start() { echo "start"; start_engine || return $?; }
        telegram_restart() { echo "telegram-restart"; return 0; }
        if [ "$branch" = settings-restart ]; then
            . "$TEMP/r-settings-restart.sh"
            settings_restart
        else
            case "$branch" in
                engine-restart) . "$TEMP/$impl-engine-restart.sh" ;;
                restart) . "$TEMP/$impl-restart.sh" ;;
                start) start ;;
            esac
        fi
        echo "exit=$?"
    )
}

for mode in off observe; do
    for branch in start restart engine-restart; do
        run_branch c "$branch" "$mode" >"$TEMP/c-$branch-$mode.out"
        run_branch r "$branch" "$mode" >"$TEMP/r-$branch-$mode.out"
        if ! diff -u "$TEMP/c-$branch-$mode.out" "$TEMP/r-$branch-$mode.out"; then
            printf 'FAIL: B6 %s MODE=%s\n' "$branch" "$mode" >&2
            exit 1
        fi
    done
done

# settings-restart — R2O-специфичная команда; проверяем её MODE=off-ветвь
# отдельно: остановка движка и перезапуск Telegram, без запуска движка.
run_branch r settings-restart off >"$TEMP/r-settings-off.out"
cat >"$TEMP/want-settings-off.out" <<'EOF'
engine-stop
telegram-restart
exit=0
EOF
if ! diff -u "$TEMP/want-settings-off.out" "$TEMP/r-settings-off.out"; then
    printf 'FAIL: B6 settings-restart MODE=off\n' >&2
    exit 1
fi

printf 'branches=8\n'
cat "$TEMP/c-engine-restart-off.out"
printf 'PASS: C/Rust start/restart/engine-restart MODE=off branches match (D2O %s)\n' "$ACTUAL_D2O_SHA"
