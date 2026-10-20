#!/bin/sh
set -eu

r2o_timer_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_timer_state="$r2o_timer_root/.rea"
r2o_timer_log="$r2o_timer_state/r2o-метрики-итераций.tsv"

r2o_timer_validate_id() {
    case $1 in
        ''|*[!a-z0-9-]*)
            printf 'Неверный идентификатор сценария: %s\n' "$1" >&2
            exit 2
            ;;
    esac
}

case ${1:-} in
    начать|закончить)
        [ "$#" -eq 3 ] || {
            printf 'Использование: %s начать|закончить <сценарий> <анализ|реализация>\n' "$0" >&2
            exit 2
        }
        r2o_timer_action=$1
        r2o_timer_scenario=$2
        r2o_timer_phase=$3
        r2o_timer_validate_id "$r2o_timer_scenario"
        case $r2o_timer_phase in
            анализ|реализация) ;;
            *)
                printf 'Неизвестный этап: %s\n' "$r2o_timer_phase" >&2
                exit 2
                ;;
        esac
        mkdir -p "$r2o_timer_state"
        r2o_timer_marker="$r2o_timer_state/.r2o-таймер-$r2o_timer_scenario-$r2o_timer_phase"
        if [ "$r2o_timer_action" = начать ]; then
            [ ! -e "$r2o_timer_marker" ] || {
                printf 'Этап уже запущен: %s / %s\n' "$r2o_timer_scenario" "$r2o_timer_phase" >&2
                exit 1
            }
            date +%s >"$r2o_timer_marker"
            printf 'Начат этап «%s» сценария %s\n' "$r2o_timer_phase" "$r2o_timer_scenario"
        else
            [ -f "$r2o_timer_marker" ] || {
                printf 'Этап не был запущен: %s / %s\n' "$r2o_timer_scenario" "$r2o_timer_phase" >&2
                exit 1
            }
            r2o_timer_started=$(cat "$r2o_timer_marker")
            r2o_timer_finished=$(date +%s)
            r2o_timer_elapsed=$((r2o_timer_finished - r2o_timer_started))
            rm "$r2o_timer_marker"
            if [ ! -f "$r2o_timer_log" ]; then
                printf 'сценарий\tэтап\tсекунды\tзавершено_UTC\n' >"$r2o_timer_log"
            fi
            printf '%s\t%s\t%s\t%s\n' "$r2o_timer_scenario" "$r2o_timer_phase" \
                "$r2o_timer_elapsed" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >>"$r2o_timer_log"
            printf 'Этап «%s» сценария %s: %s с\n' \
                "$r2o_timer_phase" "$r2o_timer_scenario" "$r2o_timer_elapsed"
        fi
        ;;
    закрыть)
        [ "$#" -eq 3 ] || {
            printf 'Использование: %s закрыть <сценарий> <число_закрытых_сценариев>\n' "$0" >&2
            exit 2
        }
        r2o_timer_scenario=$2
        r2o_timer_count=$3
        r2o_timer_validate_id "$r2o_timer_scenario"
        case $r2o_timer_count in
            ''|*[!0-9]*)
                printf 'Число сценариев должно быть неотрицательным целым\n' >&2
                exit 2
                ;;
        esac
        mkdir -p "$r2o_timer_state"
        if [ ! -f "$r2o_timer_log" ]; then
            printf 'сценарий\tэтап\tсекунды\tзавершено_UTC\n' >"$r2o_timer_log"
        fi
        printf '%s\tзакрытые_сценарии\t%s\t%s\n' \
            "$r2o_timer_scenario" "$r2o_timer_count" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >>"$r2o_timer_log"
        printf 'Для сценария %s записано закрытых сценариев: %s\n' "$r2o_timer_scenario" "$r2o_timer_count"
        ;;
    *)
        printf 'Использование: %s начать|закончить|закрыть ...\n' "$0" >&2
        exit 2
        ;;
esac
