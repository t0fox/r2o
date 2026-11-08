#!/bin/sh
# shellcheck disable=SC1090,SC2034
# B48 C-side trace: offset/backoff/run_at/tick из D2O scheduler.
set -eu

D2O_ROOT=${1:?D2O root}
TEMP=${2:?temp dir}
SCHEDULER="$D2O_ROOT/files/d2k-instagram-dns-scheduler.sh"
FUNCS="$TEMP/c-scheduler-functions.sh"
: >"$FUNCS"
for function in log random16 store_offset refresh_offset run_at backoff_after \
    write_attempt tick; do
    sed -n "/^$function() {/,/^}/p" "$SCHEDULER" | tr -d '\r' >>"$FUNCS"
done
[ -s "$FUNCS" ] || {
    echo "C scheduler functions not found" >&2
    exit 2
}
. "$FUNCS"

DIR="$TEMP/d2o-dir"
mkdir -p "$DIR/state" "$DIR/log"
HELPER="$TEMP/helper"
STATE="$DIR/state/success"
ATTEMPT="$DIR/state/attempt"
LOG="$DIR/log/scheduler.log"
OFFSET_FILE="$DIR/state/offset"
RETRY_AFTER=1800
MAX_BACKOFF=86400
RUN_AT=
RUN_EVERY=60
child_pid=

classify_offset() {
    case "$1" in
        'v2 '[0-9]|'v2 '[1-9][0-9]|'v2 1'[0-9][0-9]|'v2 2'[0-3][0-9]) echo stored ;;
        [0-9]|[1-5][0-9]|0[0-9]) echo migrated ;;
        *) echo regenerated ;;
    esac
}

offset_case() {
    name=$1
    content=$2
    printf '%s' "$content" >"$OFFSET_FILE"
    stored=$(cat "$OFFSET_FILE" 2>/dev/null || true)
    kind=$(classify_offset "$stored")
    value=$(refresh_offset)
    case "$kind" in
        stored) printf 'offset %s stored value=%s\n' "$name" "$value" ;;
        *) printf 'offset %s %s\n' "$name" "$kind" ;;
    esac
}

offset_case v2-0 'v2 0'
offset_case v2-9 'v2 9'
offset_case v2-10 'v2 10'
offset_case v2-99 'v2 99'
offset_case v2-100 'v2 100'
offset_case v2-199 'v2 199'
offset_case v2-200 'v2 200'
offset_case v2-239 'v2 239'
offset_case v2-240 'v2 240'
offset_case v2-007 'v2 007'
offset_case v2-07 'v2 07'
offset_case v2-00 'v2 00'
offset_case v2-plus 'v2 +5'
offset_case v2-space 'v2 5 '
offset_case bare-0 '0'
offset_case bare-9 '9'
offset_case bare-00 '00'
offset_case bare-09 '09'
offset_case bare-10 '10'
offset_case bare-59 '59'
offset_case bare-60 '60'
offset_case bare-007 '007'
offset_case bare-plus '+5'
offset_case bare-space ' 5'
offset_case junk 'junk'
offset_case empty ''

for retry in 60 1800 86400; do
    RETRY_AFTER=$retry
    for failures in 0 1 2 3 4 5 6 7 8 9 10 11 12; do
        printf 'backoff retry=%s failures=%s secs=%s\n' \
            "$retry" "$failures" "$(backoff_after "$failures")"
    done
done

for offset in 0 1 59 60 120 239; do
    printf 'v2 %s\n' "$offset" >"$OFFSET_FILE"
    RUN_AT=
    printf 'run_at explicit=none offset=%s value=%s\n' "$offset" "$(run_at)"
done
RUN_AT=0345
printf 'run_at explicit=0345 offset=10 value=%s\n' "$(run_at)"
RUN_AT=

date() {
    case "$1" in
        +%Y-%m-%d) printf '%s\n' "$CASE_DAY" ;;
        +%H%M) printf '%s\n' "$CASE_HHMM" ;;
        +%s) printf '%s\n' "$CASE_EPOCH" ;;
        *) printf '2026-11-08 00:00:00\n' ;;
    esac
}

tick_case() {
    name=$1
    day=$2
    hhmm=$3
    epoch=$4
    state_day=$5
    attempt=$6
    case_dir="$TEMP/tick-$name"
    rm -rf "$case_dir"
    mkdir -p "$case_dir"
    STATE="$case_dir/state"
    ATTEMPT="$case_dir/attempt"
    LOG="$case_dir/log"
    HELPER="$case_dir/helper"
    RUN_AT=0100
    RETRY_AFTER=1800
    if [ "$state_day" = none ]; then
        rm -f "$STATE"
    else
        printf '%s\n0\n' "$state_day" >"$STATE"
    fi
    if [ "$attempt" = none ]; then
        rm -f "$ATTEMPT"
    else
        printf '%s\n' "$attempt" >"$ATTEMPT"
    fi
    printf '#!/bin/sh\ntouch "%s"\n' "$case_dir/ran" >"$HELPER"
    chmod 0755 "$HELPER"
    CASE_DAY=$day
    CASE_HHMM=$hhmm
    CASE_EPOCH=$epoch
    child_pid=
    tick
    if [ -e "$case_dir/ran" ]; then
        printf 'tick %s run=1\n' "$name"
    else
        printf 'tick %s run=0\n' "$name"
    fi
}

tick_case first-install 2026-11-08 0000 1000 none none
tick_case backoff-wait 2026-11-08 0000 1000 none '0 2026-11-07 1'
tick_case backoff-elapsed 2026-11-08 0000 2000 none '0 2026-11-07 1'
tick_case before-slot 2026-11-08 0059 1000 2026-11-07 none
tick_case at-slot 2026-11-08 0100 1000 2026-11-07 none
tick_case already-today 2026-11-08 0100 1000 2026-11-08 none
tick_case today-fail-wait 2026-11-08 0100 2000 2026-11-07 '1000 2026-11-08 1'
tick_case today-fail-elapsed 2026-11-08 0100 2000 2026-11-07 '0 2026-11-08 1'
tick_case yesterday-attempt 2026-11-08 0100 2000 2026-11-07 '1000 2026-11-07 1'
tick_case future-attempt 2026-11-08 0000 1000 none '5000 2026-11-07 0'
