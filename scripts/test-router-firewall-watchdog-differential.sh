#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
[ "$ACTUAL_D2O_SHA" = "$EXPECTED_D2O_SHA" ] || {
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-firewall-watchdog.XXXXXX")
d2o_worker=
r2o_worker=
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    for worker in "$d2o_worker" "$r2o_worker"; do
        [ -z "$worker" ] || { kill -TERM "$worker" 2>/dev/null || true; wait "$worker" 2>/dev/null || true; }
    done
    rm -rf "$TEMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

sed 's/\r$//' "$D2O_ROOT/files/S99d2k" > "$TEMP/d2o-S99d2k"
{
    printf '#!/bin/sh\nHEAL=%s\nHEAL_EVERY=1\nTRACE=%s\nexport HEAL HEAL_EVERY TRACE\n' \
        "'${TEMP}/d2o-heal'" "'${TEMP}/d2o.trace'"
    awk '/WATCHLOOP="/ { copy=1 } copy { print } copy && /done"/ { exit }' "$TEMP/d2o-S99d2k"
    printf 'exec sh -c "$WATCHLOOP"\n'
} > "$TEMP/d2o-watchdog"
[ -s "$TEMP/d2o-watchdog" ] || { echo "не извлечён периодический D2O watchdog" >&2; exit 1; }

cat > "$TEMP/d2o-heal" <<'HEAL'
#!/bin/sh
printf 'heal\n' >> "$TRACE"
HEAL
cat > "$TEMP/r2o-init" <<'INIT'
#!/bin/sh
[ "${1:-}" = firewall-heal ] || exit 2
printf 'firewall-heal\n' >> "$TRACE"
INIT
chmod 0700 "$TEMP/d2o-heal" "$TEMP/r2o-init"

chmod 0700 "$TEMP/d2o-watchdog"
sh "$TEMP/d2o-watchdog" >/dev/null 2>&1 &
d2o_worker=$!

wait_for_two_ticks() {
    trace=$1
    attempt=0
    while [ "$(cat "$trace" 2>/dev/null | wc -l)" -lt 2 ]; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 40 ] || return 1
        sleep 0.1
    done
}

wait_for_two_ticks "$TEMP/d2o.trace" || { echo "D2O watchdog не сделал периодический вызов" >&2; exit 1; }
kill -TERM "$d2o_worker" 2>/dev/null || true
wait "$d2o_worker" 2>/dev/null || true
d2o_worker=

WATCHDOG=$ROOT/router/r2o-firewall-watchdog.sh
[ -x "$WATCHDOG" ] || {
    echo "D2O сделал периодические вызовы, но R2O worker отсутствует или неисполняемый" >&2
    exit 1
}
HEAL_EVERY=1 TRACE=$TEMP/r2o.trace R2O_INIT=$TEMP/r2o-init \
    sh "$WATCHDOG" run >/dev/null 2>&1 &
r2o_worker=$!
wait_for_two_ticks "$TEMP/r2o.trace" || { echo "R2O watchdog не сделал периодический вызов" >&2; exit 1; }
kill -TERM "$r2o_worker" 2>/dev/null || true
wait "$r2o_worker" 2>/dev/null || true
r2o_worker=

sed -n '/^firewall_watchdog_running() {/,/^}/p; /^firewall_watchdog_start() {/,/^}/p; /^firewall_watchdog_stop() {/,/^}/p' \
    "$ROOT/router/S99r2o" | sed 's/^firewall_watchdog_stop()/r2o_firewall_watchdog_stop()/' > "$TEMP/r2o-watchdog-functions.sh"
sed -n '/^engine_stop() {/,/^}/p' "$ROOT/router/S99r2o" > "$TEMP/r2o-engine-stop.sh"
sed 's/\r$//' "$D2O_ROOT/files/S99d2k" > "$TEMP/d2o-S99d2k"
sed -n '/^engine_stop() {/,/^}/p' "$TEMP/d2o-S99d2k" > "$TEMP/d2o-engine-stop.sh"
cat > "$TEMP/start-stop-daemon" <<'SSD'
#!/bin/sh
pidfile=
program=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -p) pidfile=$2; shift 2 ;;
        -x) program=$2; shift 2 ;;
        --) shift; break ;;
        *) shift ;;
    esac
done
"$program" "$@" >/dev/null 2>&1 &
child=$!
printf '%s\n' "$child" > "$pidfile"
mkdir -p "$PROC/$child"
printf '%s\000run\000' "$program" > "$PROC/$child/cmdline"
SSD
cat > "$TEMP/firewall" <<'FIREWALL'
#!/bin/sh
printf 'firewall-%s\n' "$1" >> "$EVENTS"
FIREWALL
cat > "$TEMP/r2o-lifecycle" <<'LIFECYCLE'
#!/bin/sh
set -eu
RUN=$TEST_RUN
PROC=$TEST_PROC
FW_WATCHDOG=$TEST_WATCHDOG
FW_WD_PID=$RUN/r2o-firewall-watchdog.pid
FIREWALL=$TEST_FIREWALL
EVENTS=$TEST_EVENTS
CT4_PID=$RUN/controller4.pid
CT6_PID=$RUN/controller6.pid
DP4_PID=$RUN/datapath4.pid
DP6_PID=$RUN/datapath6.pid
SOCK4=$RUN/datapath4.sock
SOCK6=$RUN/datapath6.sock
export RUN PROC FW_WATCHDOG FW_WD_PID FIREWALL EVENTS CT4_PID CT6_PID DP4_PID DP6_PID SOCK4 SOCK6
prepare_dirs() { mkdir -p "$RUN"; }
say() { :; }
ppe_remove() { :; }
stop_component() { :; }
. "$TEST_FUNCTIONS"
firewall_watchdog_stop() {
    r2o_firewall_watchdog_stop
    printf 'watchdog-stopped\n' >> "$EVENTS"
}
. "$TEST_ENGINE_STOP"
firewall_watchdog_start
first_pid=$(cat "$FW_WD_PID")
firewall_watchdog_running
firewall_watchdog_start
[ "$(cat "$FW_WD_PID")" = "$first_pid" ] || { echo "повторный старт породил второй watchdog" >&2; exit 1; }
engine_stop
[ ! -e "$FW_WD_PID" ] || { echo "остановка оставила PID watchdog" >&2; exit 1; }
if kill -0 "$first_pid" 2>/dev/null; then
    echo "остановка оставила периодический worker запущенным" >&2
    exit 1
fi
LIFECYCLE
chmod 0700 "$TEMP/start-stop-daemon" "$TEMP/firewall" "$TEMP/r2o-lifecycle"
mkdir -p "$TEMP/fake-proc"
TEST_EVENTS=$TEMP/r2o-stop.events
TEST_RUN=$TEMP/r2o-run
TEST_PROC=$TEMP/fake-proc
TEST_WATCHDOG=$WATCHDOG
TEST_FIREWALL=$TEMP/firewall
TEST_FUNCTIONS=$TEMP/r2o-watchdog-functions.sh
TEST_ENGINE_STOP=$TEMP/r2o-engine-stop.sh
: > "$TEST_EVENTS"
export TEST_EVENTS TEST_RUN TEST_PROC TEST_WATCHDOG TEST_FIREWALL TEST_FUNCTIONS TEST_ENGINE_STOP
PATH="$TEMP:$PATH" R2O_INIT="$TEMP/r2o-init" HEAL_EVERY=1 TRACE="$TEMP/lifecycle.trace" \
    sh "$TEMP/r2o-lifecycle"

cat > "$TEMP/d2o-stop-lifecycle" <<'D2OSTOP'
#!/bin/sh
HL_PID=heal.pid
CT_PID=controller.pid
DP_PID=datapath.pid
SOCK=datapath.sock
EVENTS=$1
export EVENTS
stop_pidfile() { printf 'watchdog-stopped\n' >> "$EVENTS"; }
fw_down() { printf 'firewall-down\n' >> "$EVENTS"; }
legacy_http_stop() { :; }
fastnat_restore() { :; }
flowoffload_restore() { :; }
rst_rules_down() { :; }
say() { :; }
D2OSTOP
cat "$TEMP/d2o-engine-stop.sh" >> "$TEMP/d2o-stop-lifecycle"
cat >> "$TEMP/d2o-stop-lifecycle" <<'D2OSTOP'
engine_stop
D2OSTOP
chmod 0700 "$TEMP/d2o-stop-lifecycle"
sh "$TEMP/d2o-stop-lifecycle" "$TEMP/d2o-stop.events"
head -n 2 "$TEMP/d2o-stop.events" > "$TEMP/d2o-stop-order"
head -n 2 "$TEMP/r2o-stop.events" > "$TEMP/r2o-stop-order"
cmp "$TEMP/d2o-stop-order" "$TEMP/r2o-stop-order" || {
    echo "порядок watchdog/firewall stop отличается" >&2
    cat "$TEMP/d2o-stop-order" "$TEMP/r2o-stop-order" >&2
    exit 1
}

grep -q 'firewall_watchdog_start' "$ROOT/router/S99r2o" || { echo "S99r2o не запускает firewall watchdog" >&2; exit 1; }
grep -q 'firewall_watchdog_running' "$ROOT/router/S99r2o" || { echo "S99r2o не проверяет watchdog при старте" >&2; exit 1; }
grep -q 'firewall_watchdog_stop' "$ROOT/router/S99r2o" || { echo "S99r2o не останавливает watchdog" >&2; exit 1; }
grep -q 'сторож правил:' "$ROOT/router/S99r2o" || { echo "S99r2o не показывает состояние watchdog" >&2; exit 1; }
grep -q 'r2o-firewall-watchdog.sh' "$ROOT/scripts/package-release.sh" || { echo "watchdog не включён в release manifest" >&2; exit 1; }

printf 'D2O/R2O periodic firewall watchdog executes, stops, and is wired into service lifecycle (%s).\n' "$ACTUAL_D2O_SHA"
