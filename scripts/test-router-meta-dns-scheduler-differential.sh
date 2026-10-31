#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-$(dirname -- "$ROOT")/d2o}
TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-meta-dns-scheduler.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

grep -Ev '^[[:space:]]*(#|$)' "$D2O_ROOT/files/meta-ranges.txt" | tr -d '\r' > "$TEMP/d2o-ranges"
grep -Ev '^[[:space:]]*(#|$)' "$ROOT/router/files/meta-ranges.txt" | tr -d '\r' > "$TEMP/r2o-ranges"
cmp "$TEMP/d2o-ranges" "$TEMP/r2o-ranges"

d2o_start=$(sed -n '/^start() {/,/^}/p' "$D2O_ROOT/files/S99d2k" | tr -d '\r')
d2o_stop=$(sed -n '/^stop() {/,/^}/p' "$D2O_ROOT/files/S99d2k" | tr -d '\r')
r2o_start=$(sed -n '/^start() {/,/^}/p' "$ROOT/router/S99r2o" | tr -d '\r')
r2o_stop=$(sed -n '/^stop() {/,/^}/p' "$ROOT/router/S99r2o" | tr -d '\r')
r2o_dns_start=$(sed -n '/^meta_dns_scheduler_start() {/,/^}/p' "$ROOT/router/S99r2o" | tr -d '\r')
r2o_dns_stop=$(sed -n '/^meta_dns_scheduler_stop() {/,/^}/p' "$ROOT/router/S99r2o" | tr -d '\r')
r2o_dns_running=$(sed -n '/^meta_dns_scheduler_running() {/,/^}/p' "$ROOT/router/S99r2o" | tr -d '\r')
[ -n "$d2o_start" ] && [ -n "$d2o_stop" ] && [ -n "$r2o_start" ] && [ -n "$r2o_stop" ] \
    && [ -n "$r2o_dns_start" ] && [ -n "$r2o_dns_stop" ] && [ -n "$r2o_dns_running" ] || {
    echo "could not extract D2O/R2O service lifecycle functions" >&2
    exit 2
}

run_start() {
    implementation=$1
    source=$2
    events=$3
    scheduler=$4
    eval "$source"
    if [ "$implementation" = R2O ]; then eval "$r2o_dns_running"; eval "$r2o_dns_start"; fi
    start_engine() { :; }
    engine_start() { :; }
    telegram_start() { :; }
    start_panel() { :; }
    panel_start() { :; }
    update_scheduler_start() { printf '%s:update\n' "$implementation" >> "$events"; }
    running() { return 1; }
    component_running() { return 1; }
    prepare_dirs() { :; }
    spawn_daemon() {
        case " $* " in
            *" $scheduler "*) printf '%s:start\n' "$implementation" >> "$events" ;;
            *" $TEMP/updater "*) printf '%s:update\n' "$implementation" >> "$events" ;;
        esac
        return 0
    }
    spawn_component() {
        case " $* " in *--meta-dns-scheduler*) printf '%s:start\n' "$implementation" >> "$events" ;; esac
        return 0
    }
    if [ "$implementation" = D2O ]; then
        DNS_SCHEDULER=$scheduler DNS_SCHED_PID="$TEMP/d2o.pid" \
            UPDATER="$TEMP/updater" UPD_PID="$TEMP/d2o-update.pid" TG_ENABLED=0 start
    else
        META_DNS_PID="$TEMP/r2o.pid" R2O_META_RANGES="$TEMP/meta-ranges.txt" \
            UPDATER="$TEMP/updater" R2O_INSTAGRAM_SCHED_ATTEMPT="$TEMP/attempt" \
            TG_ENABLED=0 MODE=observe LOG="$TEMP/log" TG_STATUS="$TEMP/tg.status" start
    fi
}

run_stop() {
    implementation=$1
    source=$2
    events=$3
    scheduler_pid=$4
    eval "$source"
    if [ "$implementation" = R2O ]; then eval "$r2o_dns_running"; eval "$r2o_dns_stop"; fi
    stop_pidfile() {
        case "$1" in
            "$scheduler_pid") printf '%s:stop\n' "$implementation" >> "$events" ;;
            "$TEMP/d2o-update.pid") printf '%s:update-stop\n' "$implementation" >> "$events" ;;
        esac
        return 0
    }
    stop_component() {
        [ "$2" != "$scheduler_pid" ] || printf '%s:stop\n' "$implementation" >> "$events"
        return 0
    }
    update_scheduler_stop() { printf '%s:update-stop\n' "$implementation" >> "$events"; }
    telegram_stop() { :; }
    engine_stop() { :; }
    panel_stop() { :; }
    log_maintenance_stop() { :; }
    rst_rules_down() { :; }
    firewall_down() { :; }
    say() { :; }
    if [ "$implementation" = D2O ]; then
        DNS_SCHED_PID=$scheduler_pid UPD_PID="$TEMP/d2o-update.pid" \
            PN_PID="$TEMP/no-panel.pid" LM_PID="$TEMP/no-log.pid" LIVE="$TEMP/live" stop
    else
        META_DNS_PID=$scheduler_pid FIREWALL="$TEMP/firewall" stop
    fi
}

mkdir -p "$TEMP/bin"
printf '#!/bin/sh\nexit 0\n' > "$TEMP/bin/ndmc"
chmod 0755 "$TEMP/bin/ndmc"
printf '#!/bin/sh\nexit 0\n' > "$TEMP/firewall"
chmod 0755 "$TEMP/firewall"
printf '#!/bin/sh\nexit 0\n' > "$TEMP/d2o-dns-scheduler"
printf '#!/bin/sh\nexit 0\n' > "$TEMP/r2o-dns-scheduler"
chmod 0755 "$TEMP/d2o-dns-scheduler" "$TEMP/r2o-dns-scheduler"
printf '#!/bin/sh\nexit 0\n' > "$TEMP/updater"
chmod 0755 "$TEMP/updater"
export PATH="$TEMP/bin:$PATH"
printf '%s\n' fixture > "$TEMP/meta-ranges.txt"

run_start D2O "$d2o_start" "$TEMP/events" "$TEMP/d2o-dns-scheduler"
run_start R2O "$r2o_start" "$TEMP/events" "$TEMP/r2o-dns-scheduler"

expected_start=$(printf 'D2O:start\nD2O:update\nR2O:start\nR2O:update')
actual_start=$(cat "$TEMP/events" 2>/dev/null || true)
[ "$actual_start" = "$expected_start" ] || {
    printf 'DNS scheduler start mismatch\nexpected:\n%s\nactual:\n%s\n' \
        "$expected_start" "$actual_start" >&2
    exit 1
}

run_stop D2O "$d2o_stop" "$TEMP/events" "$TEMP/d2o.pid"
run_stop R2O "$r2o_stop" "$TEMP/events" "$TEMP/r2o.pid"
expected=$(printf 'D2O:start\nD2O:update\nR2O:start\nR2O:update\nD2O:stop\nD2O:update-stop\nR2O:stop\nR2O:update-stop')
actual=$(cat "$TEMP/events")
[ "$actual" = "$expected" ] || {
    printf 'DNS scheduler lifecycle mismatch\nexpected:\n%s\nactual:\n%s\n' \
        "$expected" "$actual" >&2
    exit 1
}

run_r2o_gate() {
    gate_path=$1
    gate_asset=$2
    events=$3
    eval "$r2o_dns_running"
    eval "$r2o_dns_start"
    component_running() { return 1; }
    spawn_component() { printf '%s\n' "$*" >> "$events"; }
    say() { :; }
    META_DNS_PID="$TEMP/gate.pid" LOG="$TEMP/log" R2O_META_RANGES="$gate_asset" \
        PATH="$gate_path" meta_dns_scheduler_start
}
mkdir -p "$TEMP/no-ndmc"
run_r2o_gate "$TEMP/no-ndmc" "$TEMP/meta-ranges.txt" "$TEMP/gates"
run_r2o_gate "$TEMP/bin" "$TEMP/missing-meta-ranges.txt" "$TEMP/gates"
[ ! -s "$TEMP/gates" ] || { echo "Meta DNS scheduler ignored its NDM/data prerequisites" >&2; exit 1; }

echo "D2O/R2O Meta DNS scheduler start/stop lifecycle matches"
