#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-firewall-rst-down.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/bin" "$TEMP/d2o-state" "$TEMP/r2o-state" "$TEMP/d2k/run" "$TEMP/r2o/run"
: >"$TEMP/d2o-state/d2k"
: >"$TEMP/d2o-state/d2k_rst"
: >"$TEMP/r2o-state/r2o"
: >"$TEMP/r2o-state/r2o_rst"
printf 'FW_BACKEND=nft\n' >"$TEMP/d2k/config"
printf 'FW_BACKEND=nft\nIPV6_ENABLED=0\n' >"$TEMP/r2o/config"

cat >"$TEMP/bin/nft" <<'NFT'
#!/bin/sh
printf '%s\n' "$*" >>"$NFT_TRACE"
if [ "${1:-}" = list ] && [ "${2:-}" = table ]; then
    table=$4
    if [ -f "$NFT_STATE_DIR/$table" ]; then
        echo "table inet $table { comment \"r2o-managed\"; }"
        exit 0
    fi
    exit 1
fi
if [ "${1:-}" = delete ] && [ "${2:-}" = table ]; then rm -f "$NFT_STATE_DIR/$4"; fi
exit 0
NFT
chmod 0755 "$TEMP/bin/nft"

tr -d '\r' <"$D2O_ROOT/files/S99d2k" |
    awk '$0 == "case \"$1\" in" { exit } { print }' >"$TEMP/d2k-functions.sh"
cat >"$TEMP/run-d2o.sh" <<'D2O'
#!/bin/sh
set -eu
D2K_DIR=$1
FW_LOCK=$D2K_DIR/run/firewall-operation.lock
export D2K_DIR FW_LOCK
. "$2"
PATH=$3:$PATH
NFT_STATE_DIR=$4
NFT_TRACE=$5
export PATH NFT_STATE_DIR NFT_TRACE
say() { :; }
if fw_down; then echo DOWN:success; else echo DOWN:failed; fi
if [ -f "$NFT_STATE_DIR/d2k" ]; then echo MAIN_TABLE:present; else echo MAIN_TABLE:absent; fi
if [ -f "$NFT_STATE_DIR/d2k_rst" ]; then echo RST_AFTER_DOWN:present; else echo RST_AFTER_DOWN:absent; fi
if rst_rules_down all; then echo STOP_RST:success; else echo STOP_RST:failed; fi
if [ -f "$NFT_STATE_DIR/d2k_rst" ]; then echo RST_AFTER_STOP:present; else echo RST_AFTER_STOP:absent; fi
D2O
chmod 0755 "$TEMP/run-d2o.sh"

if NFT_STATE_DIR="$TEMP/d2o-state" NFT_TRACE="$TEMP/d2o.trace" \
    "$TEMP/run-d2o.sh" "$TEMP/d2k" "$TEMP/d2k-functions.sh" "$TEMP/bin" \
    "$TEMP/d2o-state" "$TEMP/d2o.trace" >"$TEMP/d2o.out"; then :; else exit 1; fi
if R2O_DIR="$TEMP/r2o" R2O_CONFIG="$TEMP/r2o/config" \
    R2O_RUN_DIR="$TEMP/r2o/run" R2O_PROC_DIR="$TEMP/proc" \
    R2O_SYS_MODULE_DIR="$TEMP/sys" R2O_MODULES_DIR="$TEMP/modules" \
    NFT_STATE_DIR="$TEMP/r2o-state" NFT_TRACE="$TEMP/r2o.trace" \
    PATH="$TEMP/bin:$PATH" sh "$ROOT/router/r2o-firewall.sh" down >"$TEMP/r2o.log" 2>&1; then
    echo DOWN:success >"$TEMP/r2o.out"
else
    echo DOWN:failed >"$TEMP/r2o.out"
fi
if [ -f "$TEMP/r2o-state/r2o" ]; then echo MAIN_TABLE:present >>"$TEMP/r2o.out"; else echo MAIN_TABLE:absent >>"$TEMP/r2o.out"; fi
if [ -f "$TEMP/r2o-state/r2o_rst" ]; then echo RST_AFTER_DOWN:present >>"$TEMP/r2o.out"; else echo RST_AFTER_DOWN:absent >>"$TEMP/r2o.out"; fi
if R2O_DIR="$TEMP/r2o" R2O_CONFIG="$TEMP/r2o/config" \
    R2O_RUN_DIR="$TEMP/r2o/run" R2O_PROC_DIR="$TEMP/proc" \
    R2O_SYS_MODULE_DIR="$TEMP/sys" R2O_MODULES_DIR="$TEMP/modules" \
    NFT_STATE_DIR="$TEMP/r2o-state" NFT_TRACE="$TEMP/r2o.trace" \
    PATH="$TEMP/bin:$PATH" sh "$ROOT/router/r2o-firewall.sh" rst-down >>"$TEMP/r2o.log" 2>&1; then
    echo STOP_RST:success >>"$TEMP/r2o.out"
else
    echo STOP_RST:failed >>"$TEMP/r2o.out"
fi
if [ -f "$TEMP/r2o-state/r2o_rst" ]; then echo RST_AFTER_STOP:present >>"$TEMP/r2o.out"; else echo RST_AFTER_STOP:absent >>"$TEMP/r2o.out"; fi
cat "$TEMP/d2o.out" "$TEMP/r2o.out"
cmp "$TEMP/d2o.out" "$TEMP/r2o.out"

sed 's/\r$//' "$D2O_ROOT/files/S99d2k" |
    sed -n '/^stop() {/,/^}/p' >"$TEMP/d2o-stop.sh"
sed -n '/^stop() {/,/^}/p' "$ROOT/router/S99r2o" >"$TEMP/r2o-stop.sh"
cat >"$TEMP/r2o-firewall" <<'FIREWALL'
#!/bin/sh
[ "${1:-}" = rst-down ] || exit 2
printf 'rst-all\n' >>"$EVENTS"
FIREWALL
cat >"$TEMP/run-d2o-stop.sh" <<'D2OSTOP'
#!/bin/sh
set -eu
EVENTS=$1
LIVE=$2
DNS_SCHED_PID=
UPD_PID=
PN_PID=
LM_PID=
export EVENTS LIVE DNS_SCHED_PID UPD_PID PN_PID LM_PID
stop_pidfile() { :; }
telegram_stop() { :; }
engine_stop() { printf 'engine-stop\n' >>"$EVENTS"; }
rst_rules_down() { printf 'rst-%s\n' "$1" >>"$EVENTS"; }
say() { :; }
. "$3"
stop
D2OSTOP
cat >"$TEMP/run-r2o-stop.sh" <<'R2OSTOP'
#!/bin/sh
set -eu
EVENTS=$1
FIREWALL=$2
export EVENTS FIREWALL
update_scheduler_stop() { :; }
telegram_stop() { :; }
engine_stop() { printf 'engine-stop\n' >>"$EVENTS"; }
panel_stop() { :; }
log_maintenance_stop() { :; }
say() { :; }
. "$3"
stop
R2OSTOP
chmod 0755 "$TEMP/r2o-firewall" "$TEMP/run-d2o-stop.sh" "$TEMP/run-r2o-stop.sh"
"$TEMP/run-d2o-stop.sh" "$TEMP/d2o-stop.events" "$TEMP/live" "$TEMP/d2o-stop.sh"
EVENTS="$TEMP/r2o-stop.events" "$TEMP/run-r2o-stop.sh" \
    "$TEMP/r2o-stop.events" "$TEMP/r2o-firewall" "$TEMP/r2o-stop.sh"
cmp "$TEMP/d2o-stop.events" "$TEMP/r2o-stop.events"
printf 'D2O %s and R2O agree on RST-table lifetime during down and full stop cleanup.\n' \
    "$ACTUAL_D2O_SHA"
