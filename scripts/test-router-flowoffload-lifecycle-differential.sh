#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    echo "unexpected D2O revision" >&2
    exit 2
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-flowoffload-lifecycle.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

sed -n '/^start_engine() {/,/^start_panel() {/p' "$D2O_ROOT/files/S99d2k" |
    sed '$d' | tr -d '\r' > "$TEMP/d2o-start.sh"
sed -n '/^engine_start() {/,/^firewall_heal() {/p' "$ROOT/router/S99r2o" |
    sed '$d' | tr -d '\r' > "$TEMP/r2o-start.sh"
sed -n '/^engine_stop() {/,/^}/p' "$D2O_ROOT/files/S99d2k" |
    tr -d '\r' > "$TEMP/d2o-stop.sh"
sed -n '/^engine_stop() {/,/^}/p' "$ROOT/router/S99r2o" |
    tr -d '\r' > "$TEMP/r2o-stop.sh"

ordered_start() {
    awk '
        /fw_up \|\|/ { fw = NR }
        fw && /fastnat_off/ { fast = NR }
        fast && /flowoffload_off/ { off = NR }
        off && /spawn_daemon/ { controller = NR; exit }
        END { if (!(fw && fast && off && controller && fw < fast && fast < off && off < controller)) exit 1 }
    ' "$TEMP/d2o-start.sh" || {
        echo "D2O startup flow-offload order changed; update the differential contract" >&2
        exit 1
    }
    awk '
        /R2O_IPV6_ENABLED_RUNTIME=.*FIREWALL.* up/ { fw = NR }
        fw && /fastnat_off/ { fast = NR }
        fast && /flowoffload-ensure/ { off = NR }
        off && /spawn_component r2o-controller/ { controller = NR; exit }
        END { if (!(fw && fast && off && controller && fw < fast && fast < off && off < controller)) exit 1 }
    ' "$TEMP/r2o-start.sh" || {
        echo "R2O does not globally disable offload after rules and before controller startup" >&2
        exit 1
    }
}

ordered_stop() {
    awk '
        /fw_down/ { fw = NR }
        fw && /fastnat_restore/ { fast = NR }
        fast && /flowoffload_restore/ { off = NR }
        off && /stop_pidfile.*CT_PID/ { controller = NR; exit }
        END { if (!(fw && fast && off && controller && fw < fast && fast < off && off < controller)) exit 1 }
    ' "$TEMP/d2o-stop.sh" || {
        echo "D2O stop restoration order changed; update the differential contract" >&2
        exit 1
    }
    awk '
        /FIREWALL.*down/ { fw = NR }
        fw && /fastnat_restore/ { fast = NR }
        fast && /flowoffload_restore/ { off = NR }
        off && /stop_component r2o-controller.*CT4_PID/ { controller = NR; exit }
        END { if (!(fw && fast && off && controller && fw < fast && fast < off && off < controller)) exit 1 }
    ' "$TEMP/r2o-stop.sh" || {
        echo "R2O stop does not restore OpenWrt offload after removing datapath rules" >&2
        exit 1
    }
}

ordered_start
ordered_stop

if grep -q 'flowoffload_hook_install' "$ROOT/router/S99r2o"; then
    echo "R2O still installs a fw4 selective-offload reload hook" >&2
    exit 1
fi
if ! grep -q 'flowoffload_hook_remove' "$ROOT/router/S99r2o"; then
    echo "R2O no longer cleans up an include hook left by an older selective-offload build" >&2
    exit 1
fi

echo "D2O/R2O startup and stop order preserves NFQUEUE visibility and restores native offload."
