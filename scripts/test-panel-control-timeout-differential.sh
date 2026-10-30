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

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-panel-control-timeout.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
cat > "$TEMP/service" <<'SERVICE'
#!/bin/sh
sleep 5
SERVICE
chmod 700 "$TEMP/service"

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
    -DD2K_PANEL_ACTION_TIMEOUT_MS=40 \
    -I"$D2O_ROOT/panel" \
    "$ROOT/crates/r2o-panel/tests/d2o_control_timeout.c" \
    "$D2O_ROOT/panel/server.c" \
    -o "$TEMP/d2o-panel-timeout"
"$TEMP/d2o-panel-timeout" "$TEMP/service" > "$TEMP/c.trace"

R2O_PANEL_TIMEOUT_SERVICE="$TEMP/service" \
R2O_PANEL_TIMEOUT_C_TRACE="$TEMP/c.trace" \
R2O_PANEL_TIMEOUT_TRACE_OUTPUT="$TEMP/rust.trace" \
    cargo test -p r2o-panel --lib --locked --offline \
        d2o_control_timeout_state_trace -- --ignored --nocapture

printf 'C/Rust panel control timeout state matches d2o %s.\n' "$ACTUAL_D2O_SHA"
