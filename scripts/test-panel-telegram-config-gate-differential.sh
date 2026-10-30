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

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-panel-tg-config.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
cat > "$TEMP/config" <<'CONFIG'
TG_ENABLED=0
TG_MODE=local
UNRELATED="unterminated
CONFIG
cat > "$TEMP/service" <<'SERVICE'
#!/bin/sh
exit 0
SERVICE
chmod 700 "$TEMP/service"

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
    -I"$D2O_ROOT/panel" \
    "$ROOT/crates/r2o-panel/tests/d2o_telegram_config_gate.c" \
    "$D2O_ROOT/panel/server.c" -o "$TEMP/d2o-panel-config-gate"
"$TEMP/d2o-panel-config-gate" "$TEMP/config" "$TEMP/service" > "$TEMP/c.trace"

if R2O_PANEL_TG_CONFIG_PATH="$TEMP/config" \
    R2O_PANEL_TG_CONFIG_SERVICE="$TEMP/service" \
    R2O_PANEL_TG_CONFIG_C_TRACE="$TEMP/c.trace" \
    R2O_PANEL_TG_CONFIG_TRACE_OUTPUT="$TEMP/rust.trace" \
    cargo test -p r2o-panel --test http --locked --offline \
        d2o_telegram_config_gate_trace -- --ignored --nocapture; then
    RUST_STATUS=0
else
    RUST_STATUS=$?
fi
[ -f "$TEMP/rust.trace" ] || {
    printf 'Rust panel config gate test produced no trace.\n' >&2
    exit "$RUST_STATUS"
}
[ "$RUST_STATUS" -eq 0 ] || exit "$RUST_STATUS"
printf 'C/Rust Telegram config gate matches d2o %s.\n' "$ACTUAL_D2O_SHA"
