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

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-panel-workers-config-write.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
printf 'MODE=apply\n# invalid byte: \377\nTG_CF_WORKER_DOMAIN=old.example\n' > "$TEMP/config-c"
cp "$TEMP/config-c" "$TEMP/config-rust"
cat > "$TEMP/service" <<'SERVICE'
#!/bin/sh
exit 0
SERVICE
chmod 700 "$TEMP/service"

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/panel" \
    "$ROOT/crates/r2o-panel/tests/d2o_workers_config.c" \
    "$D2O_ROOT/panel/server.c" \
    -o "$TEMP/d2o-panel-workers-config"
"$TEMP/d2o-panel-workers-config" post-ascii "$TEMP/config-c" "$TEMP/service" > "$TEMP/c.trace"

R2O_PANEL_WORKER_SERVICE="$TEMP/service" \
R2O_PANEL_WORKER_CONFIG="$TEMP/config-rust" \
R2O_PANEL_WORKER_C_TRACE="$TEMP/c.trace" \
R2O_PANEL_WORKER_TRACE_OUTPUT="$TEMP/rust.trace" \
    cargo test -p r2o-panel --test http --locked --offline \
        d2o_worker_config_write_preserves_non_utf8_comments -- --ignored --nocapture

printf 'C/Rust panel Workers config write matches d2o %s.\n' "$ACTUAL_D2O_SHA"
