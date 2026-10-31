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

TOOL_HOME=${R2O_TOOL_HOME:-${ROOT%/*}/r2o-tooling}
TEMP_BASE=${R2O_TEST_TMP:-$TOOL_HOME/tmp}
[ -d "$TEMP_BASE" ] || { printf 'Temporary directory must exist on E: %s\n' "$TEMP_BASE" >&2; exit 2; }
TEMP=$(mktemp -d "$TEMP_BASE/r2o-panel-live-size.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

printf '{"linked":false,"catalog_at":"live","boxes":[],"searches":[],"padding":"' > "$TEMP/live.json"
head -c 1048577 /dev/zero | tr '\000' 'x' >> "$TEMP/live.json"
printf '"}\n' >> "$TEMP/live.json"

CC=${CC:-cc}
"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-status" \
    "$ROOT/crates/r2o-panel/tests/d2o_status_unavailable.c"
"$TEMP/d2o-status" "$TEMP/live.json" > "$TEMP/c.json"

export HOME=${R2O_TEST_HOME:-$TOOL_HOME/home}
export CARGO_HOME=${R2O_CARGO_HOME:-$TOOL_HOME/cargo-home}
export RUSTUP_HOME=${R2O_RUSTUP_HOME:-$TOOL_HOME/rustup-home}
export CARGO_TARGET_DIR=${R2O_CARGO_TARGET_DIR:-$TOOL_HOME/target-panel-live-size}
export TMPDIR=$TEMP_BASE
export R2O_PANEL_LIVE_SIZE_PATH="$TEMP/live.json"
export R2O_PANEL_LIVE_SIZE_C_BODY="$TEMP/c.json"
export R2O_PANEL_LIVE_SIZE_TRACE_OUTPUT="$TEMP/rust.trace"

CARGO=${CARGO:-cargo}
"$CARGO" test --locked --offline -p r2o-panel --test http \
    d2o_status_live_file_size_limit_matches_rust_route -- --ignored --nocapture
printf 'test-panel-live-status-size-differential: D2O and R2O catalog_at match\n'
