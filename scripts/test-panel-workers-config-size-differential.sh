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
TEMP=$(mktemp -d "$TEMP_BASE/r2o-panel-workers-size.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

printf 'MODE=apply\n' > "$TEMP/config"
head -c 1048577 /dev/zero | tr '\000' '#' >> "$TEMP/config"
printf '\nTG_CF_WORKER_DOMAIN=Old.Example\n' >> "$TEMP/config"
cp "$TEMP/config" "$TEMP/config-write-c"
cp "$TEMP/config" "$TEMP/config-write-rust"

CC=${CC:-cc}
"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/panel" \
    "$ROOT/crates/r2o-panel/tests/d2o_workers_config.c" \
    "$D2O_ROOT/panel/server.c" \
    -o "$TEMP/d2o-panel-workers-config"
"$TEMP/d2o-panel-workers-config" get "$TEMP/config" > "$TEMP/c.trace"
"$TEMP/d2o-panel-workers-config" post "$TEMP/config-write-c" \
    "$TEMP/missing-service" > "$TEMP/c-write.trace"

export HOME=${R2O_TEST_HOME:-$TOOL_HOME/home}
export CARGO_HOME=${R2O_CARGO_HOME:-$TOOL_HOME/cargo-home}
export RUSTUP_HOME=${R2O_RUSTUP_HOME:-$TOOL_HOME/rustup-home}
export CARGO_TARGET_DIR=${R2O_CARGO_TARGET_DIR:-$TOOL_HOME/target-panel-workers-size}
export TMPDIR=$TEMP_BASE
export R2O_PANEL_WORKER_SIZE_CONFIG="$TEMP/config"
export R2O_PANEL_WORKER_SIZE_C_TRACE="$TEMP/c.trace"
export R2O_PANEL_WORKER_SIZE_TRACE_OUTPUT="$TEMP/rust.trace"
CARGO=${CARGO:-cargo}
case ${R2O_PANEL_WORKER_SIZE_CASE:-all} in
    all|read|write) ;;
    *) printf 'Unknown worker size case: %s\n' "$R2O_PANEL_WORKER_SIZE_CASE" >&2; exit 2 ;;
esac
case ${R2O_PANEL_WORKER_SIZE_CASE:-all} in
    all|read)
        "$CARGO" test --locked --offline -p r2o-panel --test http \
            d2o_worker_config_size_limit_matches_rust_route -- --ignored --nocapture
        ;;
esac
case ${R2O_PANEL_WORKER_SIZE_CASE:-all} in
    all|write)
        export R2O_PANEL_WORKER_SIZE_WRITE_CONFIG="$TEMP/config-write-rust"
        export R2O_PANEL_WORKER_SIZE_WRITE_SERVICE="$TEMP/missing-service"
        export R2O_PANEL_WORKER_SIZE_WRITE_C_TRACE="$TEMP/c-write.trace"
        export R2O_PANEL_WORKER_SIZE_WRITE_TRACE_OUTPUT="$TEMP/rust-write.trace"
        "$CARGO" test --locked --offline -p r2o-panel --test http \
            d2o_worker_config_write_size_limit_matches_rust_route -- --ignored --nocapture
        ;;
esac
printf 'test-panel-workers-config-size-differential (%s): D2O and R2O response match\n' "${R2O_PANEL_WORKER_SIZE_CASE:-all}"
