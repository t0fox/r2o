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
TEMP=$(mktemp -d "$TEMP_BASE/r2o-panel-header-limit.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

export HOME=${R2O_TEST_HOME:-$TOOL_HOME/home}
export CARGO_HOME=${R2O_CARGO_HOME:-$TOOL_HOME/cargo-home}
export RUSTUP_HOME=${R2O_RUSTUP_HOME:-$TOOL_HOME/rustup-home}
export CARGO_TARGET_DIR=${R2O_CARGO_TARGET_DIR:-$TOOL_HOME/target-panel-header-limit}
export TMPDIR=$TEMP_BASE

CC=${CC:-cc}
"$CC" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
    -D_POSIX_C_SOURCE=200809L \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-request-header-limit" \
    "$ROOT/crates/r2o-panel/tests/d2o_request_header_limit.c" \
    "$D2O_ROOT/panel/server.c"
"$TEMP/d2o-request-header-limit" > "$TEMP/d2o.trace"
printf 'HTTP/1.1 404\n' > "$TEMP/d2o.expected"
cmp "$TEMP/d2o.expected" "$TEMP/d2o.trace"

export R2O_PANEL_HEADER_LIMIT_C_TRACE="$TEMP/d2o.trace"
export R2O_PANEL_HEADER_LIMIT_RUST_TRACE="$TEMP/rust.trace"
CARGO=${CARGO:-cargo}
"$CARGO" test --quiet --locked --offline -p r2o-panel --lib \
    d2o_request_header_limit_matches_rust_handler -- --ignored --nocapture
cmp "$TEMP/d2o.trace" "$TEMP/rust.trace"
cat "$TEMP/d2o.trace"
printf '%s\n' 'test-panel-request-header-limit-differential: D2O and R2O response status match'
