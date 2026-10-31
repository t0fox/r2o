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
TEMP=$(mktemp -d "$TEMP_BASE/r2o-panel-header-deadline.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

export HOME=${R2O_TEST_HOME:-$TOOL_HOME/home}
export CARGO_HOME=${R2O_CARGO_HOME:-$TOOL_HOME/cargo-home}
export RUSTUP_HOME=${R2O_RUSTUP_HOME:-$TOOL_HOME/rustup-home}
export CARGO_TARGET_DIR=${R2O_CARGO_TARGET_DIR:-$TOOL_HOME/target-panel-header-deadline}
export TMPDIR=$TEMP_BASE

CC=${CC:-cc}
"$CC" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
    -D_POSIX_C_SOURCE=200809L \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-header-deadline" \
    "$ROOT/crates/r2o-panel/tests/d2o_header_deadline.c" \
    "$D2O_ROOT/panel/server.c"
"$TEMP/d2o-header-deadline" > "$TEMP/d2o.trace"
export R2O_PANEL_HEADER_DEADLINE_C_TRACE="$TEMP/d2o.trace"
export R2O_PANEL_HEADER_DEADLINE_RUST_TRACE="$TEMP/rust.trace"
CARGO=${CARGO:-cargo}
"$CARGO" test --quiet --locked --offline -p r2o-panel --lib \
    d2o_header_deadline_matches_rust_reader -- --ignored --nocapture
if [ "$(sed -n '1p' "$TEMP/d2o.trace")" != "$(sed -n '1p' "$TEMP/rust.trace")" ]; then
    printf 'D2O/R2O status mismatch:\nD2O: %s\nR2O: %s\n' \
        "$(cat "$TEMP/d2o.trace")" "$(cat "$TEMP/rust.trace")" >&2
    exit 1
fi
printf 'D2O: '; tr '\n' ' ' < "$TEMP/d2o.trace"; printf '\n'
printf 'R2O: '; tr '\n' ' ' < "$TEMP/rust.trace"; printf '\n'
printf '%s\n' 'test-panel-header-deadline-differential: D2O and R2O share a 5-second absolute deadline'
