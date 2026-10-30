#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TOOLING_ROOT=${R2O_TOOLING_ROOT:-${ROOT%/*}/r2o-tooling}
ROOT_TOOLCHAIN_BIN=$TOOLING_ROOT/cargo-home/bin
ROOT_CARGO_HOME=$TOOLING_ROOT/cargo-home
ROOT_RUSTUP_HOME=$TOOLING_ROOT/rustup-home
ROOT_BUILD_TARGET=$TOOLING_ROOT/target-panel-diagnostics
ROOT_TMP=$TOOLING_ROOT/tmp
windows_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s\n' "$1"; fi
}
WIN_CARGO_HOME=$(windows_path "$ROOT_CARGO_HOME")
WIN_RUSTUP_HOME=$(windows_path "$ROOT_RUSTUP_HOME")
WIN_BUILD_TARGET=$(windows_path "$ROOT_BUILD_TARGET")
WIN_TMP=$(windows_path "$ROOT_TMP")
WIN_CARGO=$(windows_path "$ROOT_TOOLCHAIN_BIN/cargo.exe")
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$ROOT_TMP"
TEMP=$(mktemp -d "$ROOT_TMP/panel-diagnostics.XXXXXX")
cleanup() {
    if [ "${R2O_KEEP_TEST_TMP:-0}" = 1 ]; then
        echo "kept test directory: $TEMP" >&2
    else
        rm -rf "$TEMP"
    fi
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$TEMP/diagnostics" "$TEMP/state/diagnostics"
: > "$TEMP/diagnostics/enabled"
: > "$TEMP/state/diagnostics/enabled"
chmod 0700 "$TEMP/diagnostics" "$TEMP/state/diagnostics"
chmod 0600 "$TEMP/diagnostics/enabled" "$TEMP/state/diagnostics/enabled"

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
    -I"$D2O_ROOT/panel" \
    "$ROOT/crates/r2o-panel/tests/d2o_diagnostics_default_query.c" \
    "$D2O_ROOT/panel/server.c" \
    -o "$TEMP/d2o-panel-diagnostics"
R2O_PANEL_DIAGNOSTICS_DIR="$TEMP/diagnostics" \
    "$TEMP/d2o-panel-diagnostics" > "$TEMP/c.trace"

cat > "$TEMP/run-rust-test.ps1" <<PS
\$env:CARGO_HOME = '$WIN_CARGO_HOME'
\$env:RUSTUP_HOME = '$WIN_RUSTUP_HOME'
\$env:CARGO_TARGET_DIR = '$WIN_BUILD_TARGET'
\$env:TMP = '$WIN_TMP'
\$env:TEMP = '$WIN_TMP'
\$env:TMPDIR = '$WIN_TMP'
\$env:R2O_PANEL_DIAGNOSTICS_STATE_DIR = '$(windows_path "$TEMP/state")'
\$env:R2O_PANEL_DIAGNOSTICS_C_TRACE = '$(windows_path "$TEMP/c.trace")'
\$env:R2O_PANEL_DIAGNOSTICS_TRACE_OUTPUT = '$(windows_path "$TEMP/rust.trace")'
& '$WIN_CARGO' +1.98.0-x86_64-pc-windows-gnu test -p r2o-panel --test http --locked --offline d2o_diagnostics_default_query_trace -- --ignored --nocapture
exit \$LASTEXITCODE
PS
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass \
    -File "$(windows_path "$TEMP/run-rust-test.ps1")"

echo "C/Rust diagnostics default-query responses match d2o $ACTUAL_D2O_SHA."
