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
[ "$ACTUAL_D2O_SHA" = "$EXPECTED_D2O_SHA" ] || {
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
}

mkdir -p "$ROOT_TMP"
TEMP=$(mktemp -d "$ROOT_TMP/panel-config-bytes.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
    -I"$D2O_ROOT/panel" \
    "$ROOT/crates/r2o-panel/tests/d2o_config_parse_trace.c" \
    "$D2O_ROOT/panel/server.c" \
    -o "$TEMP/d2o-config-trace"
{
    printf '# legacy comment with byte '
    printf '\377\n'
    printf 'MODE=apply # trailing comment with byte '
    printf '\377\n'
    printf 'PANEL_LISTEN=192.168.1.1:8090\nQUEUE_NUM=2000\n'
    printf 'FUTURE_KEY=opaque value with byte '
    printf '\377\n'
    printf 'FUTURE_KEY'
    printf '\377'
    printf '_WITH_INVALID_BYTE=value\n'
} > "$TEMP/config"
printf 'MODE="apply" # accepted trailing comment\n' > "$TEMP/quoted.conf"
printf 'PANEL_LISTEN=192.168.1.1:8090\nQUEUE_NUM=2000\n' >> "$TEMP/quoted.conf"
printf 'MODE=apply\t# accepted tab comment\n' > "$TEMP/tab.conf"
printf 'PANEL_LISTEN=192.168.1.1:8090\nQUEUE_NUM=2000\n' >> "$TEMP/tab.conf"
"$TEMP/d2o-config-trace" "$TEMP/config" > "$TEMP/c.trace"
"$TEMP/d2o-config-trace" "$TEMP/quoted.conf" > "$TEMP/quoted.c.trace"
"$TEMP/d2o-config-trace" "$TEMP/tab.conf" > "$TEMP/tab.c.trace"

cat > "$TEMP/run-rust-test.ps1" <<PS
\$env:CARGO_HOME = '$WIN_CARGO_HOME'
\$env:RUSTUP_HOME = '$WIN_RUSTUP_HOME'
\$env:CARGO_TARGET_DIR = '$WIN_BUILD_TARGET'
\$env:TMP = '$WIN_TMP'
\$env:TEMP = '$WIN_TMP'
\$env:TMPDIR = '$WIN_TMP'
\$env:R2O_PANEL_CONFIG_BYTES_PATH = '$(windows_path "$TEMP/config")'
\$env:R2O_PANEL_CONFIG_BYTES_C_TRACE = '$(windows_path "$TEMP/c.trace")'
\$env:R2O_PANEL_CONFIG_QUOTED_PATH = '$(windows_path "$TEMP/quoted.conf")'
\$env:R2O_PANEL_CONFIG_QUOTED_C_TRACE = '$(windows_path "$TEMP/quoted.c.trace")'
\$env:R2O_PANEL_CONFIG_TAB_PATH = '$(windows_path "$TEMP/tab.conf")'
\$env:R2O_PANEL_CONFIG_TAB_C_TRACE = '$(windows_path "$TEMP/tab.c.trace")'
& '$WIN_CARGO' +1.98.0-x86_64-pc-windows-gnu test -p r2o-panel --test http --locked --offline d2o_config_parser_matches_ -- --ignored --nocapture
exit \$LASTEXITCODE
PS
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass \
    -File "$(windows_path "$TEMP/run-rust-test.ps1")"

echo "D2O/R2O config parsing matches for ignored non-UTF-8 bytes at $ACTUAL_D2O_SHA."
