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

TEMP_BASE=${R2O_TEST_TMP:-${ROOT%/*}/r2o-tooling/tmp}
if [ ! -d "$TEMP_BASE" ]; then
    TEMP_BASE=${TMPDIR:-/tmp}
fi
TEMP=$(mktemp -d "$TEMP_BASE/r2o-classifier-white-decoy.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
CC=${CC:-cc}
RUSTC=${RUSTC:-rustc}
rustc_cmd=$RUSTC
rust_fixture="$ROOT/crates/r2o-controller/tests/fixtures/classify-white-decoy-r2o.rs"
rust_output="$TEMP/r2o-white-decoy.exe"
if command -v cygpath >/dev/null 2>&1; then
    case $RUSTC in
        [A-Za-z]:\\*) rustc_cmd=$(cygpath -u "$RUSTC") ;;
    esac
    rust_fixture=$(cygpath -am "$rust_fixture")
    rust_output=$(cygpath -am "$rust_output")
fi

mkdir -p "$TEMP/profiles"
cp "$D2O_ROOT/core/profiles/modern.hex" "$D2O_ROOT/core/profiles/legacy.hex" \
    "$TEMP/profiles/"
make -s -C "$TEMP" -f "$D2O_ROOT/core/Makefile" hello_profiles.inc
"$CC" -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/detect" -I"$D2O_ROOT/detect/include" \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -I"$TEMP" \
    -o "$TEMP/d2o-white-decoy" \
    "$ROOT/crates/r2o-controller/tests/fixtures/classify-white-decoy-d2o.c" \
    "$D2O_ROOT/detect/trigger.c" "$D2O_ROOT/core/measured.c" "$D2O_ROOT/core/hello.c" \
    -Wl,--gc-sections

"$rustc_cmd" --edition 2024 -Awarnings \
    "$rust_fixture" -o "$rust_output"
"$TEMP/d2o-white-decoy" > "$TEMP/d2o.out"
"$TEMP/r2o-white-decoy" > "$TEMP/r2o.out"
if ! cmp -s "$TEMP/d2o.out" "$TEMP/r2o.out"; then
    diff -u "$TEMP/d2o.out" "$TEMP/r2o.out" || true
    exit 1
fi
printf 'D2O %s white decoy plus default/custom controls and target/control raw triggers match R2O.\n' "$ACTUAL_D2O_SHA"
