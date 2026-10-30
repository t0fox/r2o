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

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-classifier-clear-confirm.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
D2O_CORE=$D2O_ROOT/core
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
RUSTC=${RUSTC:-rustc}

"$CC" -std=c99 -O2 -Wall -Wextra -Werror -pthread -D_POSIX_C_SOURCE=200809L \
    -I"$D2O_CORE/include" \
    -o "$TEMP/d2o-classifier" \
    "$ROOT/crates/r2o-controller/tests/fixtures/classify-clear-confirm-d2o.c" \
    "$D2O_CORE/verdict.c" "$D2O_CORE/meas.c" "$D2O_CORE/hello.c"

mkdir -p "$TEMP/rust/src"
rust_root=$ROOT
rust_temp=$TEMP
rust_target=${CARGO_TARGET_DIR:-$TEMP/target}
if command -v cygpath >/dev/null 2>&1; then
    rust_root=$(cygpath -am "$ROOT")
    rust_temp=$(cygpath -am "$TEMP")
    rust_target=$(cygpath -am "$rust_target")
fi
cat > "$TEMP/rust/Cargo.toml" <<EOF
[package]
name = "r2o-classifier-clear-confirm-differential"
version = "0.1.0"
edition = "2024"

[dependencies]
r2k-core = { path = "$rust_root/crates/r2k-core" }
EOF
cat "$ROOT/crates/r2o-controller/tests/fixtures/classify-probe-support.rs" > "$TEMP/rust/src/main.rs"
cat >> "$TEMP/rust/src/main.rs" <<EOF
#[path = "$rust_root/crates/r2o-controller/src/hello.rs"]
pub mod hello;
#[path = "$rust_root/crates/r2o-controller/src/plan_text.rs"]
pub mod plan_text;
#[path = "$rust_root/crates/r2o-controller/src/classify_measured.rs"]
mod classify_measured;
#[path = "$rust_root/crates/r2o-controller/src/classify.rs"]
pub mod classify;
EOF
cat "$ROOT/crates/r2o-controller/tests/fixtures/classify-clear-confirm-rust.rs" >> "$TEMP/rust/src/main.rs"

"$TEMP/d2o-classifier" > "$TEMP/d2o.out"
CARGO_TARGET_DIR=$rust_target \
RUSTFLAGS="${RUSTFLAGS:--Awarnings}" \
CARGO_BUILD_TARGET=${CARGO_BUILD_TARGET:-$($RUSTC -vV | sed -n 's/^host: //p')} \
CARGO_MAKEFLAGS= \
    "$CARGO" run --quiet --manifest-path "$rust_temp/rust/Cargo.toml" > "$TEMP/r2o.out"
cmp "$TEMP/d2o.out" "$TEMP/r2o.out"
cat "$TEMP/d2o.out"
printf 'D2O %s matches R2O for clear/base/control repeats, mark confirmation, unproven responses, and cancellation.\n' \
    "$ACTUAL_D2O_SHA"
