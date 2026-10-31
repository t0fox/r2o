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
TEMP=$(mktemp -d "$TEMP_BASE/r2o-classifier-candidate-filter.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
RUSTC=${RUSTC:-rustc}

"$CC" -std=c99 -O2 -Wall -Wextra -Werror -Wno-unused-variable -Wno-unused-function \
    -pthread -I"$D2O_ROOT/detect" -I"$D2O_ROOT/detect/include" \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-filter" \
    "$ROOT/crates/r2o-controller/tests/fixtures/classify-candidate-filter-d2o.c" \
    "$D2O_ROOT/detect/poison.c" "$D2O_ROOT/detect/trigger.c" \
    "$D2O_ROOT/detect/response.c" "$D2O_ROOT/detect/raw.c" \
    "$D2O_ROOT/core/measured.c" "$D2O_ROOT/core/hello.c" \
    "$D2O_ROOT/core/plantlv.c" "$D2O_ROOT/core/quic.c" \
    "$D2O_ROOT/core/quicwire.c" "$D2O_ROOT/core/crypto.c" \
    "$D2O_ROOT/datapath/plan_parse.c" "$D2O_ROOT/datapath/plan_apply.c" \
    "$D2O_ROOT/datapath/wire.c"
"$TEMP/d2o-filter" > "$TEMP/d2o.out"

mkdir -p "$TEMP/rust/src"
rust_root=$ROOT
rust_temp=$TEMP
rust_target=${CARGO_TARGET_DIR:-$TEMP/target}
if command -v cygpath >/dev/null 2>&1; then
    rust_root=$(cygpath -am "$ROOT")
    rust_temp=$(cygpath -am "$TEMP")
    rust_target=$(cygpath -am "$rust_target")
fi
rust_root_dep=$(realpath --relative-to="$TEMP/rust" "$ROOT")
cat > "$TEMP/rust/Cargo.toml" <<EOF
[package]
name = "r2o-classifier-candidate-filter-differential"
version = "0.1.0"
edition = "2024"

[dependencies]
r2k-core = { path = "$rust_root_dep/crates/r2k-core" }
EOF
cat "$ROOT/crates/r2o-controller/tests/fixtures/classify-probe-support.rs" > "$TEMP/rust/src/main.rs"
cat >> "$TEMP/rust/src/main.rs" <<EOF
#[path = "$rust_root/crates/r2o-controller/src/hello.rs"]
pub mod hello;
#[path = "$rust_root/crates/r2o-controller/src/trigger.rs"]
pub mod trigger;
#[path = "$rust_root/crates/r2o-controller/src/plan_text.rs"]
pub mod plan_text;
#[path = "$rust_root/crates/r2o-controller/src/classify_measured.rs"]
mod classify_measured;
#[path = "$rust_root/crates/r2o-controller/src/classify.rs"]
pub mod classify;
EOF
cat "$ROOT/crates/r2o-controller/tests/fixtures/classify-candidate-filter-r2o.rs" >> "$TEMP/rust/src/main.rs"

CARGO_TARGET_DIR=$rust_target \
RUSTFLAGS="${RUSTFLAGS:--Awarnings}" \
CARGO_BUILD_TARGET=${CARGO_BUILD_TARGET:-$($RUSTC -vV | sed -n 's/^host: //p')} \
CARGO_MAKEFLAGS= \
    "$CARGO" run --quiet --target "${CARGO_BUILD_TARGET:-$($RUSTC -vV | sed -n 's/^host: //p')}" \
        --manifest-path "$rust_temp/rust/Cargo.toml" > "$TEMP/r2o.out"
if ! cmp -s "$TEMP/d2o.out" "$TEMP/r2o.out"; then
    diff -u "$TEMP/d2o.out" "$TEMP/r2o.out" || true
    exit 1
fi
printf 'D2O %s poison filters, raw-probe gating, classifier timeouts, and write gaps match R2O.\n' \
    "$ACTUAL_D2O_SHA"
