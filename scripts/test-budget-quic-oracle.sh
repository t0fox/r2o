#!/bin/sh
# C oracle budget_quic (verify.c + mock quic_budget_io) и Rust
# threshold/growth differential. Полный Rust-аналог budget_quic отсутствует.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT}
EXPECTED_D2O_SHA=${R2O_EXPECTED_DONOR_SHA:-7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05}
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-budget-quic.XXXXXX")
cleanup() {
    status=$?
    rm -rf -- "$TEMP"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -DD2K_RELEASE_ID='"dev"' \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/runtime" \
    -o "$TEMP/d2o-budget-quic" \
    "$ROOT/crates/r2o-controller/tests/d2o_budget_quic_differential.c" \
    "$D2O_ROOT/core/diagnostics.c" -Wl,--gc-sections -pthread
"$TEMP/d2o-budget-quic" >"$TEMP/c.out"
cat "$TEMP/c.out"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib \
    r2o_quic_http3::tests::d2o_quic_budget_growth_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

printf 'PASS: C budget_quic oracle and Rust QUIC threshold/growth differential (D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
