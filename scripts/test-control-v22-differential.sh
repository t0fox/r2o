#!/bin/sh
# S12: C/Rust differential v22 SET_NAME_BOUND ACK (raw 28-byte binding, без R2BC).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-control-v22.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c11 -O2 -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core/include" \
    -o "$TEMP/c-v22-ack" "$ROOT/scripts/fixtures/control_v22_ack.c"
"$TEMP/c-v22-ack" > "$TEMP/c.hex"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    --package r2k-core --example control_v22_ack > "$TEMP/rust.hex"

if ! diff -u "$TEMP/c.hex" "$TEMP/rust.hex"; then
    printf 'FAIL: v22 ACK C/Rust differential\n' >&2
    exit 1
fi

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2k-core --test plan converts_r2op_to_legacy_d2kp_and_back
printf 'PASS: v22 ACK body and D2KP outbound conversion match D2O %s\n' "$ACTUAL_D2O_SHA"
