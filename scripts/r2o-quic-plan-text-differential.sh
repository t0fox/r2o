#!/bin/sh
# C/Rust differential: production quic_plan_text builder against C oracle.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CC=${CC:-cc}
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-quic-plan.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$DONOR/core" -I"$DONOR/core/include" -I"$DONOR/datapath/include" \
    -o "$TEMP/c" \
    "$ROOT/crates/r2o-controller/tests/d2o_quic_plan_text_differential.c" \
    -Wl,--gc-sections -pthread
"$TEMP/c" >"$TEMP/c.out"
R2O_QUIC_PLAN_TEXT_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib quic_replay::tests::quic_plan_text_from_state_matches_c_oracle \
    >"$TEMP/rust.log" 2>&1
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'PASS: production quic_plan_text matches C oracle (%s).\n' "$ACTUAL_SHA"
