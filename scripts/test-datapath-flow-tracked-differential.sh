#!/bin/sh
# C/Rust differential: flow_tracked (datapath/session.c:678-777) на структурах.
#
# session.c включается в C-оракул; d2k_nat_hook подменён сценарными ответами.
# Проверяются nat_state 0/1/3, first-packet, SYN-ACK, до трёх попыток и
# счётчики ok/miss/none/retried. Live-netns не нужен.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
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
TEMP=$(mktemp -d "$TMPDIR/r2o-flow-tracked.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -D_GNU_SOURCE -O2 -Wall -Wextra \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -I"$D2O_ROOT/datapath" -I"$D2O_ROOT/datapath/include" \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/runtime" \
    -o "$TEMP/d2o-flow-tracked" \
    "$ROOT/crates/r2o-datapath/tests/d2o_flow_tracked_differential.c" \
    "$D2O_ROOT/datapath/nat.c" -lm
"$TEMP/d2o-flow-tracked" >"$TEMP/c.out"

R2O_FLOW_TRACKED_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib flow_tracked_differential \
    >"$TEMP/cargo.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: flow_tracked C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
