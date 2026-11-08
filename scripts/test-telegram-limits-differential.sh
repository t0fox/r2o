#!/bin/sh
# TG22: paired C/Rust differential пределов соединений и memory budget.
#
# C-оракул — production `telegram/src/limits.c` + `memory_budget.c`.
# Проверяются те же векторы D2O test_limits.c/test_memory_budget.c,
# бюджет роутера, configured_max=64 и серверные stats-поля.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-limits.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/telegram/include" \
    -o "$TEMP/c-limits" "$ROOT/scripts/fixtures/d2o_limits_trace.c" \
    "$D2O_ROOT/telegram/src/limits.c" "$D2O_ROOT/telegram/src/memory_budget.c"
"$TEMP/c-limits" > "$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example limits_trace > "$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: limits/memory budget C/Rust differential\n' >&2
    exit 1
fi

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-telegram --test limits
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-telegram --test server connection_limit_and_buffer_stats_match_d2o_contract
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-telegram --lib memory_budget::tests

printf 'PASS: C/Rust connection limits, router memory budget and D2O 64 cap match (D2O %s)\n' "$ACTUAL_D2O_SHA"
