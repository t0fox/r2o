#!/bin/sh
# Telegram core taken from z2kOW: source-level parity of retry/cooldown/policy
# functions and the donor test suite. C11 D2O is not the Telegram source.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR_ROOT=${R2O_Z2KOW_ROOT:?set R2O_Z2KOW_ROOT to the z2kOW checkout}
EXPECTED_SHA=42c8111765fe5bc5a2a690223df2523e85400eb5
ACTUAL_SHA=$(git -C "$DONOR_ROOT" rev-parse HEAD)
CARGO=${CARGO:-cargo}

if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    printf 'Expected z2kOW %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
fi

DONOR_SRC="$DONOR_ROOT/platform/openwrt/tg-proxy/src"
python3 "$ROOT/scripts/fixtures/compare_donor_functions.py" \
    "$DONOR_SRC" "$ROOT/crates/r2o-telegram/src"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-telegram --lib \
    ws_client::tests -- --test-threads=1 >/dev/null
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-telegram --lib \
    routing::tests -- --test-threads=1 >/dev/null
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-telegram --test config >/dev/null

printf 'PASS: z2kOW retry/cooldown/routing core and tests match %s\n' "$ACTUAL_SHA"
