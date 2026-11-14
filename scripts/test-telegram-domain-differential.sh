#!/bin/sh
# C/Rust differential: is_telegram_tunnel_domain + SCHED_DECOY (core/sched.c).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-telegram-domain.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/core" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-telegram-domain" \
    "$ROOT/crates/r2o-controller/tests/d2o_telegram_domain_differential.c"
"$TEMP/d2o-telegram-domain" >"$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --example tg_telegram_domain_trace >"$TEMP/rust.out"

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l < "$TEMP/c.out")"
printf 'PASS: C/Rust Telegram tunnel/decoy filters match (D2O %s)\n' "$ACTUAL_D2O_SHA"
