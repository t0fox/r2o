#!/bin/sh
# M6: paired C/Rust differential crypto.c (SHA/HMAC/HKDF/AES-128).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-m6-crypto.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-crypto" \
    "$ROOT/crates/r2k-core/tests/d2o_crypto_differential.c" \
    "$D2O_ROOT/core/crypto.c"
"$TEMP/d2o-crypto" >"$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2k-core --example m6_crypto_trace >"$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: crypto differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(grep -c '^case ' "$TEMP/c.out")"
grep -A1 '^case hkdf-client-in$' "$TEMP/c.out"
printf 'PASS: C/Rust crypto helpers match (D2O %s)\n' "$ACTUAL_D2O_SHA"
