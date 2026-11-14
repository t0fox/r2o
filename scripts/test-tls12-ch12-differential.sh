#!/bin/sh
# C/Rust differential: donor ch12_build против r2o_tls12_client_hello.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the current D2O checkout}
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tls12-ch12.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" \
    -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-ch12" \
    "$ROOT/crates/r2o-controller/tests/d2o_tls12_ch12_differential.c" \
    -Wl,--gc-sections
"$TEMP/d2o-ch12" >"$TEMP/c.out"

R2O_TLS12_CH12_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib ch12_build_c_differential_matches_donor_bytes >/dev/null

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: TLS1.2 ch12_build differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(grep -c '^case=' "$TEMP/c.out")"
grep '^case=example ' "$TEMP/c.out" | cut -c1-100
grep '^case=example-700 ' "$TEMP/c.out" | cut -c1-100
printf 'PASS: C/Rust TLS1.2 ch12_build match (D2O %s)\n' "$ACTUAL_D2O_SHA"
