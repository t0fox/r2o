#!/bin/sh
# C/Rust differential: DNS health wire encode/parse and DoH response parser.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-dns-health.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -DD2K_RELEASE_ID='"dev"' \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/runtime" \
    -o "$TEMP/d2o-dns-health" \
    "$ROOT/crates/r2o-controller/tests/d2o_dns_health_differential.c" \
    "$D2O_ROOT/core/diagnostics.c" -Wl,--gc-sections -pthread
"$TEMP/d2o-dns-health" >"$TEMP/c.out"

R2O_DNS_HEALTH_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib dns_health_c_differential_matches_current_donor \
    >/dev/null

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: DNS health wire/parser differential\n' >&2
    exit 1
fi

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib loopback_dot_health_returns_valid_length_prefixed_reply \
    >/dev/null
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib loopback_doh_health_returns_valid_dns_reply \
    >/dev/null
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib loopback_doq_health_uses_stream_zero_and_zero_id \
    >/dev/null

printf 'cases=%s\n' "$(grep -c '^dns case=\|^doh case=' "$TEMP/c.out")"
cat "$TEMP/c.out"
printf 'PASS: C/Rust DNS health wire/parser match; DoT/DoH/DoQ loopback passed (D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
