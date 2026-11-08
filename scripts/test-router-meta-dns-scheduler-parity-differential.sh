#!/bin/sh
# B48: paired C/Rust differential Meta DNS offset/backoff/run_at/tick.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-b48-meta-dns.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

sh "$ROOT/scripts/fixtures/d2o-meta-dns-scheduler-trace.sh" "$D2O_ROOT" "$TEMP" >"$TEMP/c.out"

R2O_B48_TRACE_DIR="$TEMP/rust-trace" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-telegram --lib meta_dns::tests::b48_scheduler_trace \
    -- --ignored --nocapture >"$TEMP/rust.raw" 2>&1
grep -E '^(offset|backoff|run_at|tick) ' "$TEMP/rust.raw" >"$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: Meta DNS scheduler differential\n' >&2
    exit 1
fi

printf 'offset-cases=%s\n' "$(grep -c '^offset ' "$TEMP/c.out")"
grep '^tick first-install ' "$TEMP/c.out"
printf 'PASS: C/Rust Meta DNS offset/backoff/run_at/tick match (D2O %s)\n' "$ACTUAL_D2O_SHA"
