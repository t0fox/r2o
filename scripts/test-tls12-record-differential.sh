#!/bin/sh
# C/Rust differential TLS1.2 sealed-записи: production C send_sealed против
# production Rust Tls12RecordWriter::seal (exact bytes + sequence).
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
CC=${CC:-cc}
(
    cd "$DONOR/core"
    "$CC" -std=gnu11 -O2 -ffunction-sections -fdata-sections \
        -I. -Iinclude -o "$TMP/c" \
        "$ROOT/crates/r2o-controller/tests/d2o_tls12_record_differential.c" \
        crypto.c -Wl,--gc-sections
)
cargo build --locked -q -p r2o-controller --example tls12_record_trace
"$TMP/c" > "$TMP/c.out"
"$ROOT/target/debug/examples/tls12_record_trace" > "$TMP/r.out"
diff -u "$TMP/c.out" "$TMP/r.out"
cat "$TMP/c.out"
printf 'PASS: TLS1.2 sealed record C/Rust bytes match (D2O %s)\n' "$ACTUAL_SHA"
