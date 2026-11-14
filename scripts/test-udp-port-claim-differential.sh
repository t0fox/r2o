#!/bin/sh
# C/Rust differential: d2k_udp_port_claim — кольцо недавних UDP-портов.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-udp-port-claim.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

cat >"$TEMP/ports.txt" <<'EOF'
39001
39002
39001
39003
39002
39004
39001
39005
39003
39006
EOF

"$CC" -std=c11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-udp-port-claim" \
    "$ROOT/crates/r2o-controller/tests/d2o_udp_port_claim_differential.c" \
    "$D2O_ROOT/core/meas.c"
"$TEMP/d2o-udp-port-claim" "$TEMP/ports.txt" >"$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --example tg_udp_port_claim_trace -- \
    "$TEMP/ports.txt" >"$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: udp port claim differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(wc -l < "$TEMP/ports.txt")"
printf 'PASS: C/Rust d2k_udp_port_claim match (D2O %s)\n' "$ACTUAL_D2O_SHA"
