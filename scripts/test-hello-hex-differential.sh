#!/bin/sh
# C/Rust differential: статический hex_decode из core/hello.c (480-498).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-hello-hex.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

cat >"$TEMP/cases.txt" <<'EOF'

00
0fF0
abc
gg
0x10
1 0

FFff
000102030405060708090a0b0c0d0e0f
000102030405060708090a0b0c0d0e0f10
000102030405060708090a0b0c0d0e0f1011
09
a
zz
00#11
EOF

"$CC" -std=c11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/core" \
    -o "$TEMP/d2o-hello-hex" \
    "$ROOT/crates/r2o-controller/tests/d2o_hello_hex_differential.c"
"$TEMP/d2o-hello-hex" "$TEMP/cases.txt" >"$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --example tg_hello_hex_trace -- \
    "$TEMP/cases.txt" >"$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: hello hex_decode differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(wc -l < "$TEMP/cases.txt")"
grep '^000102030405060708090a0b0c0d0e0f ' "$TEMP/c.out"
printf 'PASS: C/Rust hex_decode match (D2O %s)\n' "$ACTUAL_D2O_SHA"
