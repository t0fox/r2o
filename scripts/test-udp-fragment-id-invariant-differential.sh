#!/bin/sh
# C/Rust invariant differential: udp_next_fragment_id (C) против
# wire::next_udp_fragment_id (Rust).
#
# Значения разные из-за случайного seed, поэтому сравниваются только
# инварианты 32 последовательных вызовов: next == prev+1 или prev+2,
# low16 != 0, значения не нулевые и уникальные (32 вызова).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-fragment-id.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -C "$D2O_ROOT/core" test_udp_runtime >"$TEMP/d2o-build.log" 2>&1
(
    cd "$D2O_ROOT/core"
    "$CC" -std=c99 -O2 -Wall -Wextra -Werror -D_GNU_SOURCE \
        -I. -Iinclude -I../datapath/include \
        -ffunction-sections -fdata-sections \
        -o "$TEMP/d2o-fragment-id" \
        "$ROOT/crates/r2k-core/tests/d2o_udp_fragment_id_invariant.c" \
        tls13core.o crypto.o x25519.o -Wl,--gc-sections -lpthread
)
"$TEMP/d2o-fragment-id" >"$TEMP/c.out"

cd "$ROOT"
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2k-core --lib --no-run >"$TEMP/build.log" 2>&1
RUST_BIN=$(sed -n 's/.*Executable unittests src\/lib.rs (\(.*\))/\1/p' "$TEMP/build.log" | tail -1)
if [ -z "$RUST_BIN" ]; then
    echo "не найден тестовый бинарник r2k-core lib" >&2
    cat "$TEMP/build.log" >&2
    exit 2
fi
case "$RUST_BIN" in
    /*) ;;
    *) RUST_BIN="$ROOT/$RUST_BIN" ;;
esac
R2O_FRAGMENT_ID_INVARIANT_OUT="$TEMP/rust.out" \
    "$RUST_BIN" --exact --nocapture \
    wire::udp_fragment_id_tests::udp_fragment_id_sequence_is_monotonic_32 \
    >"$TEMP/rust.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=1\n'
printf 'PASS: udp fragment id invariants C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
