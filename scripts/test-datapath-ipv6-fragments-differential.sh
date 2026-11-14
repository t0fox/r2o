#!/bin/sh
# C/Rust differential: сборка IPv6-фрагментов без отправки.
#
# Сверяются fragment header, id, offset/M, порядок форм 1-4, длины и байты
# полезной нагрузки. CAP_NET_RAW не требуется.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-ipv6-frag.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-ipv6-frag" \
    "$ROOT/crates/r2o-datapath/tests/d2o_ipv6_fragments_differential.c" \
    "$D2O_ROOT/core/ipfrag.c"
"$TEMP/d2o-ipv6-frag" >"$TEMP/c.out"

R2O_IPV6_FRAG_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib raw::tests::ipv6_fragment_build_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(grep -c '^shape' "$TEMP/c.out")"
printf 'PASS: IPv6 fragment build C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
