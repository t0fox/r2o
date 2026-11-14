#!/bin/sh
# C/Rust differential: SO_TIMESTAMP на NFQUEUE-сокете (d2kd.c:1313-1319).
#
# Без этого параметра ядро не кладёт NFQA_TIMESTAMP, и HTTP80 меряет RTT по
# своим часам вместо часов приёма пакета.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-nfq-timestamp.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -o "$TEMP/d2o-nfq-timestamp" \
    "$ROOT/crates/r2o-datapath/tests/d2o_nfq_timestamp_differential.c"
"$TEMP/d2o-nfq-timestamp" >"$TEMP/c.out"

R2O_NFQ_TIMESTAMP_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib nfqueue::tests::nfq_timestamp_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: NFQUEUE SO_TIMESTAMP C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
