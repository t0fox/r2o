#!/bin/sh
# C/Rust differential: d2k_ct_get_req и разбор ответов (datapath/ctq.c).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
DONOR_DATAPATH=${R2O_DONOR_DATAPATH:-"$D2O_ROOT/datapath"}
CC=${CC:-clang-18}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-ctget.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$DONOR_DATAPATH/include" \
    "$ROOT/crates/r2o-datapath/tests/d2o_conntrack_cli.c" \
    "$DONOR_DATAPATH/ctq.c" \
    "$DONOR_DATAPATH/nl.c" \
    -o "$TEMP/d2o-conntrack-oracle"

D2O_CONNTRACK_ORACLE="$TEMP/d2o-conntrack-oracle" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --test d2o_conntrack -- --ignored --nocapture
printf 'PASS: d2k_ct_get_req C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
