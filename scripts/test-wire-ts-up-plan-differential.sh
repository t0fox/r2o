#!/bin/sh
# M7: paired C/Rust vector checks for tcp_ts_up and the legacy D2KP container.
set -eu

ROOT=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
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
TEMP=$(mktemp -d "$TMPDIR/r2o-wire-plan.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

(
    cd "$D2O_ROOT/datapath"
    "$CC" -std=c99 -O2 -Wall -Wextra -Iinclude -I../core/include \
        -DD2K_RELEASE_ID='"dev"' -o "$TEMP/test_wire" test_wire.c wire.c
    "$TEMP/test_wire"
    "$CC" -std=c99 -O2 -Wall -Wextra -Iinclude -I../core/include \
        -DD2K_RELEASE_ID='"dev"' -o "$TEMP/test_plan_parse" test_plan_parse.c plan_parse.c
    "$TEMP/test_plan_parse"
)

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2k-core --test wire tcp_ts_up
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2k-core --test plan parses_legacy_d2kp_container
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --test plan_text accepts_d2k_plan_header_and_tsup

printf 'PASS: C and Rust agree on tcp_ts_up vectors and D2KP/R2OP container (D2O %s)\n' "$ACTUAL_D2O_SHA"
