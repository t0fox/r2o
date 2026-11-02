#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
EXPECTED_D2O_SHA=a63d9641f4e00aa35fa1e5ccbda47bb5f310c0fe
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-ipfrag.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c11 -O2 -I "$D2O_ROOT/core/include" \
    "$D2O_ROOT/core/ipfrag.c" \
    "$ROOT/crates/r2k-core/tests/d2o_ipfrag_oracle.c" \
    -o "$TEMP/oracle"
"$TEMP/oracle" > "$TEMP/oracle.bin"

D2O_IPFRAG_ORACLE="$TEMP/oracle.bin" "$CARGO" +1.98.0 test \
    --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    --package r2k-core --test ipfrag -- \
    --include-ignored --exact d2o_ipfrag_builder_matches_r2o_on_ipv4_ipv6_shapes

make -C "$D2O_ROOT/datapath" test_quic_session CC="$CC"
(
    cd "$D2O_ROOT/datapath"
    "$CC" -std=c99 -O2 -Wall -Wextra -Werror -I include -I ../core/include \
        -o "$TEMP/session-oracle" "$ROOT/crates/r2o-datapath/tests/d2o_ipfrag_session_oracle.c" \
        session.o http80.o hold.o capture.o nat.o ctq.o nl.o track.o tls.o wire.o wire_udp.o \
        journal.o plans.o plan_parse.o plan_apply.o core_quic.o core_quicwire.o core_quicsnap.o \
        core_crypto.o core_ipfrag.o core_httpup_logic.o core_quichello.o core_hello.o \
        core_tls13core.o core_x25519.o
)
R2O_D2O_IPFRAG_SESSION_ORACLE="$TEMP/session-oracle" "$CARGO" +1.98.0 test \
    --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    --package r2o-datapath --lib current_d2o_session_ipfrag_outputs_match_r2o_production_decisions \
    -- --include-ignored
