#!/bin/sh
# C/Rust differential: d2k_ctlsrv_command ACK results (a378).
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

DENY="$D2O_ROOT/datapath"
make -s -C "$DENY" test_ctl CC="$CC" >/dev/null
mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-ctlsrv-command.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$DENY/include" -I"$D2O_ROOT/core/include" \
    -DD2K_RELEASE_ID='"dev"' \
    -o "$TEMP/d2o-ctlsrv-command" \
    "$ROOT/crates/r2o-datapath/tests/d2o_ctlsrv_command_differential.c" \
    "$DENY/ctl.o" "$DENY/ctlsrv.o" "$DENY/session.o" "$DENY/http80.o" \
    "$DENY/hold.o" "$DENY/capture.o" "$DENY/nat.o" "$DENY/ctq.o" \
    "$DENY/nl.o" "$DENY/journal.o" "$DENY/track.o" "$DENY/tls.o" \
    "$DENY/wire.o" "$DENY/wire_udp.o" "$DENY/plans.o" \
    "$DENY/plan_parse.o" "$DENY/plan_apply.o" "$DENY/core_quic.o" \
    "$DENY/core_quicwire.o" "$DENY/core_quicsnap.o" \
    "$DENY/core_crypto.o" "$DENY/core_ipfrag.o" \
    "$DENY/core_httpup_logic.o" -pthread -lm
"$TEMP/d2o-ctlsrv-command" >"$TEMP/c.out" 2>/dev/null

R2O_CTLSRV_COMMAND_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib control::tests::ctlsrv_command_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: d2k_ctlsrv_command ACK C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
