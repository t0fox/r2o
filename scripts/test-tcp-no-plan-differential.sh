#!/bin/sh
# C/Rust differential: TCP-ветка «плана для этой цели нет» (session.c:2368-2410).
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
make -s -C "$DENY" udp_path.o udp_hold.o udp_release.o routemark.o session.o \
    http80.o hold.o capture.o nat.o ctq.o nl.o track.o tls.o wire.o wire_udp.o \
    journal.o plans.o plan_parse.o plan_apply.o core_quic.o core_quicwire.o \
    core_quicsnap.o core_crypto.o core_ipfrag.o core_httpup_logic.o CC="$CC" >/dev/null
mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-tcp-no-plan.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$DENY/include" -I"$D2O_ROOT/core/include" \
    -DD2K_RELEASE_ID='"dev"' \
    -o "$TEMP/d2o-tcp-no-plan" \
    "$ROOT/crates/r2o-datapath/tests/d2o_tcp_no_plan_differential.c" \
    "$DENY/udp_path.o" "$DENY/udp_hold.o" "$DENY/udp_release.o" \
    "$DENY/routemark.o" "$DENY/session.o" "$DENY/http80.o" "$DENY/hold.o" \
    "$DENY/capture.o" "$DENY/nat.o" "$DENY/ctq.o" "$DENY/nl.o" \
    "$DENY/track.o" "$DENY/tls.o" "$DENY/wire.o" "$DENY/wire_udp.o" \
    "$DENY/journal.o" "$DENY/plans.o" "$DENY/plan_parse.o" \
    "$DENY/plan_apply.o" "$DENY/core_quic.o" "$DENY/core_quicwire.o" \
    "$DENY/core_quicsnap.o" "$DENY/core_crypto.o" "$DENY/core_ipfrag.o" \
    "$DENY/core_httpup_logic.o" -pthread -lm
"$TEMP/d2o-tcp-no-plan" >"$TEMP/c.out"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib engine::tests::d2o_tcp_no_plan_trace \
    -- --ignored --nocapture >"$TEMP/rust.raw" 2>&1
grep -E '^T[0-9] ' "$TEMP/rust.raw" >"$TEMP/rust.out"

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l < "$TEMP/c.out")"
printf 'PASS: C/Rust TCP no-plan refusal match (D2O %s)\n' "$ACTUAL_D2O_SHA"
