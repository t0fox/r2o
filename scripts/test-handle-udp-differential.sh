#!/bin/sh
# C/Rust differential: ветви handle_udp — voice/STUN, QUIC Initial,
# серверное направление и отказ UDP-таблицы.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}
FIXTURE="$ROOT/crates/r2k-core/tests/fixtures/quic_v1_initial.bin"
FIXTURE_NO_SNI="$ROOT/crates/r2k-core/tests/fixtures/quic_v1_initial_no_sni.bin"

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

DENY="$D2O_ROOT/datapath"
make -s -C "$DENY" test_udp_path CC="$CC" >/dev/null
mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-handle-udp.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$DENY/include" -I"$D2O_ROOT/core/include" \
    -DD2K_RELEASE_ID='"dev"' \
    -o "$TEMP/d2o-handle-udp" \
    "$ROOT/crates/r2o-datapath/tests/d2o_handle_udp_differential.c" \
    "$DENY/udp_path.o" "$DENY/udp_hold.o" "$DENY/udp_release.o" \
    "$DENY/routemark.o" "$DENY/session.o" "$DENY/http80.o" "$DENY/hold.o" \
    "$DENY/capture.o" "$DENY/nat.o" "$DENY/ctq.o" "$DENY/nl.o" \
    "$DENY/track.o" "$DENY/tls.o" "$DENY/wire.o" "$DENY/wire_udp.o" \
    "$DENY/journal.o" "$DENY/plans.o" "$DENY/plan_parse.o" \
    "$DENY/plan_apply.o" "$DENY/core_quic.o" "$DENY/core_quicwire.o" \
    "$DENY/core_quicsnap.o" "$DENY/core_crypto.o" "$DENY/core_ipfrag.o" \
    "$DENY/core_httpup_logic.o" -pthread -lm
"$TEMP/d2o-handle-udp" "$FIXTURE" "$FIXTURE_NO_SNI" >"$TEMP/c.out"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib r2o_udp_sessions::tests::d2o_handle_udp_trace \
    -- --ignored --nocapture >"$TEMP/rust.raw" 2>&1
grep -E '^([QVRS][0-9]) ' "$TEMP/rust.raw" >"$TEMP/rust.out"

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l < "$TEMP/c.out")"
printf 'PASS: C/Rust handle_udp voice/QUIC/refusal match (D2O %s)\n' "$ACTUAL_D2O_SHA"
