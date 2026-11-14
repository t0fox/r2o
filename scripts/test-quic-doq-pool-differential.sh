#!/bin/sh
# C/Rust differential: DoQ port 853 does not call the address resolver.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the current D2O checkout}
EXPECTED_D2O_SHA=${R2O_EXPECTED_DONOR_SHA:-7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05}
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-doq-pool.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

# hello.c #include'ит сгенерированный hello_profiles.inc.
make -C "$D2O_ROOT/core" hello_profiles.inc >/dev/null

"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -DD2K_RELEASE_ID='"dev"' \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/runtime" \
    -o "$TEMP/d2o-doq" \
    "$ROOT/crates/r2o-controller/tests/d2o_quic_doq_pool_differential.c" \
    "$D2O_ROOT/core/props.c" "$D2O_ROOT/core/quicprobe.c" \
    "$D2O_ROOT/core/quicsnap.c" "$D2O_ROOT/core/quicsnap_reseal.c" \
    "$D2O_ROOT/core/quicarms.c" "$D2O_ROOT/core/ipfrag.c" \
    "$D2O_ROOT/core/net4.c" "$D2O_ROOT/core/quichello.c" \
    "$D2O_ROOT/core/hello.c" "$D2O_ROOT/core/tls13core.c" \
    "$D2O_ROOT/core/x25519.c" "$D2O_ROOT/core/quic.c" \
    "$D2O_ROOT/core/quicwire.c" "$D2O_ROOT/core/crypto.c" \
    "$D2O_ROOT/core/meas.c" "$D2O_ROOT/core/quicconn.c" \
    "$D2O_ROOT/core/h3.c" "$D2O_ROOT/core/udpplan.c" \
    "$D2O_ROOT/core/udpruntime.c" "$D2O_ROOT/core/plantlv.c" \
    "$D2O_ROOT/datapath/plan_parse.c" "$D2O_ROOT/datapath/plan_apply.c" \
    "$D2O_ROOT/datapath/wire.c" "$D2O_ROOT/datapath/wire_udp.c" \
    "$D2O_ROOT/core/diagnostics.c" -Wl,--gc-sections -pthread
"$TEMP/d2o-doq" >"$TEMP/c.out"

R2O_QUIC_DOQ_POOL_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib r2o_quic_doq_pool_c_differential_matches_resolver_calls \
    >/dev/null

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: QUIC DoQ pool differential\n' >&2
    exit 1
fi

cat "$TEMP/c.out"
printf 'PASS: C/Rust DoQ 853 resolver bypass match (D2O %s)\n' "$ACTUAL_D2O_SHA"
