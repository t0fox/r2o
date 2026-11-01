#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
ROOT_PARENT=$(dirname "$ROOT")
D2O_ROOT="${R2O_DONOR_ROOT:-$ROOT_PARENT/d2o}"
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    echo "pinned D2O checkout is missing or changed" >&2
    exit 2
}
[ "$(uname -s)" = Linux ] || {
    echo "full QUIC data-stage replay requires Linux" >&2
    exit 77
}

TOOLING_ROOT="$ROOT_PARENT/r2o-tooling"
CARGO_HOME="$TOOLING_ROOT/linux-cargo"
RUSTUP_HOME="$TOOLING_ROOT/linux-rustup"
CARGO_TARGET_DIR="$TOOLING_ROOT/linux-target"
TMPDIR="$TOOLING_ROOT/tests"
PATH="$CARGO_HOME/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR TMPDIR PATH
CC=cc
mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-quic-full-stage.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

DONOR_CORE="$D2O_ROOT/core"
"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$DONOR_CORE/include" -I"$D2O_ROOT/datapath/include" \
    "$ROOT/crates/r2o-controller/tests/d2o_quic_data_stage_loopback.c" \
    "$DONOR_CORE/quicprobe.c" "$DONOR_CORE/quicconn.c" "$DONOR_CORE/h3.c" \
    "$DONOR_CORE/quic.c" "$DONOR_CORE/quicwire.c" "$DONOR_CORE/crypto.c" \
    "$DONOR_CORE/tls13core.c" "$DONOR_CORE/x25519.c" "$DONOR_CORE/tls13.c" \
    "$DONOR_CORE/p256.c" "$DONOR_CORE/quichello.c" "$DONOR_CORE/hello.c" \
    "$DONOR_CORE/quicsnap.c" "$DONOR_CORE/quicsnap_reseal.c" \
    "$DONOR_CORE/meas.c" "$DONOR_CORE/net4.c" "$DONOR_CORE/ipfrag.c" \
    -pthread -Wl,--gc-sections -o "$TEMP/d2o-quic-data-stage"

cd "$ROOT"
D2O_QUIC_DATA_STAGE_BIN="$TEMP/d2o-quic-data-stage" \
    cargo +1.98.0 test -p r2o-controller --test r2o_quic_http3 \
        --locked --offline -- --include-ignored --test-threads=1
