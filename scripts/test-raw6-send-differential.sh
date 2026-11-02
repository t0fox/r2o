#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
D2O_ROOT=/mnt/e/r2o-tooling/d2o-current-main
EXPECTED_D2O_SHA=a63d9641f4e00aa35fa1e5ccbda47bb5f310c0fe
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
[ "$ACTUAL_D2O_SHA" = "$EXPECTED_D2O_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
}
[ "$(uname -s)" = Linux ] || {
    echo "IPv6 raw-send differential requires Linux" >&2
    exit 77
}

TOOLING_ROOT=$(dirname "$ROOT")/r2o-tooling
CARGO_HOME=$TOOLING_ROOT/linux-cargo
RUSTUP_HOME=$TOOLING_ROOT/linux-rustup
CARGO_TARGET_DIR=$TOOLING_ROOT/linux-target
TMPDIR=$TOOLING_ROOT/tests
PATH=$CARGO_HOME/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR TMPDIR PATH

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-raw6-differential.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

cc -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-raw6-send" \
    "$ROOT/crates/r2o-datapath/tests/d2o_raw6_send_oracle.c" \
    "$D2O_ROOT/datapath/raw.c" "$D2O_ROOT/datapath/wire_udp.c" \
    "$D2O_ROOT/core/ipfrag.c"

cd "$ROOT"
D2O_RAW6_SEND_ORACLE_BIN="$TEMP/d2o-raw6-send" \
    cargo +1.98.0 test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-datapath --test raw6_differential \
        -- --include-ignored --exact ipv6_raw_send_matches_d2o_on_live_loopback \
        --test-threads=1
