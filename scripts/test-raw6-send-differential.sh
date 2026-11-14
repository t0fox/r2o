#!/bin/sh
# C/Rust differential: живая отправка IPv6 raw-пакетов и фрагментов на loopback.
#
# Требует CAP_NET_RAW/CAP_NET_ADMIN (root или сетевой namespace).
set -eu

ROOT=$(CDPATH='' cd -P "$(dirname -- "$0")/.." && pwd)
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
[ "$(uname -s)" = Linux ] || {
    echo "IPv6 raw-send differential requires Linux" >&2
    exit 77
}

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-raw6-differential.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-raw6-send" \
    "$ROOT/crates/r2o-datapath/tests/d2o_raw6_send_oracle.c" \
    "$D2O_ROOT/datapath/raw.c" "$D2O_ROOT/datapath/wire_udp.c" \
    "$D2O_ROOT/core/ipfrag.c"

cd "$ROOT"
D2O_RAW6_SEND_ORACLE_BIN="$TEMP/d2o-raw6-send" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-datapath --test raw6_differential \
        -- --include-ignored --exact ipv6_raw_send_matches_d2o_on_live_loopback \
        --test-threads=1
printf 'PASS: IPv6 raw-send C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
