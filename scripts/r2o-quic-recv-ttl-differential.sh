#!/bin/sh
# C/Rust differential: qp_recv_ttl — TTL/hop limit входящей датаграммы.
#
# C-сторона включает production core/quicprobe.c и вызывает настоящий
# qp_recv_ttl на loopback-сокетах. Rust-сторона — production
# r2o_controller::recv_ttl. Сравниваются четыре исхода: IPv4 TTL, IPv4 без
# IP_RECVTTL, нулевая датаграмма и IPv6 hop limit.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-/mnt/e/d2o-a378w}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-/tmp}
for tool in "$CC" "$CARGO"; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing required command: %s\n' "$tool" >&2
        exit 127
    }
done

TEMP=$(mktemp -d "$TMPDIR/r2o-quic-recv-ttl.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

if ! "$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" \
    -I"$D2O_ROOT/datapath/include" \
    -DD2K_RELEASE_ID='"dev"' \
    "$ROOT/crates/r2o-controller/tests/d2o_quic_recv_ttl_differential.c" \
    -Wl,--gc-sections -o "$TEMP/c" >"$TEMP/c-build.log" 2>&1; then
    cat "$TEMP/c-build.log" >&2
    exit 1
fi

"$TEMP/c" >"$TEMP/c.out"

if ! R2O_QUIC_RECV_TTL_DIFF_OUTPUT="$TEMP/rust.out" "$CARGO" test \
    --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib \
    recv_ttl::tests::quic_recv_ttl_c_differential_harness -- --exact \
    >"$TEMP/rust.log" 2>&1; then
    cat "$TEMP/rust.log" >&2
    exit 1
fi

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: qp_recv_ttl C/Rust mismatch\n' >&2
    exit 1
fi

printf 'PASS: qp_recv_ttl C/Rust match (%s cases, D2O %s).\n' \
    "$(grep -c '|' "$TEMP/c.out")" "$ACTUAL_D2O_SHA"
