#!/bin/sh
# C/Rust differential: ENOBUFS NFQUEUE при переполнении SO_RCVBUF.
#
# Детерминированный стенд без внешнего флуда: nft отправляет 512 UDP-
# датаграмм по 60 КиБ в очередь, сокет открыт с rcvbuf=4096 и copy_range=
# 0xffff. Ядро переполняет приёмный буфер netlink и возвращает ENOBUFS.
# C `d2k_nfq_recv` обязан вернуть -2 и увеличить lost; Rust
# `receive_timeout` — `ReceiveError::LostPackets` и `lost_packets()`.
set -eu

if [ -z "${R2O_IN_USERNS:-}" ] && [ "$(id -u)" -ne 0 ]; then
    R2O_IN_USERNS=1 exec unshare -Urn sh "$0" "$@"
fi

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

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-enobufs.XXXXXX")
cleanup() {
    nft delete table inet r2o_enobufs_c 2>/dev/null || true
    nft delete table inet r2o_enobufs 2>/dev/null || true
    rm -rf -- "$TEMP"
}
trap cleanup EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-enobufs" \
    "$ROOT/crates/r2o-datapath/tests/d2o_nfq_enobufs_differential.c" \
    "$D2O_ROOT/datapath/nfq.c" "$D2O_ROOT/datapath/nl.c"

ip link set lo up
nft delete table inet r2o_enobufs_c 2>/dev/null || true
nft add table inet r2o_enobufs_c
nft 'add chain inet r2o_enobufs_c out { type filter hook output priority 0; }'
nft add rule inet r2o_enobufs_c out udp dport 9998 queue num 65002 bypass

cd "$ROOT"
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib --no-run >"$TEMP/build.log" 2>&1
RUST_BIN=$(sed -n 's/.*Executable unittests src\/lib.rs (\(.*\))/\1/p' "$TEMP/build.log" | tail -1)
if [ -z "$RUST_BIN" ]; then
    echo "не найден тестовый бинарник r2o-datapath lib" >&2
    cat "$TEMP/build.log" >&2
    exit 2
fi
case "$RUST_BIN" in
    /*) ;;
    *) RUST_BIN="$ROOT/$RUST_BIN" ;;
esac

"$TEMP/d2o-enobufs" >"$TEMP/c.out"
R2O_NFQ_ENOBUFS_DIFF_OUTPUT="$TEMP/rust.out" \
    "$RUST_BIN" --ignored --exact --nocapture \
    nfqueue::tests::enobufs_rcvbuf_overflow_is_deterministic \
    >"$TEMP/rust.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=1\n'
printf 'PASS: NFQUEUE ENOBUFS C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
