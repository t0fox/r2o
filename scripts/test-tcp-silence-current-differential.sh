#!/bin/sh
set -eu

R2O_ROOT=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-"${R2O_ROOT%/*}/d2o"}
EXPECTED_D2O_SHA=a63d9641f4e00aa35fa1e5ccbda47bb5f310c0fe
[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    echo "expected current D2O main $EXPECTED_D2O_SHA" >&2
    exit 2
}
[ "$(uname -s)" = Linux ] || {
    echo "TCP silence differential requires Linux" >&2
    exit 77
}

TMPDIR=${TMPDIR:-/tmp}
CC=${CC:-cc}
mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-tcp-silence-current.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -B -C "$D2O_ROOT/datapath" test_session CC="$CC"
"$D2O_ROOT/datapath/test_session"

(
    cd "$D2O_ROOT/datapath"
    "$CC" -std=c99 -O2 -Wall -Wextra -Werror -I. -Iinclude -I../core/include \
        -DD2K_RELEASE_ID='"dev"' \
        -o "$TEMP/d2o-tcp-silence" \
        "$R2O_ROOT/crates/r2o-datapath/tests/d2o_tcp_silence_differential.c" \
        session.o http80.o hold.o capture.o nat.o ctq.o nl.o track.o tls.o \
        wire.o wire_udp.o journal.o plans.o plan_parse.o plan_apply.o \
        core_quic.o core_quicwire.o core_quicsnap.o core_crypto.o core_ipfrag.o \
        core_httpup_logic.o
)

"$TEMP/d2o-tcp-silence" >"$TEMP/c.out"
R2O_TCP_SILENCE_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test -p r2o-datapath --lib \
        tcp_silence_shared_lifecycle_matches_current_d2o --locked --offline
diff -u "$TEMP/c.out" "$TEMP/rust.out"
cat "$TEMP/c.out"
printf 'D2O/R2O TCP silence sweep, expiry, close, retry and per-flow visibility match.\n'
