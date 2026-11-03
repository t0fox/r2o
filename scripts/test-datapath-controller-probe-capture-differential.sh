#!/bin/sh
set -eu

R2O_ROOT=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
R2O_TOOL_HOME=${R2O_TOOL_HOME:-"${R2O_ROOT%/*}/r2o-tooling"}
D2O_ROOT=${R2O_DONOR_ROOT:-"$R2O_TOOL_HOME/d2o-current-main"}
EXPECTED_D2O_SHA=a63d9641f4e00aa35fa1e5ccbda47bb5f310c0fe
[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    echo "expected current D2O main $EXPECTED_D2O_SHA" >&2
    exit 2
}
[ "$(uname -s)" = Linux ] || {
    echo "controller-probe capture differential requires Linux" >&2
    exit 77
}

CC=${CC:-cc}
R2O_TEST_TMPDIR=${R2O_TEST_TMPDIR:-"$R2O_TOOL_HOME/tests"}
mkdir -p "$R2O_TEST_TMPDIR"
r2o_capture_tmp=$(mktemp -d "$R2O_TEST_TMPDIR/r2o-controller-probe-capture.XXXXXX")
trap 'rm -rf -- "$r2o_capture_tmp"' EXIT HUP INT TERM

make -C "$D2O_ROOT/datapath" test_session CC="$CC"
(
    cd "$D2O_ROOT/datapath"
    "$CC" -std=c99 -O2 -Wall -Wextra -Werror -I. -Iinclude -I../core/include \
        -DD2K_RELEASE_ID='"dev"' \
        -o "$r2o_capture_tmp/d2o-capture-probe" \
        "$R2O_ROOT/crates/r2o-datapath/tests/d2o_controller_probe_capture_metrics_differential.c" \
        session.o http80.o hold.o capture.o nat.o ctq.o nl.o track.o tls.o \
        wire.o wire_udp.o journal.o plans.o plan_parse.o plan_apply.o \
        core_quic.o core_quicwire.o core_quicsnap.o core_crypto.o core_ipfrag.o \
        core_httpup_logic.o
)
"$r2o_capture_tmp/d2o-capture-probe" >"$r2o_capture_tmp/c.out"

CARGO_HOME=${CARGO_HOME:-"$R2O_TOOL_HOME/linux-cargo"}
RUSTUP_HOME=${RUSTUP_HOME:-"$R2O_TOOL_HOME/linux-rustup"}
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$R2O_TOOL_HOME/linux-target"}
PATH="$CARGO_HOME/bin:$RUSTUP_HOME/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin:/usr/bin:/bin"
export CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR PATH
R2O_CAPTURE_PROBE_DIFF_OUTPUT="$r2o_capture_tmp/rust.out" \
    cargo +1.98.0 test --locked --offline -p r2o-datapath --lib \
        hold::tests::controller_probe_capture_counts_like_d2o_without_incomplete_diagnostics -- --exact

diff -u "$r2o_capture_tmp/c.out" "$r2o_capture_tmp/rust.out"
cat "$r2o_capture_tmp/c.out"
echo 'D2O/R2O controller-probe capture metrics match for split and single ClientHello paths.'