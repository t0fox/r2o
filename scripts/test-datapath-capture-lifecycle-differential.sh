#!/bin/sh
set -eu

R2O_ROOT=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
R2O_TOOL_HOME=${R2O_TOOL_HOME:-"${R2O_ROOT%/*}/r2o-tooling"}
D2O_ROOT=${D2O_ROOT:-"$R2O_TOOL_HOME/d2o-current-main"}
EXPECTED_D2O_SHA=a63d9641f4e00aa35fa1e5ccbda47bb5f310c0fe
[ "$(git -C "$D2O_ROOT" rev-parse HEAD)" = "$EXPECTED_D2O_SHA" ] || {
    echo "expected current D2O main $EXPECTED_D2O_SHA" >&2
    exit 2
}

CC=${CC:-cc}
R2O_TEST_TMPDIR=${R2O_TEST_TMPDIR:-"$R2O_TOOL_HOME/tests"}
mkdir -p "$R2O_TEST_TMPDIR"
r2o_capture_tmp=$(mktemp -d "$R2O_TEST_TMPDIR/r2o-capture-lifecycle.XXXXXX")
trap 'rm -rf -- "$r2o_capture_tmp"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I "$D2O_ROOT/datapath/include" -I "$D2O_ROOT/core/include" \
    -o "$r2o_capture_tmp/d2o-capture-lifecycle" \
    "$R2O_ROOT/crates/r2o-datapath/tests/d2o_capture_lifecycle_differential.c" \
    "$D2O_ROOT/datapath/capture.c"
"$r2o_capture_tmp/d2o-capture-lifecycle" >"$r2o_capture_tmp/c.out"

RUST_TEST_THREADS=1 cargo +1.98.0 test --locked -p r2o-datapath --lib \
    capture::tests::capture_ -- --nocapture \
    >"$r2o_capture_tmp/rust.log"
sed -n 's/.*TRACE //p' "$r2o_capture_tmp/rust.log" >"$r2o_capture_tmp/rust.out"
diff -u "$r2o_capture_tmp/c.out" "$r2o_capture_tmp/rust.out"
cat "$r2o_capture_tmp/c.out"
printf '%s\n' 'D2O/R2O capture lifecycle traces match for reordered reassembly, absolute TTL, full-table reuse and size boundary.'
