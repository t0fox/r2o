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
    echo "ICMP guard differential requires Linux" >&2
    exit 77
}

CC=${CC:-cc}
TEMP_BASE=${TMPDIR:-"$R2O_ROOT/target"}
mkdir -p "$TEMP_BASE"
TEMP=$(mktemp -d "$TEMP_BASE/r2o-icmp-guard-current.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -B -C "$D2O_ROOT/datapath" test-icmpguard CC="$CC"
(
    cd "$D2O_ROOT/datapath"
    "$CC" -std=c99 -O2 -Wall -Wextra -Werror -Iinclude \
        -o "$TEMP/d2o-icmp-guard" \
        "$R2O_ROOT/crates/r2o-datapath/tests/d2o_icmp_guard_differential.c" \
        icmpguard.o
)

"$TEMP/d2o-icmp-guard" >"$TEMP/c.out"
R2O_ICMP_GUARD_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test -p r2o-datapath --test r2o_icmp_guard \
        r2o_periodic_icmp_summary_matches_d2o_fields --locked --offline
diff -u "$TEMP/c.out" "$TEMP/rust.out"
cat "$TEMP/c.out"
printf 'Current D2O/R2O ICMP summary counters and line match.\n'
