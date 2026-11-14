#!/bin/sh
# C/Rust differential: обязательность групп rtnetlink watch (8/7) и
# необязательность IPv6 (19/11), плюс возврат ошибки при отказе IPv4.
#
# setsockopt(NETLINK_ADD_MEMBERSHIP) подменяется LD_PRELOAD-шимом.
set -eu

if [ -z "${R2O_IN_USERNS:-}" ] && [ "$(id -u)" -ne 0 ]; then
    R2O_IN_USERNS=1 exec unshare -Urn sh "$0" "$@"
fi

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
DONOR_DATAPATH=${R2O_DONOR_DATAPATH:-"$D2O_ROOT/datapath"}
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-route-watch.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$DONOR_DATAPATH/include" -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-route-watch" \
    "$ROOT/crates/r2o-datapath/tests/d2o_route_watch_differential.c" \
    "$DONOR_DATAPATH/routemark_nl.c" "$DONOR_DATAPATH/routemark.c" \
    "$DONOR_DATAPATH/nl.c" -lm
"$CC" -shared -fPIC -O2 -Wall -Wextra -Werror \
    -o "$TEMP/watch-fail.so" \
    "$ROOT/crates/r2o-datapath/tests/watch_group_fail_preload.c" -ldl

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib --no-run >"$TEMP/build.log" 2>&1
RUST_BIN=$(sed -n 's/.*Executable unittests src\/lib.rs (\(.*\))/\1/p' "$TEMP/build.log" | tail -1)
if [ -z "$RUST_BIN" ]; then
    echo "не найден тестовый бинарник r2o-datapath lib" >&2
    cat "$TEMP/build.log" >&2
    exit 2
fi

: >"$TEMP/c.out"
: >"$TEMP/rust.out"
for scenario in ok ipv4_rule ipv4_route ipv6_rule ipv6_route; do
    case "$scenario" in
        ok) group= ;;
        ipv4_rule) group=8 ;;
        ipv4_route) group=7 ;;
        ipv6_rule) group=19 ;;
        ipv6_route) group=11 ;;
    esac
    FAKE_WATCH_SCENARIO="$scenario" FAKE_WATCH_FAIL_GROUP="$group" \
        LD_PRELOAD="$TEMP/watch-fail.so" \
        "$TEMP/d2o-route-watch" >>"$TEMP/c.out"
    FAKE_WATCH_SCENARIO="$scenario" FAKE_WATCH_FAIL_GROUP="$group" \
        LD_PRELOAD="$TEMP/watch-fail.so" \
        R2O_WATCH_DIFF_OUTPUT="$TEMP/one.out" \
        "$RUST_BIN" --exact --nocapture \
        r2o_route::tests::r2o_watch_open_differential_matches_c \
        >"$TEMP/run.log" 2>&1
    cat "$TEMP/one.out" >>"$TEMP/rust.out"
done

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: rtnetlink watch group requirements C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
