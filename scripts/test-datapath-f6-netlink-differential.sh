#!/bin/sh
# C/Rust differential: d2k_f6_route/d2k_f6_neighbor на инъекции rtnetlink.
#
# LD_PRELOAD-шим подменяет socket/sendto/recvfrom/setsockopt/close и отдаёт
# заранее собранные ответы: NLMSG_ERROR (включая короткий и положительный),
# EAGAIN, пустой ответ, RTN_LOCAL, RTN_UNICAST без RTA_OIF/GATEWAY, короткие
# RTA_OIF/RTA_GATEWAY, чужой sequence, не-IPv6/не-unicast; neighbor —
# NUD STALE/DELAY/PROBE/REACHABLE/PERMANENT/INCOMPLETE, отсутствующий/короткий
# NDA_LLADDR, короткий NDA_DST, чужой ifindex, пустой dump, NLMSG_DONE/ERROR,
# 64 батча и 200-мс timeout.
#
# Никакого root/netns не требуется: запросы и ответы проверяются побайтно.
set -eu

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
TEMP=$(mktemp -d "$TMPDIR/r2o-f6-netlink.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-f6" \
    "$ROOT/crates/r2o-datapath/tests/d2o_f6_netlink_differential.c" -lm
"$CC" -shared -fPIC -O2 -Wall -Wextra -Werror \
    -o "$TEMP/f6-shim.so" \
    "$ROOT/crates/r2o-datapath/tests/f6_netlink_shim.c" -ldl

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

: >"$TEMP/c.out"
: >"$TEMP/rust.out"
: >"$TEMP/c.log"
: >"$TEMP/rust.log"
for scenario in \
    route_success route_error route_empty route_local route_no_oif \
    route_no_gateway route_mark route_wrong_seq route_nonipv6 \
    route_nonunicast route_short_oif route_error_short route_error_positive \
    route_eagain route_short_gateway route_bad_source \
    neighbor_stale neighbor_delay neighbor_probe neighbor_reachable \
    neighbor_permanent neighbor_no_lladdr neighbor_short_lladdr \
    neighbor_wrong_ifindex neighbor_empty neighbor_done neighbor_batch64 \
    neighbor_eagain neighbor_error neighbor_incomplete neighbor_nonipv6 \
    neighbor_dst_short neighbor_timeout neighbor_bad_source
do
    rm -f "$TEMP/one.out" "$TEMP/one.log"
    R2O_F6_SCENARIO="$scenario" R2O_F6_SHIM_LOG="$TEMP/one.log" \
        LD_PRELOAD="$TEMP/f6-shim.so" "$TEMP/d2o-f6" >"$TEMP/one.out"
    cat "$TEMP/one.out" >>"$TEMP/c.out"
    cat "$TEMP/one.log" >>"$TEMP/c.log"

    rm -f "$TEMP/one.out" "$TEMP/one.log"
    R2O_F6_SCENARIO="$scenario" R2O_F6_SHIM_LOG="$TEMP/one.log" \
        R2O_F6_DIFF_OUTPUT="$TEMP/one.out" \
        LD_PRELOAD="$TEMP/f6-shim.so" \
        "$RUST_BIN" --ignored --exact --nocapture \
        raw::tests::f6_netlink_differential_matches_c \
        >"$TEMP/rust-$scenario.log" 2>&1
    cat "$TEMP/one.out" >>"$TEMP/rust.out"
    cat "$TEMP/one.log" >>"$TEMP/rust.log"
done

diff -u "$TEMP/c.out" "$TEMP/rust.out"
diff -u "$TEMP/c.log" "$TEMP/rust.log"
printf 'cases=%s\n' "$(grep -c '^route ' "$TEMP/c.out")"
printf 'PASS: f6 route/neighbor netlink C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
