#!/bin/sh
# C/Rust differential: ctnetlink down (socket(AF_NETLINK, NETLINK_NETFILTER)
# возвращает EAFNOSUPPORT). Проверяется, что open даёт None/-1 и не падает.
set -eu

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
TEMP=$(mktemp -d "$TMPDIR/r2o-ct-open-down.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$DONOR_DATAPATH/include" \
    -o "$TEMP/d2o-ct-open-down" \
    "$ROOT/crates/r2o-datapath/tests/d2o_ct_open_down_differential.c" \
    "$DONOR_DATAPATH/ctq.c" "$DONOR_DATAPATH/nl.c"
"$CC" -shared -fPIC -O2 -Wall -Wextra -Werror \
    -o "$TEMP/ct-down.so" \
    "$ROOT/crates/r2o-datapath/tests/ct_socket_down_preload.c" -ldl

cd "$ROOT"
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --test d2o_conntrack --no-run >"$TEMP/build.log" 2>&1
RUST_BIN=$(sed -n 's/.*Executable tests\/d2o_conntrack.rs (\(.*\))/\1/p' \
    "$TEMP/build.log" | tail -1)
if [ -z "$RUST_BIN" ]; then
    echo "не найден тестовый бинарник d2o_conntrack" >&2
    cat "$TEMP/build.log" >&2
    exit 2
fi
case "$RUST_BIN" in
    /*) ;;
    *) RUST_BIN="$ROOT/$RUST_BIN" ;;
esac

LD_PRELOAD="$TEMP/ct-down.so" "$TEMP/d2o-ct-open-down" >"$TEMP/c.out"
LD_PRELOAD="$TEMP/ct-down.so" \
    R2O_CT_OPEN_DOWN_DIFF_OUTPUT="$TEMP/rust.out" \
    "$RUST_BIN" --ignored --exact ct_open_down_differential_matches_c \
    >"$TEMP/rust.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: ctnetlink down C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
