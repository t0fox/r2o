#!/bin/sh
# C/Rust differential: d2k_raw_send accounting/error paths (a378).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-raw-send.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/datapath" -I"$D2O_ROOT/datapath/include" \
    -I"$D2O_ROOT/core/include" -ffunction-sections -fdata-sections \
    -o "$TEMP/d2o-raw-send" \
    "$ROOT/crates/r2o-datapath/tests/d2o_raw_send_differential.c" \
    -Wl,--gc-sections
"$CC" -shared -fPIC -O2 -o "$TEMP/fake-sendto.so" \
    "$ROOT/crates/r2o-datapath/tests/fake_sendto.c" -ldl

: >"$TEMP/c.out"
: >"$TEMP/rust.out"
for scenario in ok eintr enobufs emsgsize short invalid; do
    case "$scenario" in
        eintr) plan="EINTR,OK" ;;
        enobufs) plan="ENOBUFS" ;;
        emsgsize) plan="EMSGSIZE" ;;
        short) plan="SHORT" ;;
        *) plan="OK" ;;
    esac
    LD_PRELOAD="$TEMP/fake-sendto.so" FAKE_SENDTO_PLAN="$plan" \
        FAKE_SENDTO_SCENARIO="$scenario" \
        "$TEMP/d2o-raw-send" >>"$TEMP/c.out"
    LD_PRELOAD="$TEMP/fake-sendto.so" FAKE_SENDTO_PLAN="$plan" \
        FAKE_SENDTO_SCENARIO="$scenario" \
        R2O_RAW_SEND_DIFF_OUTPUT="$TEMP/one.out" \
        "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-datapath --lib raw::tests::raw_send_differential_matches_c \
        -- --exact >"$TEMP/cargo.log" 2>&1
    cat "$TEMP/one.out" >>"$TEMP/rust.out"
done

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: d2k_raw_send C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
