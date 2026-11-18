#!/bin/sh
# C/Rust differential: d2k_stun_request (core/stun.c:27-45) и
# d2k_t13_random (core/tls13core.c:21-27).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CORE="$DONOR/core"
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-stun-request.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror \
    -Wno-unused-function -Wno-unused-variable \
    -ffunction-sections -fdata-sections \
    -I"$CORE" -I"$CORE/include" -I"$DONOR/datapath/include" \
    "$ROOT/crates/r2o-controller/tests/d2o_stun_request_differential.c" \
    "$CORE/tls13core.c" \
    -Wl,--gc-sections -lpthread -lm -o "$TEMP/c"

"$TEMP/c" >"$TEMP/c.out"
R2O_STUN_REQUEST_OUTPUT="$TEMP/rust.out" \
    cargo test --locked -p r2k-core --lib \
    stun::tests::stun_request_matches_c -- --exact \
    >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'PASS: STUN request and t13 random match C (%s, %s lines)\n' \
    "$ACTUAL_SHA" "$(wc -l <"$TEMP/c.out" | tr -d ' ')"
