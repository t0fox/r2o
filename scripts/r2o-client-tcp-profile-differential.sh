#!/bin/sh
# C/Rust differential: `client_tcp_profile` (core/sched.c:2413-2431).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-client-tcp-profile.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror \
    -Wno-unused-function -Wno-unused-variable \
    -ffunction-sections -fdata-sections \
    -I"$CORE" -I"$CORE/include" -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
    -DD2K_RELEASE_ID='"dev"' \
    "$ROOT/crates/r2o-controller/tests/d2o_client_tcp_profile_differential.c" \
    "$CORE/catalog.c" "$CORE/groups.c" "$CORE/domain.c" \
    -Wl,--gc-sections -lpthread -lm -o "$TEMP/c"

"$TEMP/c" >"$TEMP/c.out"
R2O_CLIENT_TCP_PROFILE_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --locked -p r2k-core --test client_tcp_profile \
    -- --exact client_tcp_profile_matches_c \
    >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'PASS: client_tcp_profile matches C (%s, %s cases)\n' \
    "$ACTUAL_SHA" "$(wc -l <"$TEMP/c.out" | tr -d ' ')"
