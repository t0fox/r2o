#!/bin/sh
# C/Rust differential: решение http_search_portal (d2kc.c).
# C-оракул — production `http_search_portal`; приёмник `d2k_httpsearch_portal`
# подменён счётчиком. Rust — production `r2o_http_search_https_action`,
# где Queue означает тот же вызов портала.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CC=${CC:-cc}
CORE="$DONOR/core"
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-http-portal.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$CORE" -I"$CORE/include" -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
    -DD2K_RELEASE_ID='"dev"' \
    "$ROOT/crates/r2o-controller/tests/d2o_http_search_portal_differential.c" \
    "$CORE/httpsprobe.c" \
    -Wl,--gc-sections -lpthread -o "$TEMP/c"

"$TEMP/c" >"$TEMP/c.out"
R2O_HTTP_PORTAL_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --locked -p r2o-controller --bin r2o-controller \
    tests::http_search_portal_state_matches_c -- --exact >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'PASS: http_search_portal states match C (%s)\n' "$ACTUAL_SHA"
