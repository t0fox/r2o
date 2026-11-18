#!/bin/sh
# C field-by-field oracle request_page_budget против production
# r2o_request_page_budget_from_state. 9 кейсов: same-origin/external redirect,
# challenge, denied-451, complete-2xx, short-body, keepalive-pass, conn-close,
# silence.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT}
EXPECTED_D2O_SHA=${R2O_EXPECTED_DONOR_SHA:-7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05}
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-request-budget.XXXXXX")
cleanup() {
    status=$?
    rm -rf -- "$TEMP"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -DD2K_RELEASE_ID='"dev"' \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/runtime" \
    -o "$TEMP/d2o-request-budget" \
    "$ROOT/crates/r2o-controller/tests/d2o_request_page_budget_differential.c" \
    "$D2O_ROOT/core/diagnostics.c" -Wl,--gc-sections -pthread
"$TEMP/d2o-request-budget" >"$TEMP/c.out"
cat "$TEMP/c.out"

R2O_REQUEST_PAGE_BUDGET_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib \
    fetch::tests::request_page_budget_c_differential_matches_c \
    -- --exact >"$TEMP/rust-diff.log" 2>&1
diff -u "$TEMP/c.out" "$TEMP/rust.out"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib same_origin_redirects_are_safe_and_portals_match_donor_signatures \
    -- --exact >"$TEMP/rust-redirect.log" 2>&1
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib r2o_fetch_отличает_точный_cf_challenge_от_похожих_заголовков \
    -- --exact >"$TEMP/rust-challenge.log" 2>&1
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib budget_repeats_reuse_the_actual_redirected_request_like_c \
    -- --exact >"$TEMP/rust-keepalive.log" 2>&1

printf 'PASS: C request_page_budget oracle and Rust production builder match (13 cases, D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
