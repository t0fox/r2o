#!/bin/sh
# C/Rust differential: d2k_hs_probe_run response framing/judge branches.
#
# C-оракул — current main `core/verify.c` + `core/httpsearch.c`; Rust —
# production `http_search::read_probe_response` в tests/http_search.rs.
# Покрыты: body/101/CL+TE/4-KiB judge/close-delimited/таймаут в теле.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the current D2O checkout}
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
TEMP=$(mktemp -d "$TMPDIR/r2o-http-search-response.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

(
    cd "$D2O_ROOT/core"
    "$CC" -std=c99 -O2 -Wall -Wextra -Werror -DD2K_HS_TESTING \
        -Iinclude -I../datapath/include \
        -o "$TEMP/http-response-state" \
        "$ROOT/crates/r2o-controller/tests/d2o_http_response_state_differential.c" \
        httpsearch.c httpup_logic.c plantlv.c quic.c quicwire.c crypto.c \
        ../datapath/plan_parse.c ../datapath/plan_apply.c ../datapath/wire.c \
        verify.c quicconn.c h3.c tls12.c p256.c compose.c measured.c \
        hello.c meas.c link.c tls13.c tls13core.c x25519.c diagnostics.c -lpthread
)
"$TEMP/http-response-state" >"$TEMP/c.out"

R2O_HTTP_RESPONSE_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --test http_search \
    d2o_response_state_differential_preserves_portal_and_partial_head_outcomes \
    -- --nocapture >"$TEMP/cargo.log" 2>&1

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: HTTP Search response differential\n' >&2
    exit 1
fi

cat "$TEMP/c.out"
printf 'cases=%s\n' "$(grep -c '=' "$TEMP/c.out")"
printf 'PASS: C/Rust HTTP Search response framing/judge match (D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
