#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TEMP_BASE=${R2O_TEST_TMP:-${ROOT%/*}/r2o-tooling/tmp}
[ -d "$TEMP_BASE" ] || { printf 'Temporary directory must exist on E: %s\n' "$TEMP_BASE" >&2; exit 2; }
TEMP=$(mktemp -d "$TEMP_BASE/r2o-panel-static-etag.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/assets"
printf x > "$TEMP/assets/index.html"

CC=${CC:-cc}
"$CC" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
    -D_POSIX_C_SOURCE=200809L \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-static-etag" \
    "$ROOT/crates/r2o-panel/tests/d2o_static_asset_etag.c" \
    "$D2O_ROOT/panel/server.c"
"$TEMP/d2o-static-etag" "$TEMP/assets" > "$TEMP/d2o.trace"
printf 'HTTP/1.1 304\nETag: "1-499602d2"\n' > "$TEMP/d2o.expected"
cmp "$TEMP/d2o.expected" "$TEMP/d2o.trace"

export R2O_PANEL_STATIC_ETAG_DIR="$TEMP/assets"
export R2O_PANEL_STATIC_ETAG_C_TRACE="$TEMP/d2o.trace"
export R2O_PANEL_STATIC_ETAG_RUST_TRACE="$TEMP/rust.trace"
CARGO=${CARGO:-cargo}
"$CARGO" test --quiet --locked --offline -p r2o-panel --lib \
    d2o_static_asset_etag_matches_rust_asset -- --ignored --nocapture
cmp "$TEMP/d2o.trace" "$TEMP/rust.trace"
cat "$TEMP/d2o.trace"
printf '%s\n' 'test-panel-static-etag-differential: D2O and R2O status/ETag match'
