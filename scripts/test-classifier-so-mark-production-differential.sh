#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/r2o}/d2o}
EXPECTED_D2O_SHA=304ba893dd37197128ac8799c0495b035f6a38c0
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
[ "$ACTUAL_D2O_SHA" = "$EXPECTED_D2O_SHA" ] || {
    echo "expected D2O $EXPECTED_D2O_SHA, got $ACTUAL_D2O_SHA" >&2
    exit 2
}
[ "$(uname -s)" = Linux ] || {
    echo "production SO_MARK differential requires Linux sockets" >&2
    exit 77
}

TEMP=$(mktemp -d "${TMPDIR:-/tmp}/r2o-so-mark.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/core" \
    "$ROOT/crates/r2o-controller/tests/d2o_marked_probe_differential.c" \
    "$D2O_ROOT/core/meas.c" -o "$TEMP/d2o"
"$TEMP/d2o" >"$TEMP/c.out"

if R2O_RESPONSE_MARK_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline \
        production_socket_probe_mark_matches_d2o_setsockopt_result -- --nocapture; then
    test_status=0
else
    test_status=$?
fi
[ -f "$TEMP/rust.out" ] || {
    echo "Rust production SO_MARK test produced no result" >&2
    exit "$test_status"
}
diff -u "$TEMP/c.out" "$TEMP/rust.out"
[ "$test_status" -eq 0 ] || exit "$test_status"
cat "$TEMP/rust.out"
