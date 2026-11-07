#!/bin/sh
# A8: C/Rust differential абсолютного 5-секундного дедлайна ответа панели.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
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
TEMP=$(mktemp -d "$TMPDIR/r2o-panel-response-deadline.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c11 -O2 -Wall -Wextra -pthread -D_POSIX_C_SOURCE=200809L \
    -I"$D2O_ROOT/panel" -o "$TEMP/d2o-response-deadline" \
    "$D2O_ROOT/panel/test_response_deadline.c"
"$TEMP/d2o-response-deadline" | tee "$TEMP/c.trace"

"$CARGO" test --quiet --locked --offline -p r2o-panel --lib \
    d2o_response_deadline_matches_rust_sender -- --ignored --nocapture \
    2>&1 | tee "$TEMP/rust.trace"
grep -q 'R2O_RESPONSE_DEADLINE rc=true elapsed_ms=' "$TEMP/rust.trace"
elapsed=$(sed -n 's/.*elapsed_ms=\([0-9][0-9]*\).*/\1/p' "$TEMP/rust.trace" | head -n 1)
[ -n "$elapsed" ] && [ "$elapsed" -ge 4900 ] || {
    echo "Rust response deadline was not absolute: ${elapsed:-missing} ms" >&2
    exit 1
}
printf 'PASS: C and Rust enforce an absolute ~5s response deadline (D2O %s)\n' "$ACTUAL_D2O_SHA"
