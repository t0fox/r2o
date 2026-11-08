#!/bin/sh
# A9: обрыв клиента не завершает serve; следующий клиент обслуживается.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-panel-disconnect.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c11 -O2 -Wall -Wextra -pthread -D_POSIX_C_SOURCE=200809L \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-disconnect" \
    "$ROOT/crates/r2o-panel/tests/d2o_client_disconnect.c" \
    "$D2O_ROOT/panel/server.c"
"$TEMP/d2o-disconnect" > "$TEMP/c.trace"

R2O_PANEL_DISCONNECT_RUST_TRACE="$TEMP/rust.trace" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-panel --lib d2o_client_disconnect_keeps_serve_alive \
        -- --ignored > "$TEMP/rust.log" 2>&1
grep -q 'test result: ok. 1 passed' "$TEMP/rust.log" || {
    cat "$TEMP/rust.log" >&2
    exit 1
}

if ! cmp "$TEMP/c.trace" "$TEMP/rust.trace"; then
    cat "$TEMP/c.trace" >&2
    cat "$TEMP/rust.trace" >&2
    exit 1
fi

printf 'PASS: D2O/Rust survive a client abort and serve the next request (D2O %s)\n' "$ACTUAL_D2O_SHA"
