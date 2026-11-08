#!/bin/sh
# A13: структура /api/status — snapshot keys, stages/absent order, unknown_keys.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-panel-status-structure.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/state"

"$CC" -std=c11 -O2 -Wall -Wextra -pthread -D_POSIX_C_SOURCE=200809L \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-status-structure" \
    "$ROOT/crates/r2o-panel/tests/d2o_status_structure.c" \
    "$D2O_ROOT/panel/server.c"
"$TEMP/d2o-status-structure" "$TEMP/state" > "$TEMP/c.json"

R2O_PANEL_STATUS_STATE_DIR="$TEMP/state" \
R2O_PANEL_STATUS_RUST_BODY="$TEMP/rust.json" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-panel --test http d2o_status_snapshot_structure_matches \
        -- --ignored > "$TEMP/rust.log" 2>&1
grep -q 'test result: ok. 1 passed' "$TEMP/rust.log" || {
    cat "$TEMP/rust.log" >&2
    exit 1
}

python3 "$ROOT/scripts/fixtures/compare_panel_status.py" "$TEMP/c.json" "$TEMP/rust.json"

printf 'PASS: D2O/Rust /api/status snapshot keys, stage order and unknown_keys match (D2O %s)\n' "$ACTUAL_D2O_SHA"
