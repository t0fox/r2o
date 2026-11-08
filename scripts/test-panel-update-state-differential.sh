#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-${ROOT%/*}/d2o}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected d2o %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TEMP_BASE=${R2O_TEST_TMP:-${ROOT%/*}/r2o-tooling/tmp}
if [ ! -d "$TEMP_BASE" ]; then
    TEMP_BASE=${TMPDIR:-/tmp}
fi
TEMP=$(mktemp -d "$TEMP_BASE/r2o-panel-update-state.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

CC=${CC:-cc}
"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-update-state" \
    "$ROOT/crates/r2o-panel/tests/d2o_update_state.c"

printf '#!/bin/sh\nexit 0\n' > "$TEMP/updater"
chmod 0755 "$TEMP/updater"
printf '%s\n' '{"release_id":"r2o-1","checked_utc":1}' > "$TEMP/state-valid.json"
printf '%s\n' '[]' > "$TEMP/state-invalid.json"
printf '%s\n' '{broken' > "$TEMP/state-broken.json"

body() {
    trace=$1
    output=$2
    python3 - "$trace" "$output" <<'PY'
from pathlib import Path
import sys
raw = Path(sys.argv[1]).read_bytes()
head, _, body = raw.partition(b"\r\n\r\n")
if not body:
    raise SystemExit("missing HTTP body")
Path(sys.argv[2]).write_bytes(body)
PY
}

"$TEMP/d2o-update-state" - - > "$TEMP/absent.trace"
body "$TEMP/absent.trace" "$TEMP/absent.body"
"$TEMP/d2o-update-state" "$TEMP/updater" "$TEMP/state-missing.json" > "$TEMP/never.trace"
body "$TEMP/never.trace" "$TEMP/never.body"
"$TEMP/d2o-update-state" "$TEMP/updater" "$TEMP/state-valid.json" > "$TEMP/valid.trace"
body "$TEMP/valid.trace" "$TEMP/valid.body"
"$TEMP/d2o-update-state" "$TEMP/updater" "$TEMP/state-invalid.json" > "$TEMP/invalid.trace"
body "$TEMP/invalid.trace" "$TEMP/invalid.body"
"$TEMP/d2o-update-state" "$TEMP/updater" "$TEMP/state-broken.json" > "$TEMP/broken.trace"
body "$TEMP/broken.trace" "$TEMP/broken.body"

[ "$(cat "$TEMP/absent.body")" = '{"absent":true}' ] || {
    echo "unexpected C absent body: $(cat "$TEMP/absent.body")" >&2
    exit 1
}
[ "$(cat "$TEMP/never.body")" = '{"never":true}' ] || {
    echo "unexpected C never body: $(cat "$TEMP/never.body")" >&2
    exit 1
}
[ "$(cat "$TEMP/invalid.body")" = '{"never":true}' ] || {
    echo "unexpected C invalid body: $(cat "$TEMP/invalid.body")" >&2
    exit 1
}
[ "$(cat "$TEMP/broken.body")" = '{"never":true}' ] || {
    echo "unexpected C broken body: $(cat "$TEMP/broken.body")" >&2
    exit 1
}

export R2O_PANEL_UPDATE_UPDATER="$TEMP/updater"
export R2O_PANEL_UPDATE_STATE_VALID="$TEMP/state-valid.json"
export R2O_PANEL_UPDATE_STATE_INVALID="$TEMP/state-invalid.json"
export R2O_PANEL_UPDATE_STATE_BROKEN="$TEMP/state-broken.json"
export R2O_PANEL_UPDATE_ABSENT_C="$TEMP/absent.body"
export R2O_PANEL_UPDATE_NEVER_C="$TEMP/never.body"
export R2O_PANEL_UPDATE_VALID_C="$TEMP/valid.body"
export R2O_PANEL_UPDATE_INVALID_C="$TEMP/invalid.body"
export R2O_PANEL_UPDATE_BROKEN_C="$TEMP/broken.body"

CARGO=${CARGO:-cargo}
CARGO_HOME=${R2O_CARGO_HOME:-$HOME/.cargo} \
RUSTUP_HOME=${R2O_RUSTUP_HOME:-$HOME/.rustup} \
CARGO_TARGET_DIR=${R2O_CARGO_TARGET_DIR:-$HOME/r2o-target} \
    "$CARGO" test -p r2o-panel --test http --locked --offline \
        d2o_update_state_matches_rust_route -- --ignored --nocapture

echo "C/Rust update-state responses match d2o $ACTUAL_D2O_SHA."
