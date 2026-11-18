#!/bin/sh
# C/Rust differential: d2kc main — запуск, CLI и приветствие датапата.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
[ -x "$DONOR/core/d2kc" ] || make -s -C "$DONOR/core" d2kc
cargo build --locked -q -p r2o-controller --bin r2o-controller
R2O_DONOR_ROOT="$DONOR" python3 "$ROOT/scripts/r2o-serve-cli-differential.py"
