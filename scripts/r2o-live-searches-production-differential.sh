#!/bin/sh
# C/Rust differential: production-builder `searches` (main.rs
# r2o_live_searches_from_state) против C d2k_sched_write_live.
# Один state со всеми шестью task-state; T_WATCHING/T_RESTING исключены.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
fi
CC=${CC:-cc}
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-live-searches.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -ffunction-sections -fdata-sections \
    -I"$DONOR/core" -I"$DONOR/core/include" -I"$DONOR/datapath/include" \
    -I"$DONOR/runtime" \
    -o "$TEMP/c" \
    "$ROOT/crates/r2o-controller/tests/d2o_live_searches_differential.c" \
    "$DONOR/core/catalog.c" "$DONOR/core/groups.c" "$DONOR/core/domain.c" \
    -Wl,--gc-sections -lpthread -lm
"$TEMP/c" >"$TEMP/c.json"

R2O_LIVE_SEARCHES_DIFF_OUTPUT="$TEMP/rust.json" \
    cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    live_searches_production_builder_matches_c_task_states \
    >"$TEMP/rust.log" 2>&1

python3 - "$TEMP/c.json" "$TEMP/rust.json" <<'PY'
import json
import sys

full = json.load(open(sys.argv[1], encoding="utf-8"))
c = full["searches"]
r = json.load(open(sys.argv[2], encoding="utf-8"))
if c != r:
    print("C:", json.dumps(c, ensure_ascii=False, sort_keys=True, indent=2))
    print("R:", json.dumps(r, ensure_ascii=False, sort_keys=True, indent=2))
    raise SystemExit(1)
print(f"PASS: production live searches match C for {len(c)} active task states")
PY
