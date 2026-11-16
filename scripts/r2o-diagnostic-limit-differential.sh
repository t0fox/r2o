#!/bin/sh
# C/Rust differential: переходы лимитов диагностики (`limit_transitions`).
# C-оракул — production `d2k_diag_record_limit` + `d2k_diag_write`
# (core/diagnostics.c); Rust — production `limit_event_json`.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CC=${CC:-cc}
CORE="$DONOR/core"
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-diag-limit.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$CORE" -I"$CORE/include" -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
    -DD2K_RELEASE_ID='"dev"' \
    "$ROOT/crates/r2o-controller/tests/d2o_diagnostic_limit_differential.c" \
    "$CORE/diagnostics.c" \
    -Wl,--gc-sections -lpthread -o "$TEMP/c"

"$TEMP/c" >"$TEMP/c.json"
R2O_DIAG_LIMIT_DIFF_OUTPUT="$TEMP/rust.json" \
    cargo test --locked -p r2o-controller --lib \
    diagnostic_limit_transition_matches_c >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }

python3 - "$TEMP/c.json" "$TEMP/rust.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
c_events = report["limit_transitions"]
for event in c_events:
    event["at"] = 0
with open(sys.argv[2], encoding="utf-8") as handle:
    rust_events = json.load(handle)
for event in rust_events:
    event["at"] = 0
if c_events != rust_events:
    print("C:", json.dumps(c_events, ensure_ascii=False, sort_keys=True))
    print("Rust:", json.dumps(rust_events, ensure_ascii=False, sort_keys=True))
    raise SystemExit("FAIL: limit_transitions differ")
print(f"limit_transitions: {len(c_events)} cases match")
PY

printf 'PASS: diagnostic limit transitions match C (%s)\n' "$ACTUAL_SHA"
