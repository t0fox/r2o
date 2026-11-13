#!/bin/sh
# C/Rust differential: write_live_groups (live.json groups).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
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
TEMP=$(mktemp -d "$TMPDIR/r2o-live-groups.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-live-groups" \
    "$ROOT/crates/r2o-controller/tests/d2o_live_groups_differential.c" \
    "$D2O_ROOT/core/groups.c" "$D2O_ROOT/core/domain.c" \
    -Wl,--gc-sections -lpthread -lm
"$TEMP/d2o-live-groups" >"$TEMP/c.json"

R2O_LIVE_GROUPS_DIFF_OUTPUT="$TEMP/rust.json" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib live::tests::live_groups_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

python3 - "$TEMP/c.json" "$TEMP/rust.json" <<'PY'
import json
import sys

c = json.load(open(sys.argv[1], encoding="utf-8"))
r = json.load(open(sys.argv[2], encoding="utf-8"))
if c != r:
    print("C:", json.dumps(c, ensure_ascii=False, sort_keys=True))
    print("R:", json.dumps(r, ensure_ascii=False, sort_keys=True))
    raise SystemExit(1)
print("PASS: live groups C/Rust match")
PY

printf 'cases=%s\n' 1
