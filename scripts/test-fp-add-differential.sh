#!/bin/sh
# C/Rust differential: fp_add (core/sched.c:1703-1730).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-fp-add.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-fp-add" \
    "$ROOT/crates/r2o-controller/tests/d2o_fp_add_differential.c" \
    "$D2O_ROOT/core/groups.c" "$D2O_ROOT/core/domain.c" \
    -Wl,--gc-sections -lpthread -lm
"$TEMP/d2o-fp-add" >"$TEMP/c.jsonl"

R2O_FP_ADD_DIFF_OUTPUT="$TEMP/rust.jsonl" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --test catalog fp_add_differential_matches_c_sched \
    -- --exact >"$TEMP/cargo.log" 2>&1

python3 - "$TEMP/c.jsonl" "$TEMP/rust.jsonl" <<'PY'
import json
import sys


def load(path):
    rows = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            for signal in row.get("signals", []):
                # Rust намеренно опускает нулевой packets при сериализации.
                signal.setdefault("packets", 0)
            rows.append(row)
    return rows


c = load(sys.argv[1])
r = load(sys.argv[2])
if c != r:
    for left, right in zip(c, r):
        if left != right:
            print("C:", json.dumps(left, ensure_ascii=False, sort_keys=True))
            print("R:", json.dumps(right, ensure_ascii=False, sort_keys=True))
            break
    raise SystemExit(1)
print("PASS: fp_add C/Rust match")
PY

printf 'cases=%s\n' "$(grep -c '"scenario"' "$TEMP/c.jsonl")"
