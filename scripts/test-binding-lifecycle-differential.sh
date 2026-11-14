#!/bin/sh
# C/Rust differential: bind_confirmed (core/sched.c) — обновление привязки
# на месте, сохранение уровня/enabled/пути/ECH, сброс бюджета при смене плана,
# объединение отпечатка только по packets RX-объёма.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-bind-confirmed.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-bind-confirmed" \
    "$ROOT/crates/r2o-controller/tests/d2o_bind_confirmed_differential.c" \
    "$D2O_ROOT/core/catalog.c" "$D2O_ROOT/core/groups.c" \
    "$D2O_ROOT/core/domain.c" \
    -Wl,--gc-sections -lpthread -lm
"$TEMP/d2o-bind-confirmed" >"$TEMP/c.json"

R2O_BIND_CONFIRMED_DIFF_OUTPUT="$TEMP/rust.json" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib discovery::tests::bind_confirmed_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

python3 - "$TEMP/c.json" "$TEMP/rust.json" <<'PY'
import json
import sys

c = json.load(open(sys.argv[1], encoding="utf-8"))
r = json.load(open(sys.argv[2], encoding="utf-8"))
if c != r:
    for left, right in zip(c, r):
        if left != right:
            print("C:", json.dumps(left, ensure_ascii=False, sort_keys=True))
            print("R:", json.dumps(right, ensure_ascii=False, sort_keys=True))
            break
    raise SystemExit(1)
print("PASS: bind_confirmed C/Rust match")
PY

printf 'cases=%s\n' "$(grep -o '"step"' "$TEMP/c.json" | wc -l)"
