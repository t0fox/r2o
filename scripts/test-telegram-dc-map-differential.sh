#!/bin/sh
# TG3: paired C/Rust differential DC map parse/validate/merge/persist.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tg-dc-map.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/telegram/include" \
    -o "$TEMP/d2o-dc-json" \
    "$ROOT/scripts/fixtures/d2o_dc_map_json_trace.c" \
    "$D2O_ROOT/telegram/src/dc_map_json.c" \
    "$D2O_ROOT/telegram/src/dc_map.c"
"$TEMP/d2o-dc-json" > "$TEMP/c-json.txt"
"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example dc_map_json_trace > "$TEMP/r-json.txt"
diff -u "$TEMP/c-json.txt" "$TEMP/r-json.txt"

"$CC" -std=gnu11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/telegram/include" -I"$D2O_ROOT/telegram/src" \
    -o "$TEMP/d2o-dc-merge" \
    "$ROOT/scripts/fixtures/d2o_dc_map_merge_trace.c" \
    "$D2O_ROOT/telegram/src/dc_map_json.c" \
    "$D2O_ROOT/telegram/src/dc_map.c"
"$TEMP/d2o-dc-merge" > "$TEMP/c-merge.txt"
"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example dc_map_merge_trace > "$TEMP/r-merge.txt"
diff -u "$TEMP/c-merge.txt" "$TEMP/r-merge.txt"

"$CC" -std=gnu11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/telegram/include" -I"$D2O_ROOT/telegram/src" \
    -o "$TEMP/d2o-dc-store" \
    "$ROOT/scripts/fixtures/d2o_dc_map_store_trace.c" \
    "$D2O_ROOT/telegram/src/dc_map_store.c" \
    "$D2O_ROOT/telegram/src/dc_map_json.c" \
    "$D2O_ROOT/telegram/src/dc_map.c"
NOW=$(python3 "$ROOT/scripts/fixtures/make_dc_cache.py" "$TEMP/c-cache.json")
cp "$TEMP/c-cache.json" "$TEMP/r-cache.json"
"$TEMP/d2o-dc-store" "$TEMP/c-cache.json" "$NOW" > "$TEMP/c-store.txt"
"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-telegram --example dc_map_store_trace -- \
    "$TEMP/r-cache.json" "$NOW" > "$TEMP/r-store.txt"
diff -u "$TEMP/c-store.txt" "$TEMP/r-store.txt"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-telegram --lib dc_map::tests > /dev/null
printf 'PASS: C/Rust DC map parse/validate/merge/load/install match (D2O %s)\n' "$ACTUAL_D2O_SHA"
