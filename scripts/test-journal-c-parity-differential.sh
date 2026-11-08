#!/bin/sh
# D22: paired C/Rust differential журнального кольца.
#
# C-оракул — production `datapath/journal.c`. Проверяются retention, порядок
# старых→новых, added/dropped, обрезка/санитизация имени, note-тексты
# suspect/refuse и поля plan/trial/execution/binding.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-journal-parity.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/runtime" \
    -o "$TEMP/c-journal" "$ROOT/scripts/fixtures/d2o_journal_trace.c" \
    "$D2O_ROOT/datapath/journal.c"
"$TEMP/c-journal" > "$TEMP/c.txt"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --example journal_trace > "$TEMP/rust.txt"

if ! diff -u "$TEMP/c.txt" "$TEMP/rust.txt"; then
    printf 'FAIL: journal C/Rust differential\n' >&2
    exit 1
fi

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib journal_note_texts_match_d2o
printf 'PASS: C and Rust journal ring, retention, fields and note texts match (D2O %s)\n' "$ACTUAL_D2O_SHA"
