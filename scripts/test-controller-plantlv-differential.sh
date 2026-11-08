#!/bin/sh
# M6: paired C/Rust differential plantlv — текст плана в TLV.
#
# Контейнер: C-компилятор выдаёт унаследованный D2KP, R2O — канонический
# R2OP; эквивалентность контейнеров проверяет M7a, поэтому в diff магия
# нормализуется. Отдельная фикстура фиксирует случаи, где R2O строже
# C-компилятора ровно настолько, насколько строг plan_parse.c самого D2O
# (autottl/minexec и ссылки фальшивок/перекрытий).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}
FIXTURE="$ROOT/scripts/fixtures/plantlv_cases.txt"
STRICTER="$ROOT/scripts/fixtures/plantlv_stricter_cases.txt"

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-m6-plantlv.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-plantlv" \
    "$ROOT/crates/r2o-controller/tests/d2o_plantlv_differential.c" \
    "$D2O_ROOT/core/plantlv.c"

run_rust() {
    "$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -q -p r2o-controller --example m6_plantlv_trace -- "$1"
}

"$TEMP/d2o-plantlv" "$FIXTURE" >"$TEMP/c.out"
run_rust "$FIXTURE" >"$TEMP/rust.out" 2>"$TEMP/rust.err"

sed 's/^hex 44324b50/hex MAGIC/' "$TEMP/c.out" >"$TEMP/c.norm"
sed 's/^hex 52324f50/hex MAGIC/' "$TEMP/rust.out" >"$TEMP/rust.norm"
if ! diff -u "$TEMP/c.norm" "$TEMP/rust.norm"; then
    printf 'FAIL: plantlv differential\n' >&2
    exit 1
fi

# Строже, чем C-компилятор, но ровно как plan_parse.c: C принимает текст,
# R2O отвергает его на этапе компиляции плана.
"$TEMP/d2o-plantlv" "$STRICTER" >"$TEMP/c-strict.out"
run_rust "$STRICTER" >"$TEMP/rust-strict.out" 2>/dev/null
strict_cases=$(grep -c '^case ' "$TEMP/c-strict.out")
strict_c_ok=$(grep -c '^result ok$' "$TEMP/c-strict.out")
strict_rust_err=$(grep -c '^result err$' "$TEMP/rust-strict.out")
if [ "$strict_c_ok" != "$strict_cases" ] || [ "$strict_rust_err" != "$strict_cases" ]; then
    printf 'FAIL: stricter validation C_ok=%s Rust_err=%s cases=%s\n' \
        "$strict_c_ok" "$strict_rust_err" "$strict_cases" >&2
    exit 1
fi

printf 'cases=%s\n' "$(grep -c '^case ' "$TEMP/c.out")"
printf 'accepted=%s rejected=%s\n' \
    "$(grep -c '^result ok$' "$TEMP/c.out")" \
    "$(grep -c '^result err$' "$TEMP/c.out")"
printf 'stricter=%s (C accept, R2O reject as plan_parse.c)\n' "$strict_cases"
grep -A2 '^case combined-mixed$' "$TEMP/c.norm" | head -3
printf 'PASS: C/Rust plan text to TLV match (D2O %s)\n' "$ACTUAL_D2O_SHA"
