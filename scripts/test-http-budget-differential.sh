#!/bin/sh
# C/Rust differential: budget_tcp remaining branches (close/no-growth/silence).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the current D2O checkout}
EXPECTED_D2O_SHA=${R2O_EXPECTED_DONOR_SHA:-7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05}
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-http-budget.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -DD2K_RELEASE_ID='"dev"' \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/runtime" \
    -o "$TEMP/d2o-budget" \
    "$ROOT/crates/r2o-controller/tests/d2o_http_budget_differential.c" \
    "$D2O_ROOT/core/diagnostics.c" -Wl,--gc-sections -pthread
"$TEMP/d2o-budget" >"$TEMP/c.out"

R2O_HTTP_BUDGET_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib tcp_budget_remaining_branches_match_current_donor \
    >/dev/null

# Первые девять строк — общий C `budget_tcp` oracle. Ранние ветви
# `request_page_budget` (challenge/denied) C-фикстурой не покрыты: статическая
# функция требует полного verify.c и mock budget_io; проверяем их отдельной
# Rust-строкой по исходному early-return C.
head -n 9 "$TEMP/rust.out" >"$TEMP/rust-core.out"
if ! diff -u "$TEMP/c.out" "$TEMP/rust-core.out"; then
    printf 'FAIL: HTTP budget differential\n' >&2
    exit 1
fi
grep -qx 'case=challenge budget=0' "$TEMP/rust.out"
grep -qx 'case=denied budget=0' "$TEMP/rust.out"

cat "$TEMP/c.out"
printf 'PASS: C/Rust HTTP budget branches match (D2O %s)\n' "$ACTUAL_D2O_SHA"
