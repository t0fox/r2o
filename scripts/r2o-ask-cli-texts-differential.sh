#!/bin/sh
# C/Rust differential: тексты CLI d2kask — step_rc_str/ack_code_str/pval_str.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-ask-cli-texts.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror \
    -Wno-unused-function -Wno-unused-variable \
    -ffunction-sections -fdata-sections \
    -I"$DONOR/core" -I"$DONOR/core/include" -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
    "$ROOT/crates/r2o-controller/tests/d2o_ask_cli_texts_differential.c" \
    -Wl,--gc-sections -lpthread -lm -o "$TEMP/c"
"$TEMP/c" >"$TEMP/c.out"
R2O_ASK_CLI_TEXT_OUTPUT="$TEMP/rust.out" \
    cargo test --locked -p r2o-controller --bin r2o-controller \
    tests::ask_cli_texts_match_c -- --exact \
    >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'PASS: d2kask CLI texts match C (%s, %s lines)\n' \
    "$ACTUAL_SHA" "$(wc -l <"$TEMP/c.out" | tr -d ' ')"
