#!/bin/sh
# A3: незакрытая кавычка в panel config — C и Rust обязаны отвергнуть файл.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-panel-unquoted-quote.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra -pthread \
    -I"$D2O_ROOT/panel" \
    -o "$TEMP/d2o-config-trace" \
    "$ROOT/crates/r2o-panel/tests/d2o_config_parse_trace.c" \
    "$D2O_ROOT/panel/server.c"

run_case() {
    name=$1
    value=$2
    printf 'MODE=%s\nPANEL_LISTEN=192.168.1.1:8090\nQUEUE_NUM=2000\n' "$value" \
        > "$TEMP/$name.conf"
    "$TEMP/d2o-config-trace" "$TEMP/$name.conf" > "$TEMP/$name.c.trace"
    head -n 1 "$TEMP/$name.c.trace" | grep -q '^-1	' || {
        echo "C принял незакрытую кавычку ($name)" >&2
        cat "$TEMP/$name.c.trace" >&2
        exit 1
    }
    R2O_PANEL_CONFIG_UNQUOTED_QUOTE_PATH="$TEMP/$name.conf" \
    R2O_PANEL_CONFIG_UNQUOTED_QUOTE_C_TRACE="$TEMP/$name.c.trace" \
        "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
            -p r2o-panel --test http d2o_config_parser_rejects_unquoted_trailing_quote \
            -- --ignored > "$TEMP/$name.rust.trace" 2>&1
    grep -q 'test result: ok. 1 passed' "$TEMP/$name.rust.trace"
}

run_case double 'apply"'
run_case single "apply'"

printf 'PASS: C and Rust reject unquoted trailing quotes in panel config (D2O %s)\n' "$ACTUAL_D2O_SHA"
