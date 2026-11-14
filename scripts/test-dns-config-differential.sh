#!/bin/sh
# C/Rust differential: d2k_dns_uri_parse и d2k_dns_service_match из
# актуального D2O main (runtime/d2k_dns_config.c).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_CURRENT_D2O_ROOT:-/mnt/e/d2o-current}
EXPECTED_D2O_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected current D2O main %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-dns-config.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/runtime" \
    -o "$TEMP/d2o-dns-config" \
    "$ROOT/crates/r2k-core/tests/d2o_dns_config_differential.c"
"$TEMP/d2o-dns-config" >"$TEMP/c.out"
"$CC" -std=c99 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/runtime" \
    -o "$TEMP/d2o-dns-readers" \
    "$ROOT/crates/r2k-core/tests/d2o_dns_config_readers_differential.c"
"$TEMP/d2o-dns-readers" >"$TEMP/c2.out"
cat "$TEMP/c.out" "$TEMP/c2.out" >"$TEMP/c.all"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2k-core --lib dns_config::tests::d2o_dns_config_trace \
    -- --ignored --nocapture >"$TEMP/rust.raw" 2>&1
grep -E '^[PM][0-9]+ ' "$TEMP/rust.raw" >"$TEMP/rust.out"
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2k-core --lib dns_config::tests::d2o_dns_config_readers_trace \
    -- --ignored --nocapture >"$TEMP/rust2.raw" 2>&1
grep -E '^[A-E][0-9]+ ' "$TEMP/rust2.raw" >"$TEMP/rust2.out"
cat "$TEMP/rust.out" "$TEMP/rust2.out" >"$TEMP/rust.all"

diff -u "$TEMP/c.all" "$TEMP/rust.all"
printf 'cases=%s\n' "$(wc -l < "$TEMP/c.all")"
printf 'PASS: D2O current-main DNS config parse/match/readers (D2O %s)\n' "$ACTUAL_D2O_SHA"
