#!/bin/sh
# C/Rust differential: production tls13.c read_exact/write_all против
# production tls13.rs helpers (r2o_tls13_read_exact/r2o_tls13_write_all).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_D2O_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-gcc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-/tmp}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi
command -v "$CC" >/dev/null 2>&1 || {
    printf 'missing required command: %s\n' "$CC" >&2
    exit 127
}

TEMP=$(mktemp -d "$TMPDIR/r2o-tls13-io.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

# tls13.c переопределяет _POSIX_C_SOURCE; для fixture это не ошибка.
(
    cd "$D2O_ROOT/core"
    "$CC" -std=gnu11 -O2 -Wall -Wextra \
        -ffunction-sections -fdata-sections \
        -I. -Iinclude -I../datapath/include \
        -o "$TEMP/c" \
        "$ROOT/crates/r2o-controller/tests/d2o_tls13_io_differential.c" \
        -Wl,--gc-sections -pthread >"$TEMP/build.log" 2>&1
) || {
    cat "$TEMP/build.log" >&2
    exit 1
}
"$TEMP/c" >"$TEMP/c.out"

R2O_TLS13_IO_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib \
    tls12::tests::tls13_io_c_differential_trace_matches_c_fixture \
    -- --exact >"$TEMP/rust.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
cat "$TEMP/c.out"
printf 'PASS: production TLS1.3 read_exact/write_all C/Rust match (13 cases, D2O %s).\n' \
    "$ACTUAL_D2O_SHA"
