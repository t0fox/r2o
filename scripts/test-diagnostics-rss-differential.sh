#!/bin/sh
# S11: paired C/Rust periodic RSS sample (60s interval, process fields).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-diagnostics-rss.XXXXXX")
CASE=$(mktemp -d /tmp/r2o-diagnostics-rss-case.XXXXXX)
trap 'rm -rf -- "$TEMP" "$CASE"' EXIT HUP INT TERM

mkdir -p "$CASE/proc/123" "$CASE/proc/124" "$CASE/run"
printf 'VmRSS: 1024 kB\nVmHWM: 2048 kB\nRssAnon: 512 kB\nThreads: 3\nVmData: 4096 kB\nVmSwap: 8 kB\n' \
    > "$CASE/proc/123/status"
printf 'd2kc\n' > "$CASE/proc/123/comm"
printf '123\n' > "$CASE/run/d2k.pid"
printf 'VmRSS: 1024 kB\nVmHWM: 2048 kB\nRssAnon: 512 kB\nThreads: 3\nVmData: 4096 kB\nVmSwap: 8 kB\n' \
    > "$CASE/proc/124/status"
printf 'r2o-controller\n' > "$CASE/proc/124/comm"
printf '124\n' > "$CASE/run/r2o-controller4.pid"
printf 'MemTotal: 65536 kB\nMemAvailable: 8192 kB\n' > "$CASE/proc/meminfo"

"$CC" -std=c11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -DD2K_RELEASE_ID='"dev"' \
    -o "$TEMP/c-rss" "$ROOT/scripts/fixtures/d2o_diagnostics_rss_trace.c"
"$TEMP/c-rss" "$CASE/proc" "$CASE/run" > "$TEMP/c.out"

R2O_DIAG_RSS_ROOT="$CASE" R2O_DIAG_RSS_C_TRACE="$TEMP/c.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-controller --lib d2o_periodic_rss_sample_matches_c -- --ignored \
        > "$TEMP/rust.trace" 2>&1
grep -q 'test result: ok. 1 passed' "$TEMP/rust.trace" || {
    cat "$TEMP/rust.trace" >&2
    exit 1
}

printf 'PASS: C and Rust 60s RSS samples, process fields and interval match (D2O %s)\n' "$ACTUAL_D2O_SHA"
