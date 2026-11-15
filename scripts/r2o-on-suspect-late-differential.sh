#!/bin/sh
# C/Rust differential: позднее закрытие (RST_AFTER_APP/FIN_RETRY/TCP_STALL)
# и полоса TCP-stall из C on_suspect.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
fi
CC=${CC:-cc}
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-late.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

CORE="$DONOR/core"
make -s -C "$CORE" test_sched CC="$CC" >/dev/null
SCHED_OBJECTS=$(make -s -C "$CORE" \
    --eval='print-sched-test-objects:;@echo $(filter-out sched.o,$(SCHED_TEST_OBJ))' \
    print-sched-test-objects)
(
    cd "$CORE"
    "$CC" -std=gnu11 -O2 -Wall -Wextra -ffunction-sections -fdata-sections \
        -I. -Iinclude -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
        -DD2K_RELEASE_ID='"dev"' \
        "$ROOT/crates/r2o-controller/tests/d2o_on_suspect_late_differential.c" \
        $SCHED_OBJECTS .udp-engine/udpplan.o .udp-engine/udpruntime.o \
        diagnostics.o libd2k_udp.a \
        -Wl,--gc-sections -lpthread -lm -o "$TEMP/c"
)
"$TEMP/c" >"$TEMP/c.out" 2>"$TEMP/c.err"

R2O_ON_SUSPECT_LATE_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    on_suspect_late_close_and_stall_band_match_donor \
    >"$TEMP/rust.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
cat "$TEMP/c.err"
printf 'PASS: C on_suspect late close and TCP-stall band match R2O (%s).\n' \
    "$ACTUAL_SHA"
