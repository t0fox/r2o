#!/bin/sh
# C/Rust differential перехода T_ASKING -> T_VERIFY -> T_PLANNING:
# имя/адрес, family 4/6, APPLIED с нулевым, чужим и точным trial ID.
# C-оракул — production d2k_sched из donor `test_sched.c`; Rust — production
# ControlClient/service_http_search_command/apply_discovery_outcome.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD 2>/dev/null || true)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
CORE="$DONOR/core"
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-sched-tick-transition.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -s -C "$CORE" test_sched CC="$CC" >/dev/null
SCHED_OBJECTS=$(make -s -C "$CORE" CC="$CC" \
    --eval='print-sched-test-objects:;@echo $(SCHED_TEST_OBJ)' \
    print-sched-test-objects)
(
    cd "$CORE"
    "$CC" -std=gnu11 -O2 -Wall -Wextra -ffunction-sections -fdata-sections \
        -I. -Iinclude -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
        -DD2K_RELEASE_ID='"dev"' \
        "$ROOT/crates/r2o-controller/tests/d2o_sched_tick_trial_matrix.c" \
        $SCHED_OBJECTS .udp-engine/udpplan.o .udp-engine/udpruntime.o \
        diagnostics.o libd2k_udp.a \
        -Wl,--gc-sections -lpthread -lm -o "$TEMP/c"
)
"$TEMP/c" >"$TEMP/c.out"
grep '^case ' "$TEMP/c.out" >"$TEMP/c.cases"

R2O_SCHED_TICK_MATRIX_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked \
    -p r2o-controller --bin r2o-controller \
    d2o_sched_tick_trial_transitions_match_c >/dev/null 2>&1

diff -u "$TEMP/c.cases" "$TEMP/rust.out"
printf 'PASS: T_ASKING/VERIFY/PLANNING trial identity matches C %s (%s cases).\n' \
    "$ACTUAL_SHA" "$(wc -l <"$TEMP/c.cases" | tr -d ' ')"
