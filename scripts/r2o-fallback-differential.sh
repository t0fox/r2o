#!/bin/sh
set -eu
root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor=${R2O_DONOR_ROOT:-"${root%/*}/d2o"}
test "$(git -C "$donor" rev-parse HEAD)" = 783aa75ce44dd6192cd1f4f1d98e4fe909ef3045
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$donor/core/include" -I"$donor/datapath/include" \
    "$root/crates/r2o-controller/tests/d2o_fallback_differential.c" \
    "$donor/core/compose.c" "$donor/core/hello.c" -Wl,--gc-sections -o "$tmp/c"
"$tmp/c" >"$tmp/c.out"
cd "$root"
R2O_FALLBACK_DIFF_OUTPUT="$tmp/rust.out" cargo +1.98.0 test --locked -p r2o-controller --lib fallback_plans_match_donor
diff -u "$tmp/c.out" "$tmp/rust.out"
printf 'C/Rust fallback plans match for both TLS shapes and five send caps.\n'

donor_core="$donor/core"
make -s -C "$donor_core" test_sched CC=clang-18
make -s -C "$donor_core" udpplan.o CC=clang-18
donor_sched_objects=$(make -s -C "$donor_core" \
    --eval='print-sched-test-objects:;@echo $(filter-out sched.o,$(SCHED_TEST_OBJ))' \
    print-sched-test-objects)
(
    cd "$donor_core"
    clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
        -ffunction-sections -fdata-sections \
        -I. -Iinclude -I"$donor/datapath/include" \
        -DD2K_RELEASE_ID='"dev"' \
        "$root/crates/r2o-controller/tests/d2o_opaque_fallback_fixture.c" \
        $donor_sched_objects udpplan.o -Wl,--gc-sections -lpthread \
        -o "$tmp/opaque-fallback-c"
)
"$tmp/opaque-fallback-c" >"$tmp/opaque-c.out"
R2O_OWNED_FALLBACK_DIFF_OUTPUT="$tmp/opaque-rust.out" \
    cargo +1.98.0 test --locked -p r2o-controller --lib \
    opaque_owned_search_starts_with_donor_fallback_queue
diff -u "$tmp/opaque-c.out" "$tmp/opaque-rust.out"
printf 'C/Rust OPAQUE owned-search fallback activation and first 8 arms match.\n'
clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections -pthread \
    -I"$donor/core" -I"$donor/core/include" -I"$donor/datapath/include" \
    -DD2K_RELEASE_ID='"dev"' \
    "$root/crates/r2o-controller/tests/d2o_raw_budget_differential.c" \
    "$donor/core/compose.c" \
    -Wl,--gc-sections -o "$tmp/budget"
"$tmp/budget" >"$tmp/budget-c.out"
R2O_RAW_BUDGET_DIFF_OUTPUT="$tmp/budget-rust.out" cargo +1.98.0 test --locked -p r2o-controller --lib raw_measurements_do_not_consume_candidate_budget
diff -u "$tmp/budget-c.out" "$tmp/budget-rust.out"
printf 'C/Rust separate raw and candidate probe budgets match.\n'
clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$donor/core/include" -I"$donor/datapath/include" \
    "$root/crates/r2o-controller/tests/d2o_stats_wire.c" \
    "$donor/core/link.c" "$donor/datapath/ctl.c" \
    -Wl,--gc-sections -o "$tmp/stats"
"$tmp/stats" >"$tmp/stats-c.out"
R2O_STATS_DIFF_OUTPUT="$tmp/stats-rust.out" cargo +1.98.0 test --locked -p r2k-core stats_wire_matches_donor_parser
diff -u "$tmp/stats-c.out" "$tmp/stats-rust.out"
cat "$tmp/stats-c.out"
