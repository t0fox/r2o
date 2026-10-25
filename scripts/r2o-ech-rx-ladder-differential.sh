#!/bin/sh
set -eu

root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor=${R2O_DONOR_ROOT:-"${root%/*}/d2o"}
expected_donor=304ba893dd37197128ac8799c0495b035f6a38c0
test "$(git -C "$donor" rev-parse HEAD)" = "$expected_donor"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
core="$donor/core"

make -s -C "$core" test_sched CC=clang-18
make -s -C "$core" udpplan.o CC=clang-18
objects=$(make -s -C "$core" \
    --eval='print-sched-test-objects:;@echo $(filter-out sched.o,$(SCHED_TEST_OBJ))' \
    print-sched-test-objects)
(
    cd "$core"
    clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
        -ffunction-sections -fdata-sections -I. -Iinclude -I"$donor/datapath/include" \
        -DD2K_RELEASE_ID='"dev"' \
        "$root/crates/r2o-controller/tests/d2o_ech_rx_ladder_fixture.c" \
        $objects udpplan.o -Wl,--gc-sections -lpthread -o "$tmp/donor"
)
"$tmp/donor" >"$tmp/c.out"
R2O_ECH_RX_LADDER_DIFF_OUTPUT="$tmp/rust.out" \
    cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    ech_rx_ladder_batches_match_donor_refill -- --nocapture
diff -u "$tmp/c.out" "$tmp/rust.out"
printf 'C/Rust ECH RX ladder refill order, 8-plan batches, cursor and no-fallback behavior match d2o %s.\n' "$expected_donor"
