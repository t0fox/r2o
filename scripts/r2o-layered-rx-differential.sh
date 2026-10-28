#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi

donor_core="$donor_root/core"
fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_layered_rx.tsv"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-layered-rx.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

make -s -C "$donor_core" test_sched CC=clang-18
make -s -C "$donor_core" udpplan.o CC=clang-18
"$donor_core/test_sched" --own-first-only
donor_sched_objects=$(make -s -C "$donor_core" \
    --eval='print-sched-test-objects:;@echo $(filter-out sched.o,$(SCHED_TEST_OBJ))' \
    print-sched-test-objects)
(
    cd "$donor_core"
    clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
        -ffunction-sections -fdata-sections \
        -I. -Iinclude -I"$donor_root/datapath/include" \
        -DD2K_RELEASE_ID='"dev"' \
        "$repo_root/crates/r2o-controller/tests/d2o_layered_rx_fixture.c" \
        $donor_sched_objects "$donor_core/udpplan.o" \
        -Wl,--gc-sections -lpthread \
        -o "$tmp_dir/d2o-layered-rx"
)
"$tmp_dir/d2o-layered-rx" "$fixture" >"$tmp_dir/c.out"
R2O_LAYERED_RX_DIFF_OUTPUT="$tmp_dir/rust.out" \
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/r2o-target}" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked \
        own_first_layered_rx_trial_sequence_matches_d2o
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust own-first layered RX identity-repeat, gzip-control and inconclusive-plan behavior match d2o %s.\n' \
    "$actual_donor_sha"
