#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
expected_donor_sha=783aa75ce44dd6192cd1f4f1d98e4fe909ef3045
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-own-first.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
donor_core="$donor_root/core"
fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_own_first.tsv"
make -s -C "$donor_core" test_sched CC=clang-18
donor_sched_objects=$(make -s -C "$donor_core" \
    --eval='print-sched-test-objects:;@echo $(filter-out sched.o,$(SCHED_TEST_OBJ))' \
    print-sched-test-objects)
(
    cd "$donor_core"
    clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
        -ffunction-sections -fdata-sections \
        -I. -Iinclude -I"$donor_root/datapath/include" \
        -DD2K_RELEASE_ID='"dev"' \
        "$repo_root/crates/r2o-controller/tests/d2o_own_first_fixture.c" \
        $donor_sched_objects -Wl,--gc-sections -lpthread \
        -o "$tmp_dir/d2o-own-first"
)
"$tmp_dir/d2o-own-first" "$fixture" >"$tmp_dir/c.out"
R2O_OWN_FIRST_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked \
    own_first_plan_batches_match_donor
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
"$tmp_dir/d2o-own-first" "$fixture" planned >"$tmp_dir/c-planned.out"
R2O_OWN_FIRST_DIFF_PLANNED=1 R2O_OWN_FIRST_DIFF_OUTPUT="$tmp_dir/rust-planned.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked \
    own_first_plan_batches_match_donor
diff -u "$tmp_dir/c-planned.out" "$tmp_dir/rust-planned.out"
printf 'C/Rust own-plan eligibility, bound-plan priority, tier/success/freshness order, deduplication and 8-plan batches match d2o %s.\n' "$actual_donor_sha"
