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

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-own-first.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
donor_core="$donor_root/core"
fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_own_first.tsv"
make -s -C "$donor_core" test_sched CC=clang-18
"$donor_core/test_sched" --own-first-only
# shellcheck disable=SC2016
donor_sched_objects=$(make -s -C "$donor_core" \
    --eval='print-sched-test-objects:;@echo $(filter-out sched.o,$(SCHED_TEST_OBJ))' \
    print-sched-test-objects)
(
    cd "$donor_core"
    # shellcheck disable=SC2086
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
"$tmp_dir/d2o-own-first" late-result >"$tmp_dir/c-deadline.out"
R2O_OWN_FIRST_DEADLINE_DIFF_OUTPUT="$tmp_dir/rust-deadline.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked \
    own_first_deadline_precedes_late_verified_and_challenge_results
diff -u "$tmp_dir/c-deadline.out" "$tmp_dir/rust-deadline.out"
"$tmp_dir/d2o-own-first" ech-witness-order >"$tmp_dir/c-witness-order.out"
R2O_ECH_WITNESS_ORDER_DIFF_OUTPUT="$tmp_dir/rust-witness-order.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked \
    ech_witness_search_retries_challenged_names_after_unchallenged_names
diff -u "$tmp_dir/c-witness-order.out" "$tmp_dir/rust-witness-order.out"
"$tmp_dir/d2o-own-first" ech-config-rotation >"$tmp_dir/c-ech-rotation.out"
R2O_ECH_CONFIG_ROTATION_DIFF_OUTPUT="$tmp_dir/rust-ech-rotation.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked \
    ech_probe_refreshes_config_for_each_candidate_attempt
diff -u "$tmp_dir/c-ech-rotation.out" "$tmp_dir/rust-ech-rotation.out"
printf 'C/Rust own-plan order/deadline and ECH witness/config fallback match d2o %s.\n' "$actual_donor_sha"
