#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
expected_donor_sha=a378e230947ebfd011439e1cac0f1e994d883aae
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-known-plans.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
donor_core="$donor_root/core"
fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_known_plans.tsv"
# Компилятор можно переопределить (в окружении может не быть clang-18).
CC=${CC:-clang-18}
make -s -C "$donor_core" test_sched CC="$CC"
donor_sched_objects=$(make -s -C "$donor_core" \
    --eval='print-sched-test-objects:;@echo $(filter-out sched.o,$(SCHED_TEST_OBJ))' \
    print-sched-test-objects)
(
    cd "$donor_core"
    "$CC" -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
        -ffunction-sections -fdata-sections \
        -I. -Iinclude -I"$donor_root/datapath/include" \
        -DD2K_RELEASE_ID='"dev"' \
        "$repo_root/crates/r2o-controller/tests/d2o_known_plans_fixture.c" \
        $donor_sched_objects -Wl,--gc-sections -lpthread \
        -o "$tmp_dir/d2o-known-plans"
)
"$tmp_dir/d2o-known-plans" "$fixture" >"$tmp_dir/c.out"
R2O_KNOWN_PLANS_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked \
    known_plan_candidates_match_donor_scheduler
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust known-plan compatibility, transport, tried hashes, volume bucket priority, success order, stable deduplication and 8-plan cap match d2o %s.\n' "$actual_donor_sha"
