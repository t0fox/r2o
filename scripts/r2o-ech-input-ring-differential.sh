#!/bin/sh
# C/Rust differential: on_shape ech_inputs[8] -> fill_hellos.
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
donor_core="$donor_root/core"
expected_donor_sha=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-ech-input.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
CC=${CC:-cc}

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
        "$repo_root/crates/r2o-controller/tests/d2o_ech_input_ring_differential.c" \
        $donor_sched_objects -Wl,--gc-sections -lpthread \
        -o "$tmp_dir/d2o-ech-input"
)
"$tmp_dir/d2o-ech-input" >"$tmp_dir/c.out"
R2O_ECH_INPUT_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo test --manifest-path "$repo_root/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    d2o_ech_input_ring_matches_c >"$tmp_dir/rust.log" 2>&1
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust on_shape ech_inputs -> fill_hellos match d2o %s.\n' \
    "$actual_donor_sha"
