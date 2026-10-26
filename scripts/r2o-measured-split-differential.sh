#!/bin/sh
set -eu

root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor=${R2O_DONOR_ROOT:-"${root%/*}/d2o"}
expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
test "$(git -C "$donor" rev-parse HEAD)" = "$expected_donor_sha"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$donor/core/include" \
    "$root/crates/r2o-controller/tests/d2o_measured_split_differential.c" \
    "$donor/core/measured.c" -Wl,--gc-sections -o "$tmp/c"
"$tmp/c" | sed 's/d2k-plan/r2o-plan/' >"$tmp/c.out"

cd "$root"
R2O_MEASURED_SPLIT_DIFF_OUTPUT="$tmp/rust.out" \
    cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    measured_split_plans_match_donor
diff -u "$tmp/c.out" "$tmp/rust.out"
printf 'C/Rust measured PREFIX/WHOLE_PACKET split plans match d2o %s.\n' "$expected_donor_sha"

make -s -C "$donor/detect" test_bridge CC=clang-18
"$donor/detect/test_bridge"
cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    discovery_search_ownership_matches_donor_local_failure_gates
