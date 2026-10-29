#!/bin/sh
set -eu

root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor=${R2O_DONOR_ROOT:-"${root%/*}/d2o"}
expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
test "$(git -C "$donor" rev-parse HEAD)" = "$expected_donor_sha"

make -s -C "$donor/detect" test_repeats CC=clang-18
"$donor/detect/test_repeats"

cd "$root"
cargo +1.98.0 test --locked --offline -p r2o-controller --lib raw_connect_fallback_tests
printf 'C/Rust raw-connect timeout recovery branches match d2o %s.\n' "$expected_donor_sha"
