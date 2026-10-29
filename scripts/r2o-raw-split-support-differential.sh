#!/bin/sh
set -eu

root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor=${R2O_DONOR_ROOT:-"${root%/*}/d2o"}
expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
test "$(git -C "$donor" rev-parse HEAD)" = "$expected_donor_sha"
test "$(uname -s)" = Linux

tmp=$(mktemp -d "${TMPDIR:-/tmp}/r2o-raw-split-support.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM

clang-18 -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$donor/detect/include" -I"$donor/core/include" \
    -I"$donor/datapath/include" \
    "$root/crates/r2o-controller/tests/d2o_raw_split_support_differential.c" \
    "$donor/detect/raw.c" -Wl,--gc-sections -pthread -o "$tmp/c"
"$tmp/c" >"$tmp/c.out"

cd "$root"
R2O_RAW_SPLIT_SUPPORT_DIFF_OUTPUT="$tmp/rust.out" \
    cargo +1.98.0 test --locked --offline -p r2o-controller --lib \
    split_probes_follow_the_donor_linux_gate_without_cap_net_raw
diff -u "$tmp/c.out" "$tmp/rust.out"
printf 'C/Rust raw split capability gate matches d2o %s.\n' "$expected_donor_sha"
cat "$tmp/c.out"
