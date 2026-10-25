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

donor_detect="$donor_root/detect"
donor_core="$donor_root/core"
donor_datapath="$donor_root/datapath"
fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o/raw-syn-profile.tsv"
error_fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o/raw-selftest-errors.tsv"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-d2o-raw-profile.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

cc -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$donor_detect" -I"$donor_detect/include" -I"$donor_core/include" \
    -I"$donor_datapath/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_raw_syn_profile_fixture.c" \
    -Wl,--gc-sections -lpthread -o "$tmp_dir/d2o_raw_syn_profile_fixture"
cc -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$donor_detect" -I"$donor_detect/include" -I"$donor_core/include" \
    -I"$donor_datapath/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_raw_cache_key_fixture.c" \
    -Wl,--gc-sections -lpthread -o "$tmp_dir/d2o_raw_cache_key_fixture"
"$tmp_dir/d2o_raw_syn_profile_fixture" "$fixture" >"$tmp_dir/c.out"
"$tmp_dir/d2o_raw_cache_key_fixture" "$fixture" "$error_fixture" >>"$tmp_dir/c.out"

R2O_RAW_PROFILE_C_OUTPUT="$tmp_dir/c.out" \
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/r2o-target}" \
    cargo +1.98.0 test -p r2o-controller --locked --offline --lib \
        raw_syn_profile_matches_the_d2o_fixture -- --nocapture >"$tmp_dir/rust.out" 2>&1 || {
        cat "$tmp_dir/c.out"
        cat "$tmp_dir/rust.out"
        exit 1
    }

c_rows=$(sed -n '/^RAW_/p' "$tmp_dir/c.out")
rust_rows=$(sed -n '/^RAW_/p' "$tmp_dir/rust.out")
if [ "$c_rows" != "$rust_rows" ]; then
    printf 'C:\n%s\nRust:\n%s\n' "$c_rows" "$rust_rows" >&2
    exit 1
fi
printf '%s\n' "$c_rows"
