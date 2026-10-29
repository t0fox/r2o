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
cc=${CC:-cc}
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

hello_profiles_dir="$tmp_dir/d2o-core"
mkdir -p "$hello_profiles_dir/profiles"
cp "$donor_core/profiles/modern.hex" "$donor_core/profiles/legacy.hex" \
    "$hello_profiles_dir/profiles/"
make -s -C "$hello_profiles_dir" -f "$donor_core/Makefile" hello_profiles.inc

"$cc" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$donor_detect" -I"$donor_detect/include" -I"$donor_core/include" \
    -I"$hello_profiles_dir" \
    -I"$donor_datapath/include" \
    -o "$tmp_dir/d2o_white_ts_composite_fixture" \
    "$repo_root/crates/r2o-controller/tests/d2o_white_ts_composite_differential.c" \
    "$donor_detect/poison.c" "$donor_detect/trigger.c" \
    "$donor_detect/response.c" "$donor_detect/raw.c" \
    "$donor_core/measured.c" "$donor_core/hello.c" \
    "$donor_core/plantlv.c" "$donor_core/quic.c" \
    "$donor_core/quicwire.c" "$donor_core/crypto.c" \
    "$donor_datapath/plan_parse.c" "$donor_datapath/plan_apply.c" \
    "$donor_datapath/wire.c" -lpthread
"$tmp_dir/d2o_white_ts_composite_fixture" >"$tmp_dir/white-ts-c.out"

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

R2O_WHITE_TS_C_OUTPUT="$tmp_dir/white-ts-c.out" \
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/r2o-target}" \
    cargo +1.98.0 test -p r2o-controller --locked --offline --lib \
        white_hello_ts_composite_is_not_filtered_for_a_client_without_timestamps \
        -- --nocapture >"$tmp_dir/white-ts-rust.out" 2>&1 || {
        cat "$tmp_dir/white-ts-c.out"
        cat "$tmp_dir/white-ts-rust.out"
        exit 1
    }
cat "$tmp_dir/white-ts-c.out"
