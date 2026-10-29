#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_root=${R2O_DONOR_ROOT:-"${r2o_script_dir%/r2o}/d2o"}
r2o_expected_donor_sha=${R2O_EXPECTED_DONOR_SHA:-304ba893dd37197128ac8799c0495b035f6a38c0}
r2o_actual_donor_sha=$(git -C "$r2o_donor_root" rev-parse HEAD)
r2o_fixture="$r2o_script_dir/crates/r2o-controller/tests/fixtures/d2o_bridge_clone_decoy.tsv"
r2o_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-bridge-clone-decoy.XXXXXX")
trap 'rm -rf -- "$r2o_tmp_dir"' EXIT HUP INT TERM

if [ "$r2o_actual_donor_sha" != "$r2o_expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$r2o_expected_donor_sha" "$r2o_actual_donor_sha" >&2
    exit 2
fi
if ! git -C "$r2o_donor_root" diff --quiet HEAD -- \
    core/hello.c core/include/d2k_hello.h detect/bridge.c detect/test_bridge.c; then
    printf 'D2O bridge clone sources have tracked changes\n' >&2
    exit 2
fi

r2o_donor_core="$r2o_donor_root/core"
if [ ! -f "$r2o_donor_core/hello_profiles.inc" ]; then
    make -s -C "$r2o_donor_core" hello_profiles.inc
fi
r2o_cc=${CC:-clang-18}
"$r2o_cc" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$r2o_donor_core/include" \
    "$r2o_script_dir/crates/r2o-controller/tests/d2o_bridge_clone_decoy_differential.c" \
    "$r2o_donor_core/hello.c" -o "$r2o_tmp_dir/d2o-bridge-clone-decoy"
"$r2o_tmp_dir/d2o-bridge-clone-decoy" "$r2o_fixture" >"$r2o_tmp_dir/c.out"

if R2O_BRIDGE_CLONE_DIFF_OUTPUT="$r2o_tmp_dir/rust.out" \
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/r2o-target}" \
    cargo +1.98.0 test --locked --offline -p r2o-controller --lib \
        snapped_client_hello_is_the_decoy_and_control_sni_is_preserved \
        >"$r2o_tmp_dir/rust.log" 2>&1; then
    cat "$r2o_tmp_dir/rust.log"
else
    cat "$r2o_tmp_dir/rust.log"
    exit 1
fi

diff -u "$r2o_tmp_dir/c.out" "$r2o_tmp_dir/rust.out"
printf 'C/Rust bridge clone-decoy behavior matches d2o %s.\n' "$r2o_actual_donor_sha"
