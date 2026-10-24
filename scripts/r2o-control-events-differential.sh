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

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-control-differential.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
fixture="$repo_root/crates/r2k-core/tests/fixtures/d2o_control_events.hex"

cc -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -DD2K_RELEASE_ID='"dev"' \
    -I"$donor_root/core" -I"$donor_root/core/include" -I"$donor_root/datapath/include" \
    "$repo_root/crates/r2k-core/tests/d2o_control_differential.c" \
    "$donor_root/core/link.c" -pthread -Wl,--gc-sections -o "$tmp_dir/d2o_control_fixture"
"$tmp_dir/d2o_control_fixture" "$fixture" >"$tmp_dir/c.out"
grep -v '^MATCH:' "$tmp_dir/c.out" >"$tmp_dir/c-wire.out"
grep '^MATCH:' "$tmp_dir/c.out" >"$tmp_dir/c-match.out"

R2O_CONTROL_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo +1.98.0 test -p r2k-core --locked --test control \
    d2o_control_frames_match_donor_wire_decoding
diff -u "$tmp_dir/c-wire.out" "$tmp_dir/rust.out"

R2O_CONTROL_PROOF_DIFF_OUTPUT="$tmp_dir/rust-match.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked \
    d2o_legacy_applied_frame_matches_donor_flow_proof
diff -u "$tmp_dir/c-match.out" "$tmp_dir/rust-match.out"
printf 'C/Rust ACK and APPLIED wire frames match for d2o %s.\n' "$actual_donor_sha"
