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

make -s -C "$donor_root/core" test_sched CC=clang-18
donor_sched_objects=$(make -s -C "$donor_root/core" \
    --eval='print-sched-test-objects:;@echo $(filter-out sched.o,$(SCHED_TEST_OBJ))' \
    print-sched-test-objects)
(
    cd "$donor_root/core"
    clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
        -I. -Iinclude -I"$donor_root/datapath/include" \
        -DD2K_RELEASE_ID='"dev"' \
        "$repo_root/crates/r2k-core/tests/d2o_ack_sequence_differential.c" \
        $donor_sched_objects -o "$tmp_dir/d2o-ack-sequence"
)
ack_fixture="$repo_root/crates/r2k-core/tests/fixtures/d2o_ack_sequence.tsv"
"$tmp_dir/d2o-ack-sequence" "$ack_fixture" >"$tmp_dir/c-ack-sequence.out"
grep '^candidate_ack' "$tmp_dir/c-ack-sequence.out" >"$tmp_dir/c-ack-matching.out"
grep '^missing_ack ' "$tmp_dir/c-ack-sequence.out" >"$tmp_dir/c-ack-settle.out"
R2O_ACK_SEQUENCE_DIFF_C_OUTPUT="$tmp_dir/c-ack-matching.out" \
    R2O_ACK_SEQUENCE_DIFF_OUTPUT="$tmp_dir/rust-ack-sequence.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked \
    d2o_ack_sequence_ignores_foreign_acks_until_trial_ack
diff -u "$tmp_dir/c-ack-matching.out" "$tmp_dir/rust-ack-sequence.out"
R2O_ACK_SETTLE_DIFF_C_OUTPUT="$tmp_dir/c-ack-settle.out" \
    R2O_ACK_SETTLE_DIFF_OUTPUT="$tmp_dir/rust-ack-settle.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked \
    d2o_missing_candidate_ack_expires_after_settle_window
diff -u "$tmp_dir/c-ack-settle.out" "$tmp_dir/rust-ack-settle.out"
printf 'C/Rust candidate ACK matching and lost-ACK settle match d2o %s.\n' "$actual_donor_sha"
printf 'C/Rust ACK and APPLIED wire frames match for d2o %s.\n' "$actual_donor_sha"
