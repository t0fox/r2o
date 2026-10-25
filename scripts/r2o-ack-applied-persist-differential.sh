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

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-ack-applied-persist.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
fixture="$repo_root/crates/r2k-core/tests/fixtures/d2o_candidate_chain.tsv"
donor_core="$donor_root/core"
save_interval_ms=$(awk '$1 == "SAVE_INTERVAL_MS" { print $2 }' "$fixture" | tr -d '\r')
if [ "$(sed -n 's/^#define SAVE_EVERY_MS //p' "$donor_core/d2kc.c" | tr -d '\r')" != "$save_interval_ms" ]; then
    printf 'C d2kc save interval differs from shared fixture (%s ms).\n' "$save_interval_ms" >&2
    exit 2
fi

make -s -C "$donor_core" test_sched CC=clang-18
donor_sched_objects=$(make -s -C "$donor_core" \
    --eval='print-sched-test-objects:;@echo $(filter-out sched.o,$(SCHED_TEST_OBJ))' \
    print-sched-test-objects)
(
    cd "$donor_core"
    clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
        -ffunction-sections -fdata-sections \
        -I. -Iinclude -I"$donor_root/datapath/include" \
        -DD2K_RELEASE_ID='"dev"' \
        "$repo_root/crates/r2k-core/tests/d2o_ack_applied_persist_differential.c" \
        $donor_sched_objects -Wl,--gc-sections -lpthread \
        -o "$tmp_dir/d2o-ack-applied-persist"
)
"$tmp_dir/d2o-ack-applied-persist" "$fixture" "$tmp_dir/c-catalog.json" >"$tmp_dir/c.out"
R2O_ACK_APPLIED_PERSIST_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked \
    d2o_ack_applied_persist_chain_matches_donor
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust ACK → APPLIED → catalog persistence chain matches d2o %s.\n' "$actual_donor_sha"
"$tmp_dir/d2o-ack-applied-persist" --task-deadline >"$tmp_dir/c-deadline.out"
R2O_TASK_DEADLINE_DIFF_OUTPUT="$tmp_dir/rust-deadline.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked \
    d2o_candidate_deadline_keeps_the_last_nine_seconds
diff -u "$tmp_dir/c-deadline.out" "$tmp_dir/rust-deadline.out"
printf 'C/Rust task deadline matches, including the last nine seconds and exact boundary.\n'
"$tmp_dir/d2o-ack-applied-persist" --fallback-gate >"$tmp_dir/c-fallback-gate.out"
R2O_FALLBACK_GATE_DIFF_OUTPUT="$tmp_dir/rust-fallback-gate.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked \
    measured_failure_fallback_gate_matches_donor
diff -u "$tmp_dir/c-fallback-gate.out" "$tmp_dir/rust-fallback-gate.out"
printf 'C/Rust measured-failure fallback gate matches on twelve transition cases.\n'
"$tmp_dir/d2o-ack-applied-persist" --fallback-queue >"$tmp_dir/c-fallback-queue.out"
R2O_FALLBACK_QUEUE_DIFF_OUTPUT="$tmp_dir/rust-fallback-queue.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked \
    fallback_queue_batches_and_tried_hashes_match_donor
diff -u "$tmp_dir/c-fallback-queue.out" "$tmp_dir/rust-fallback-queue.out"
printf 'C/Rust fallback queue order, batches, tried hashes and changing send caps match.\n'
"$tmp_dir/d2o-ack-applied-persist" --snapshot-owner >"$tmp_dir/c-snapshot-owner.out"
R2O_SNAPSHOT_OWNER_DIFF_OUTPUT="$tmp_dir/rust-snapshot-owner.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked \
    active_discovery_keeps_its_owned_client_snapshot_like_donor
diff -u "$tmp_dir/c-snapshot-owner.out" "$tmp_dir/rust-snapshot-owner.out"
printf 'C/Rust ClientHello ownership matches for compatible and incompatible shapes.\n'
