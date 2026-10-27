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
R2O_SNAPSHOT_EVENT_DIFF_OUTPUT="$tmp_dir/rust-snapshot-event.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked \
    active_client_shape_event_matches_d2o_on_shape
diff -u "$tmp_dir/c-snapshot-owner.out" "$tmp_dir/rust-snapshot-event.out"
printf 'C/Rust ClientHello event handling matches on eight ownership and shape cases.\n'
R2O_OWN_MODERN_HELLO="$tmp_dir/modern.bin" R2O_OWN_LEGACY_HELLO="$tmp_dir/legacy.bin" \
    "$tmp_dir/d2o-ack-applied-persist" --own-snapshot >"$tmp_dir/c-own-snapshot.out"
awk '$1 < 4 || ($1 >= 8 && $1 < 12) { print $1, $2, $3 }' "$tmp_dir/c-own-snapshot.out" >"$tmp_dir/c-own-input.out"
R2O_OWN_MODERN_HELLO="$tmp_dir/modern.bin" R2O_OWN_LEGACY_HELLO="$tmp_dir/legacy.bin" R2O_OWN_SNAPSHOT_DIFF_OUTPUT="$tmp_dir/rust-own-input.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline own_first_late_snapshot_transition_matches_d2o
diff -u "$tmp_dir/c-own-input.out" "$tmp_dir/rust-own-input.out"
printf 'C/Rust own-first snapshot input and ownership match on identical ClientHello bytes.\n'

if [ -n "${R2O_C_OWN_SNAPSHOT_OUTPUT:-}" ]; then cp "$tmp_dir/c-own-snapshot.out" "$R2O_C_OWN_SNAPSHOT_OUTPUT"; fi
"$tmp_dir/d2o-ack-applied-persist" --snapshot-stage >"$tmp_dir/c-snapshot-stage.out"
R2O_SNAPSHOT_STAGE_DIFF_OUTPUT="$tmp_dir/rust-snapshot-stage.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked \
    client_shape_cancels_only_during_question_like_d2o
diff -u "$tmp_dir/c-snapshot-stage.out" "$tmp_dir/rust-snapshot-stage.out"
printf 'C/Rust ClientHello cancellation matches queue, ask, plan and verify states.\n'
"$tmp_dir/d2o-ack-applied-persist" --seed-input >"$tmp_dir/c-seed-input.out"
if ! R2O_SEED_INPUT_DIFF_OUTPUT="$tmp_dir/rust-seed-input.out" cargo +1.98.0 test -p r2o-controller --test classify --locked --offline base_seed_is_reused_only_for_same_client_hello_and_endpoint; then
    diff -u "$tmp_dir/c-seed-input.out" "$tmp_dir/rust-seed-input.out" || true
    exit 1
fi
diff -u "$tmp_dir/c-seed-input.out" "$tmp_dir/rust-seed-input.out"
printf 'C/Rust reuse base seed only for the same input.\n'
"$tmp_dir/d2o-ack-applied-persist" --own-budget >"$tmp_dir/c-own-budget.out"
if ! R2O_OWN_BUDGET_DIFF_OUTPUT="$tmp_dir/rust-own-budget.out" cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline full_search_resets_candidate_budget_after_own_plans_like_d2o; then
    diff -u "$tmp_dir/c-own-budget.out" "$tmp_dir/rust-own-budget.out" || true
    exit 1
fi
diff -u "$tmp_dir/c-own-budget.out" "$tmp_dir/rust-own-budget.out"
printf 'C/Rust own-first candidate budget reset matches.\n'
awk '$1 == 0 || $1 == 4 { print ($1 == 4), $4 }' "$tmp_dir/c-own-snapshot.out" >"$tmp_dir/c-rx-carry.out"
if ! R2O_OWN_MODERN_HELLO="$tmp_dir/modern.bin" R2O_RX_CARRY_DIFF_OUTPUT="$tmp_dir/rust-rx-carry.out" cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline snapshot_reask_carries_only_proven_rx_like_d2o; then
    diff -u "$tmp_dir/c-rx-carry.out" "$tmp_dir/rust-rx-carry.out" || true
    exit 1
fi
diff -u "$tmp_dir/c-rx-carry.out" "$tmp_dir/rust-rx-carry.out"
printf 'C/Rust proven RX survives snapshot reask.\n'
