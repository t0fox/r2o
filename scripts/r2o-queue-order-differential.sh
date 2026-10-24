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

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-queue-order.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
donor_core="$donor_root/core"
fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_scheduler_queue.tsv"

"${CC:-clang-18}" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -pthread \
    -I"$donor_core" -I"$donor_core/include" -I"$donor_root/datapath/include" \
    -DD2K_RELEASE_ID='"dev"' \
    "$repo_root/crates/r2o-controller/tests/d2o_scheduler_queue_differential.c" \
    -Wl,--gc-sections -o "$tmp_dir/d2o-queue"
"$tmp_dir/d2o-queue" "$fixture" >"$tmp_dir/c.out"
grep -v '^quic_yield_' "$tmp_dir/c.out" >"$tmp_dir/c-queue.out"
grep '^quic_yield_' "$tmp_dir/c.out" >"$tmp_dir/c-yield.out"

cat >"$tmp_dir/QueueExpiry.mk" <<'MAKEFILE'
include $(DONOR_CORE)/Makefile

$(R2O_TMP)/d2o-queue-expiry: $(R2O_REPO_ROOT)/crates/r2o-controller/tests/d2o_scheduler_queue_expiry_differential.c $(filter-out sched.o,$(SCHED_TEST_OBJ))
	$(CC) $(CFLAGS) -I"$(DONOR_CORE)" -o "$@" "$<" $(filter-out sched.o,$(SCHED_TEST_OBJ)) $(TEST_LDFLAGS)
MAKEFILE
make -C "$donor_core" -f "$tmp_dir/QueueExpiry.mk" --no-print-directory \
    "DONOR_CORE=$donor_core" "R2O_REPO_ROOT=$repo_root" "R2O_TMP=$tmp_dir" \
    "CC=${CC:-clang-18}" "$tmp_dir/d2o-queue-expiry"
"$tmp_dir/d2o-queue-expiry" \
    "$repo_root/crates/r2o-controller/tests/fixtures/d2o_scheduler_queue_expiry.tsv" \
    >"$tmp_dir/c-expiry.out"
R2O_SCHED_QUEUE_EXPIRY_DIFF_OUTPUT="$tmp_dir/rust-expiry.out" \
    cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    d2o_scheduler_queue_expiry_matches_donor
diff -u "$tmp_dir/c-expiry.out" "$tmp_dir/rust-expiry.out"

R2O_SCHED_QUEUE_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    d2o_scheduler_queue_order_matches_donor
diff -u "$tmp_dir/c-queue.out" "$tmp_dir/rust.out"
R2O_SCHED_YIELD_DIFF_OUTPUT="$tmp_dir/rust-yield.out" \
    cargo +1.98.0 test --locked -p r2o-controller --lib \
    d2o_scheduler_quic_yield_priority_matches_donor
diff -u "$tmp_dir/c-yield.out" "$tmp_dir/rust-yield.out"
printf 'C/Rust queue expiry, queue order, and QUIC-yield TCP priority match d2o %s.\n' \
    "$actual_donor_sha"
