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

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-worker-permit.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
donor_core="$donor_root/core"
fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_worker_permit.tsv"

"${CC:-clang-18}" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -pthread \
    -I"$donor_core" -I"$donor_core/include" -I"$donor_root/datapath/include" \
    -DD2K_RELEASE_ID='"dev"' \
    "$repo_root/crates/r2o-controller/tests/d2o_worker_permit_differential.c" \
    -Wl,--gc-sections -o "$tmp_dir/d2o-worker-permit"
"$tmp_dir/d2o-worker-permit" "$fixture" >"$tmp_dir/c.out"

R2O_WORKER_PERMIT_NO_TCP_OUTPUT="$tmp_dir/rust-no-tcp.out" \
    cargo +1.98.0 test --locked -p r2o-controller --lib \
    d2o_quic_does_not_yield_to_quic_only_discovery_queue
R2O_WORKER_PERMIT_TURN_OUTPUT="$tmp_dir/rust-turn.out" \
    cargo +1.98.0 test --locked -p r2o-controller --lib \
    d2o_parked_quic_resumes_after_one_tcp_admission
R2O_WORKER_PERMIT_QUEUE_DIFF_OUTPUT="$tmp_dir/rust-queue.out" \
    cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    d2o_worker_permit_queue_prefers_tcp_while_quic_is_parked

cat "$tmp_dir/rust-no-tcp.out" "$tmp_dir/rust-turn.out" \
    "$tmp_dir/rust-queue.out" | sort >"$tmp_dir/rust.sorted"
sort "$tmp_dir/c.out" >"$tmp_dir/c.sorted"
diff -u "$tmp_dir/c.sorted" "$tmp_dir/rust.sorted"
printf 'C/Rust worker, permit, and QUIC-yield behavior matches d2o %s.\n' \
    "$actual_donor_sha"
cat "$tmp_dir/c.out"
