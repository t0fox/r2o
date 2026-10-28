#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
donor_core="$donor_root/core"
expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-d2o-sched-cooldown.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

"${CC:-clang-18}" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -pthread \
    -I"$donor_core" -I"$donor_core/include" -I"$donor_root/datapath/include" \
    -DD2K_RELEASE_ID='"dev"' \
    "$repo_root/crates/r2o-controller/tests/d2o_scheduler_cooldown_differential.c" \
    -Wl,--gc-sections -o "$tmp_dir/d2o-scheduler-cooldown"

"$tmp_dir/d2o-scheduler-cooldown" >"$tmp_dir/c.out"
R2O_SCHED_COOLDOWN_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    d2o_scheduler_challenge_cooldown_matches_donor
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust scheduler cooldown decisions match d2o %s.\n' "$actual_donor_sha"
