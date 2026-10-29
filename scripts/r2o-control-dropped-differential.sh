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

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-control-dropped.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

cc -std=gnu11 -O2 -Wall -Wextra -Werror \
    -I"$donor_root/core/include" \
    -I"$donor_root/datapath/include" \
    "$repo_root/crates/r2o-datapath/tests/d2o_control_dropped_differential.c" \
    "$donor_root/datapath/ctl.c" \
    -o "$tmp_dir/d2o-control-dropped"
"$tmp_dir/d2o-control-dropped" "$tmp_dir/control.sock" >"$tmp_dir/c.out"

R2O_CONTROL_DROPPED_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo +1.98.0 test --locked -p r2o-datapath --lib \
    control_server_counts_each_event_without_connected_peer_as_dropped_like_d2o
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust disconnected control-event accounting matches d2o %s.\n' "$actual_donor_sha"
