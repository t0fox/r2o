#!/bin/sh
set -eu

r2o_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_root=${R2O_DONOR_ROOT:-"${r2o_root%/*}/d2o"}
r2o_expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
r2o_actual_donor_sha=$(git -C "$r2o_donor_root" rev-parse HEAD)
if [ "$r2o_actual_donor_sha" != "$r2o_expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$r2o_expected_donor_sha" "$r2o_actual_donor_sha" >&2
    exit 2
fi

r2o_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-tcp-capacity.XXXXXX")
trap 'rm -rf -- "$r2o_tmp_dir"' EXIT HUP INT TERM
r2o_cc=${CC:-clang}

"$r2o_cc" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$r2o_donor_root/datapath/include" -I"$r2o_donor_root/core/include" \
    "$r2o_root/crates/r2o-datapath/tests/d2o_tcp_table_capacity_differential.c" \
    "$r2o_donor_root/datapath/track.c" -o "$r2o_tmp_dir/d2o-tcp-capacity"
"$r2o_tmp_dir/d2o-tcp-capacity" >"$r2o_tmp_dir/c.out"

R2O_TCP_TABLE_DIFF_OUTPUT="$r2o_tmp_dir/rust.out" \
    cargo test --locked -p r2o-datapath --lib tcp_table_capacity_differential_matches_d2o
diff -u "$r2o_tmp_dir/c.out" "$r2o_tmp_dir/rust.out"
cat "$r2o_tmp_dir/c.out"
printf 'D2O/R2O TCP capacity, refusal count, reverse lookup and expiry match\n'
