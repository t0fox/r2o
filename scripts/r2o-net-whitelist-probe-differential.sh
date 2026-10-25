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

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-net-whitelist.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
donor_core="$donor_root/core"
clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
    -ffunction-sections -fdata-sections \
    -I"$donor_core" -I"$donor_core/include" -I"$donor_root/datapath/include" \
    -DD2K_RELEASE_ID='"dev"' \
    "$repo_root/crates/r2o-controller/tests/d2o_net_whitelist_probe_fixture.c" \
    -Wl,--gc-sections -lpthread -o "$tmp_dir/d2o-net-whitelist"
"$tmp_dir/d2o-net-whitelist" >"$tmp_dir/c.out"
catalog_fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_net_whitelist.json"
clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$donor_core/include" -I"$donor_root/datapath/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_net_whitelist_catalog_fixture.c" \
    "$donor_core/catalog.c" "$donor_core/groups.c" "$donor_core/domain.c" \
    -Wl,--gc-sections -o "$tmp_dir/d2o-net-whitelist-catalog"
"$tmp_dir/d2o-net-whitelist-catalog" "$catalog_fixture" >"$tmp_dir/c-catalog.out"
clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -pthread \
    -ffunction-sections -fdata-sections \
    -I"$donor_core" -I"$donor_core/include" -I"$donor_root/datapath/include" \
    -DD2K_RELEASE_ID='"dev"' \
    "$repo_root/crates/r2o-controller/tests/d2o_rx_ladder_batch_fixture.c" \
    -Wl,--gc-sections -lpthread -o "$tmp_dir/d2o-rx-ladder-batch"
"$tmp_dir/d2o-rx-ladder-batch" >"$tmp_dir/c-batch.out"
R2O_NET_WHITELIST_DIFF_OUTPUT="$tmp_dir/rust.out" \
R2O_NET_WHITELIST_CATALOG_DIFF_OUTPUT="$tmp_dir/rust-catalog.out" \
R2O_RX_LADDER_BATCH_DIFF_OUTPUT="$tmp_dir/rust-batch.out" \
    cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    matches_d2o -- --nocapture >"$tmp_dir/rust.log" 2>&1
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
diff -u "$tmp_dir/c-catalog.out" "$tmp_dir/rust-catalog.out"
diff -u "$tmp_dir/c-batch.out" "$tmp_dir/rust-batch.out"
printf 'C/Rust network whitelist decisions and catalog state match d2o %s.\n' "$actual_donor_sha"
cat "$tmp_dir/c.out"
cat "$tmp_dir/c-catalog.out"
cat "$tmp_dir/c-batch.out"
