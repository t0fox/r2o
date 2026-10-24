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

donor_core="$donor_root/core"
fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_catalog_sync_wire.json"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-catalog-sync.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

make -s -B -C "$donor_core" test_catalog_sync CC=clang-18
donor_objects=$(make -s -C "$donor_core" \
    --eval='print-donor-objects:;@echo $(SRC:.c=.o)' print-donor-objects)
(
    cd "$donor_core"
    clang-18 -std=c99 -O2 -Wall -Wextra -Werror \
        -Iinclude -I"$donor_root/datapath/include" \
        "$repo_root/crates/r2o-controller/tests/d2o_catalog_sync_wire_fixture.c" \
        $donor_objects libd2k_udp.a -lpthread -o "$tmp_dir/donor-catalog-wire"
)

"$tmp_dir/donor-catalog-wire" "$fixture" 1280 >"$tmp_dir/c.out"
if ! cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    catalog_sync_shared_donor_file_preserves_install_order -- --nocapture >"$tmp_dir/rust.log" 2>&1; then
    cat "$tmp_dir/rust.log" >&2
    exit 1
fi
grep '^D2O_CATALOG_OP=' "$tmp_dir/rust.log" >"$tmp_dir/rust.out"
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C d2k_sched_sync_step and Rust catalog install order match on shared fixture\n'
cat "$tmp_dir/c.out"
