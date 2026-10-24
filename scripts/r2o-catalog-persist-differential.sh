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

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-catalog-persist.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
donor_core="$donor_root/core"
fixture="$repo_root/crates/r2o-controller/tests/fixtures/d2o_catalog_persist.tsv"
cc=${CC:-clang-18}

"$cc" -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$donor_core/include" -I"$donor_root/datapath/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_catalog_persist_differential.c" \
    "$donor_core/catalog.c" "$donor_core/groups.c" "$donor_core/domain.c" \
    -Wl,--gc-sections \
    -o "$tmp_dir/d2o-catalog-persist"
"$tmp_dir/d2o-catalog-persist" "$fixture" "$tmp_dir/catalog.json" >"$tmp_dir/c.out"
R2O_CATALOG_PERSIST_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo +1.98.0 test --locked -p r2o-controller --bin r2o-controller \
    d2o_catalog_persist_overwrites_concurrent_external_update
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust catalog persistence output matches d2o %s.\n' "$actual_donor_sha"
