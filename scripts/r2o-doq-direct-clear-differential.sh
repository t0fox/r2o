#!/bin/sh
# C/Rust differential: DoQ direct CLEAR — clear_backoff_ms и QUIC-привязки.
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
donor_core="$donor_root/core"
expected_donor_sha=a378e230947ebfd011439e1cac0f1e994d883aae
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-doq-clear.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
CC=${CC:-cc}

"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -pthread \
    -I"$donor_core" -I"$donor_core/include" -I"$donor_root/datapath/include" \
    -DD2K_RELEASE_ID='"dev"' \
    "$repo_root/crates/r2o-controller/tests/d2o_doq_direct_clear_differential.c" \
    "$donor_core/catalog.c" "$donor_core/hello.c" \
    -Wl,--gc-sections -lpthread \
    -o "$tmp_dir/d2o-doq-clear"
"$tmp_dir/d2o-doq-clear" >"$tmp_dir/c.out"

R2O_DOQ_DIRECT_CLEAR_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo test --manifest-path "$repo_root/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    d2o_doq_direct_clear_state_matches_c >"$tmp_dir/rust.log" 2>&1

diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust DoQ direct CLEAR backoff and QUIC bindings match d2o %s.\n' \
    "$actual_donor_sha"
