#!/bin/sh
# C/Rust differential: ветвь on_suspect «чистое рукопожатие».
# Матрица: коды RST/REPEAT/SILENT vs RST_CUT/5/6/8, IP клиента, planned,
# другое имя, другое семейство, TTL 60/61 с.
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

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-clean-handshake.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

"${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -pthread \
    -I"$donor_core" -I"$donor_core/include" -I"$donor_root/datapath/include" \
    -DD2K_RELEASE_ID='"dev"' \
    "$repo_root/crates/r2o-controller/tests/d2o_scheduler_clean_handshake_differential.c" \
    -Wl,--gc-sections -o "$tmp_dir/d2o-clean-handshake"

"$tmp_dir/d2o-clean-handshake" >"$tmp_dir/c.out"
R2O_CLEAN_HANDSHAKE_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo test --manifest-path "$repo_root/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller \
    d2o_clean_handshake_suppression_matches_c >"$tmp_dir/rust.log" 2>&1

diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust on_suspect clean-handshake decisions match d2o %s.\n' \
    "$actual_donor_sha"
