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

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-d2o-splitter.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
cc -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$donor_root/telegram/include" \
    "$repo_root/crates/r2o-telegram/tests/d2o_raw_splitter_limit.c" \
    "$donor_root/telegram/src/mtproto_crypto.c" \
    "$donor_root/telegram/src/mtproto_splitter.c" \
    "$donor_root/telegram/src/memory_budget.c" \
    -lcrypto -o "$tmp_dir/d2o_raw_splitter_limit"

c_result=$("$tmp_dir/d2o_raw_splitter_limit")
printf 'd2o C oversized raw chunk: %s\n' "$c_result"
expected=$(printf '%s\t%s\t%s\t%s' -2 -2 1 1)
test "$c_result" = "$expected"
cargo +1.98.0 test -p r2o-telegram --locked --lib \
    splitter::tests::rejects_oversized_raw_chunk_after_zero_length_packet -- --nocapture
