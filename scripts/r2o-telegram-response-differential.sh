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

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-d2o-response.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM
cat >"$tmp_dir/input.tsv" <<'EOF'
# name<TAB>proto<TAB>WSS chunk sizes<TAB>plaintext hex<TAB>d2o result per chunk
zero_length_intermediate	2	4	00000000	I
valid_intermediate_split	2	2,9,17	18000000000000000000000001000000000000000400000011223344	P,P,C
intermediate_ack_only	2	4	00000080	P
intermediate_ack_then_response	2	4,28	0000008018000000000000000000000001000000000000000400000011223344	P,C
abridged_ack_then_response	1	4,41	800000000a0102030405060708202122232425262728292a2b2c2d2e2f404142434445464748494a4b4c4d4e4f	P,C
abridged_extended_header	1	4,4,40	800000007f0a00000102030405060708202122232425262728292a2b2c2d2e2f404142434445464748494a4b4c4d4e4f	P,P,C
abridged_zero_words	1	1	00	I
padded_ack_then_response	3	12,45	08000000ffffffff01020304290000000102030405060708202122232425262728292a2b2c2d2e2f404142434445464748494a4b4c4d4e4fa5	P,C
padded_ack_only	3	12	08000000ffffffff01020304	P
truncated_response	2	24	180000000000000000000000010000000000000004000000	P
valid_then_invalid_same_wss_payload	2	32	1800000000000000000000000100000000000000040000001122334400000000	I
valid_then_invalid_next_payload	2	28,4	1800000000000000000000000100000000000000040000001122334400000000	C,I
EOF

cc -std=c11 -D_POSIX_C_SOURCE=200809L \
    -I"$donor_root/telegram/include" -I"$donor_root/telegram/src" \
    -ffunction-sections -fdata-sections -Wno-unused-function -Wno-unused-variable \
    -c "$repo_root/crates/r2o-telegram/tests/d2o_response_observer_fixture.c" \
    -o "$tmp_dir/fixture.o"
cc -std=c11 -D_POSIX_C_SOURCE=200809L -I"$donor_root/telegram/include" \
    -ffunction-sections -fdata-sections -c "$donor_root/telegram/src/mtproto_crypto.c" \
    -o "$tmp_dir/crypto.o"
cc -Wl,--gc-sections "$tmp_dir/fixture.o" "$tmp_dir/crypto.o" \
    -lssl -lcrypto -o "$tmp_dir/d2o_response_fixture"
"$tmp_dir/d2o_response_fixture" "$tmp_dir/input.tsv" >"$tmp_dir/vectors.tsv"

R2O_D2O_RESPONSE_VECTORS="$tmp_dir/vectors.tsv" \
    CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/tmp/r2o-target} \
    cargo +1.98.0 test -p r2o-telegram --locked --lib \
        response_observer_matches_d2o_for_shared_ciphertext_and_wss_chunks \
        -- --ignored --nocapture
