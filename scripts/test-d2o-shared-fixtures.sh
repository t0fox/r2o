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

donor_detect="$donor_root/detect"
donor_core="$donor_root/core"
donor_datapath="$donor_root/datapath"
tests="$repo_root/crates/r2o-controller/tests"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-d2o-fixtures.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

make -C "$donor_detect" d2k-detect
make -C "$donor_detect" test_response
"$donor_detect/test_response"

cc -std=c99 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$donor_detect" -I"$donor_detect/include" -I"$donor_core/include" \
    -I"$donor_datapath/include" \
    "$tests/d2o_nft_fixture.c" -Wl,--gc-sections \
    -o "$tmp_dir/d2o_nft_fixture"
"$tmp_dir/d2o_nft_fixture" "$tests/fixtures/d2o_nft_rst.txt"

cc -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$donor_detect" -I"$donor_detect/include" -I"$donor_core/include" \
    -I"$donor_datapath/include" \
    "$tests/d2o_clear_fixture.c" \
    "$donor_detect/poison.o" "$donor_detect/props.o" \
    "$donor_detect/raw.o" "$donor_detect/trigger.o" \
    "$donor_detect/response.o" \
    "$donor_core/measured.o" "$donor_core/hello.o" \
    "$donor_core/plantlv.o" "$donor_core/quic.o" \
    "$donor_core/quicwire.o" "$donor_core/crypto.o" \
    "$donor_datapath/plan_parse.o" "$donor_datapath/plan_apply.o" \
    "$donor_datapath/wire.o" -lpthread \
    -o "$tmp_dir/d2o_clear_fixture"
timeout 15s "$tmp_dir/d2o_clear_fixture" "$tests/fixtures/d2o_clear.txt" \
    >"$tmp_dir/classify-c.out"
R2O_CLEAR_DIFF_OUTPUT="$tmp_dir/classify-rust.out" \
    cargo test -p r2o-controller --locked --test d2o_parity \
    d2o_clear_vector_uses_only_the_base_series_and_ignores_disabled_mark
diff -u "$tmp_dir/classify-c.out" "$tmp_dir/classify-rust.out"
printf 'C/Rust classify CLEAR output matches for the shared d2o fixture.\n'

cc -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$donor_detect" -I"$donor_detect/include" -I"$donor_core/include" \
    -I"$donor_datapath/include" \
    "$tests/d2o_classify_unproven_differential.c" \
    "$donor_detect/poison.o" "$donor_detect/props.o" \
    "$donor_detect/raw.o" "$donor_detect/trigger.o" "$donor_detect/response.o" \
    "$donor_core/measured.o" "$donor_core/hello.o" \
    "$donor_core/plantlv.o" "$donor_core/quic.o" \
    "$donor_core/quicwire.o" "$donor_core/crypto.o" \
    "$donor_datapath/plan_parse.o" "$donor_datapath/plan_apply.o" \
    "$donor_datapath/wire.o" -lpthread \
    -o "$tmp_dir/d2o_classify_unproven_differential"
timeout 15s "$tmp_dir/d2o_classify_unproven_differential" \
    >"$tmp_dir/classify-unproven-c.out"
R2O_CLASSIFY_UNPROVEN_DIFF_OUTPUT="$tmp_dir/classify-unproven-rust.out" \
    cargo test -p r2o-controller --locked --test classify \
    unrecognized_trigger_reply_matches_donor_opaque_verdict
diff -u "$tmp_dir/classify-unproven-c.out" "$tmp_dir/classify-unproven-rust.out"
printf 'C/Rust classify unrecognized-reply output matches.\n'

cc -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$donor_detect" -I"$donor_detect/include" -I"$donor_core/include" \
    -I"$donor_datapath/include" \
    "$tests/d2o_response_fixture.c" \
    "$donor_detect/classify.o" "$donor_detect/poison.o" \
    "$donor_detect/props.o" "$donor_detect/raw.o" \
    "$donor_detect/trigger.o" "$donor_detect/response.o" \
    "$donor_core/measured.o" "$donor_core/hello.o" \
    "$donor_core/plantlv.o" "$donor_core/quic.o" \
    "$donor_core/quicwire.o" "$donor_core/crypto.o" \
    "$donor_datapath/plan_parse.o" "$donor_datapath/plan_apply.o" \
    "$donor_datapath/wire.o" -lpthread \
    -o "$tmp_dir/d2o_response_fixture"
"$tmp_dir/d2o_response_fixture" "$tests/fixtures/d2o/tls-response-vectors.tsv"

cc -std=c99 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$donor_detect" -I"$donor_detect/include" -I"$donor_core/include" \
    -I"$donor_datapath/include" \
    "$tests/d2o_tls_response_eintr.c" \
    "$donor_detect/classify.o" "$donor_detect/poison.o" \
    "$donor_detect/props.o" "$donor_detect/raw.o" \
    "$donor_detect/trigger.o" "$donor_detect/response.o" \
    "$donor_core/measured.o" "$donor_core/hello.o" \
    "$donor_core/plantlv.o" "$donor_core/quic.o" \
    "$donor_core/quicwire.o" "$donor_core/crypto.o" \
    "$donor_datapath/plan_parse.o" "$donor_datapath/plan_apply.o" \
    "$donor_datapath/wire.o" -lpthread \
    -o "$tmp_dir/d2o_tls_response_eintr"
"$tmp_dir/d2o_tls_response_eintr" "$tests/fixtures/d2o_tls_response_eintr.tsv" \
    >"$tmp_dir/tls-response-c.out"
printf 'C/TLS EINTR reference: '
cat "$tmp_dir/tls-response-c.out"
R2O_TLS_RESPONSE_EINTR_OUTPUT="$tmp_dir/tls-response-rust.out" \
    cargo test -p r2o-controller --locked --test response \
    d2o_tls_response_poll_interruption_matches_c_failure -- --nocapture
diff -u "$tmp_dir/tls-response-c.out" "$tmp_dir/tls-response-rust.out"
printf 'C/Rust TLS response probe result matches after poll interruption.\n'

cargo test -p r2o-controller --locked --test response d2o_shared_tls_response_vectors_match
cargo test -p r2o-controller --locked --lib \
    nft_rst_rule_uses_r2o_table_and_exact_tuple_with_donor_timeout
