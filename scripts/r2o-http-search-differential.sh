#!/bin/sh
set -eu

r2o_script_dir=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_donor_core="${R2O_DONOR_CORE:-${r2o_script_dir%/*}/d2o/core}"
r2o_log_dir="$r2o_script_dir/.rea"
r2o_log="$r2o_log_dir/r2o-http-search-differential-$(date +%Y%m%d-%H%M%S).log"
r2o_upstream_sha=304ba893dd37197128ac8799c0495b035f6a38c0

if [ "${R2O_EXPECTED_DONOR_SHA:-}" != "$r2o_upstream_sha" ]; then
    printf 'HTTP-search differential requires pinned upstream donor %s\n' "$r2o_upstream_sha" >&2
    exit 2
fi
if [ ! -d "$r2o_donor_core" ]; then
    printf 'Каталог C-эталона не найден: %s\n' "$r2o_donor_core" >&2
    exit 2
fi

r2o_show_log_on_error() {
    r2o_status=$?
    if [ "$r2o_status" -ne 0 ] && [ -f "$r2o_log" ]; then
        cat "$r2o_log"
    fi
}
trap r2o_show_log_on_error EXIT

r2o_run_timed() {
    r2o_label=$1
    shift
    r2o_started=$(date +%s)
    if "$@"; then
        r2o_status=0
    else
        r2o_status=$?
    fi
    printf '\nВремя %s: %s с (код %s)\n' \
        "$r2o_label" "$(( $(date +%s) - r2o_started ))" "$r2o_status"
    return "$r2o_status"
}

mkdir -p "$r2o_log_dir"
{
    printf 'Дифференциальная проверка HTTP baseline: %s\n' \
        "$(date '+%Y-%m-%dT%H:%M:%S%z')"
    printf 'Исходники C: %s\n' "$r2o_donor_core"
    printf '\nSHA-256 исходников C-эталона\n'
    sha256sum "$r2o_donor_core/httpsearch.c" "$r2o_donor_core/test_httpsearch.c" \
        "$r2o_donor_core/d2kc.c" "$r2o_donor_core/httpsprobe.c"
    r2o_httpsearch_sha=$(sed 's/\r$//' "$r2o_donor_core/httpsearch.c" | sha256sum | awk '{print $1}')
    r2o_test_sha=$(sed 's/\r$//' "$r2o_donor_core/test_httpsearch.c" | sha256sum | awk '{print $1}')
    r2o_d2kc_sha=$(sed 's/\r$//' "$r2o_donor_core/d2kc.c" | sha256sum | awk '{print $1}')
    r2o_httpsprobe_sha=$(sed 's/\r$//' "$r2o_donor_core/httpsprobe.c" | sha256sum | awk '{print $1}')
    if [ "$r2o_httpsearch_sha" != \
        '7075b74f1340b53c410422bfe2ac5f558d009b29c20a7085e674f49b0210fa3a' ] || \
        [ "$r2o_test_sha" != \
        '7a1f589858f8ab5bec6b419e64f2bd262da023008726984487f4efa1cdad8195' ] || \
        [ "$r2o_d2kc_sha" != \
        'b6848021494bdf52e2850db671567a5b3d8f522cdcc933ca8bf9a9ec10efce46' ] || \
        [ "$r2o_httpsprobe_sha" != \
        '2a3f20b042d71f8565f4794fa474bc559cfb9a49045ad8c7d4d9400d4100968d' ]; then
        printf 'Исходники HTTP-search отличаются от проверенного снимка донора\n' >&2
        exit 1
    fi
    printf '\nТесты C-эталона HTTP-search\n'
    r2o_run_timed 'test_httpsearch C-эталона' \
        make -B -C "$r2o_donor_core" test-httpsearch CC=clang-18
    printf '\nСверка усечённого portal response и timeout внутри заголовка C/Rust\n'
    r2o_state_binary="$r2o_log_dir/http-response-state-$$"
    r2o_state_c="$r2o_log_dir/http-response-state-c-$$"
    r2o_state_rust="$r2o_log_dir/http-response-state-rust-$$"
    clang-18 -std=c99 -O2 -Wall -Wextra -Werror \
        -I"$r2o_donor_core/include" -I"$r2o_donor_core/../datapath/include" \
        -o "$r2o_state_binary" \
        "$r2o_script_dir/crates/r2o-controller/tests/d2o_http_response_state_differential.c" \
        "$r2o_donor_core/httpsearch.o" "$r2o_donor_core/httpup_logic.o" \
        "$r2o_donor_core/plantlv.o" "$r2o_donor_core/quic.o" \
        "$r2o_donor_core/quicwire.o" "$r2o_donor_core/crypto.o" \
        "$r2o_donor_core/../datapath/plan_parse.c" \
        "$r2o_donor_core/../datapath/plan_apply.c" \
        "$r2o_donor_core/../datapath/wire.c" \
        "$r2o_donor_core/verify.o" "$r2o_donor_core/quicconn.o" \
        "$r2o_donor_core/h3.o" "$r2o_donor_core/tls12.o" \
        "$r2o_donor_core/p256.o" "$r2o_donor_core/compose.o" \
        "$r2o_donor_core/measured.o" "$r2o_donor_core/hello.o" \
        "$r2o_donor_core/meas.o" "$r2o_donor_core/link.o" \
        "$r2o_donor_core/tls13.o" "$r2o_donor_core/tls13core.o" \
        "$r2o_donor_core/x25519.o" -lpthread
    "$r2o_state_binary" >"$r2o_state_c"
    if R2O_HTTP_RESPONSE_DIFF_OUTPUT="$r2o_state_rust" \
        cargo +1.98.0 test -p r2o-controller --locked --offline \
            --test http_search d2o_response_state_differential_preserves_portal_and_partial_head_outcomes; then
        diff -u "$r2o_state_c" "$r2o_state_rust"
    else
        diff -u "$r2o_state_c" "$r2o_state_rust" || true
        exit 1
    fi
    printf 'C/Rust HTTP portal/partial-header state: %s' "$(cat "$r2o_state_c")"
    printf '\nСверка количества APPLIED и окна подтверждения HTTP C/Rust\n'
    r2o_applied_binary="$r2o_log_dir/http-applied-window-differential-$$"
    r2o_applied_c="$r2o_log_dir/http-applied-window-c-$$"
    r2o_applied_rust="$r2o_log_dir/http-applied-window-rust-$$"
    clang-18 -std=c99 -O2 -Wall -Wextra -Werror \
        -I"$r2o_donor_core/include" -I"$r2o_donor_core/../datapath/include" \
        -o "$r2o_applied_binary" \
        "$r2o_script_dir/crates/r2o-controller/tests/d2o_http_applied_window_differential.c" \
        "$r2o_donor_core/httpsearch.o" "$r2o_donor_core/httpup_logic.o" \
        "$r2o_donor_core/plantlv.o" "$r2o_donor_core/quic.o" \
        "$r2o_donor_core/quicwire.o" "$r2o_donor_core/crypto.o" \
        "$r2o_donor_core/../datapath/plan_parse.c" \
        "$r2o_donor_core/../datapath/plan_apply.c" \
        "$r2o_donor_core/../datapath/wire.c" \
        "$r2o_donor_core/verify.o" "$r2o_donor_core/quicconn.o" \
        "$r2o_donor_core/h3.o" "$r2o_donor_core/tls12.o" \
        "$r2o_donor_core/p256.o" "$r2o_donor_core/compose.o" \
        "$r2o_donor_core/measured.o" "$r2o_donor_core/hello.o" \
        "$r2o_donor_core/meas.o" "$r2o_donor_core/link.o" \
        "$r2o_donor_core/tls13.o" "$r2o_donor_core/tls13core.o" \
        "$r2o_donor_core/x25519.o" -lpthread
    "$r2o_applied_binary" >"$r2o_applied_c"
    R2O_HTTP_APPLIED_DIFF_OUTPUT="$r2o_applied_rust" \
        cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
            http_applied_collection_requires_each_unique_execution_within_donor_window \
            --locked --offline -- --nocapture
    diff -u "$r2o_applied_c" "$r2o_applied_rust"
    printf 'C/Rust HTTP APPLIED window: %s' "$(cat "$r2o_applied_c")"
    rm -f -- "$r2o_applied_binary" "$r2o_applied_c" "$r2o_applied_rust"
    printf '\nСверка HTTPS-gate вызывающей стороны C/Rust\n'
    r2o_https_gate_binary="$r2o_log_dir/http-https-gate-differential-$$"
    r2o_https_gate_c="$r2o_log_dir/http-https-gate-c-$$"
    r2o_https_gate_rust="$r2o_log_dir/http-https-gate-rust-$$"
    clang-18 -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
        -I"$r2o_donor_core/include" \
        -o "$r2o_https_gate_binary" \
        "$r2o_script_dir/crates/r2o-controller/tests/d2o_http_https_gate_differential.c" \
        "$r2o_donor_core/httpsprobe.c" -Wl,--gc-sections -lpthread
    "$r2o_https_gate_binary" >"$r2o_https_gate_c"
    R2O_HTTP_HTTPS_GATE_DIFF_OUTPUT="$r2o_https_gate_rust" \
        cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
            http_search_https_caller_gate_matches_d2o_states --locked --offline -- --nocapture
    diff -u "$r2o_https_gate_c" "$r2o_https_gate_rust"
    printf 'C/Rust HTTP HTTPS gate: %s' "$(cat "$r2o_https_gate_c")"
    rm -f -- "$r2o_https_gate_binary" "$r2o_https_gate_c" "$r2o_https_gate_rust"
    printf '\nСверка немедленной долговечности HTTP-плана C/Rust\n'
    r2o_durable_binary="$r2o_log_dir/http-durable-differential-$$"
    r2o_durable_c="$r2o_log_dir/http-durable-c-$$"
    r2o_durable_rust="$r2o_log_dir/http-durable-rust-$$"
    clang-18 -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
        -I"$r2o_donor_core" -I"$r2o_donor_core/include" \
        -I"$r2o_donor_core/../datapath/include" \
        -o "$r2o_durable_binary" \
        "$r2o_script_dir/crates/r2o-controller/tests/d2o_http_durable_differential.c" \
        "$r2o_donor_core/httpsearch.o" "$r2o_donor_core/httpup_logic.o" \
        "$r2o_donor_core/plantlv.o" "$r2o_donor_core/quic.o" \
        "$r2o_donor_core/quicwire.o" "$r2o_donor_core/crypto.o" \
        "$r2o_donor_core/../datapath/plan_parse.c" \
        "$r2o_donor_core/../datapath/plan_apply.c" \
        "$r2o_donor_core/../datapath/wire.c" \
        "$r2o_donor_core/verify.o" "$r2o_donor_core/quicconn.o" \
        "$r2o_donor_core/h3.o" "$r2o_donor_core/tls12.o" \
        "$r2o_donor_core/p256.o" "$r2o_donor_core/compose.o" \
        "$r2o_donor_core/measured.o" "$r2o_donor_core/hello.o" \
        "$r2o_donor_core/meas.o" "$r2o_donor_core/link.o" \
        "$r2o_donor_core/tls13.o" "$r2o_donor_core/tls13core.o" \
        "$r2o_donor_core/x25519.o" -Wl,--gc-sections -lpthread
    "$r2o_durable_binary" >"$r2o_durable_c"
    R2O_HTTP_DURABLE_DIFF_OUTPUT="$r2o_durable_rust" \
        cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
            confirmed_http_candidate_is_durable_before_catalog_flush_interval \
            --locked --offline -- --nocapture
    diff -u "$r2o_durable_c" "$r2o_durable_rust"
    printf 'C/Rust HTTP persistence: %s' "$(cat "$r2o_durable_c")"
    rm -f -- "$r2o_durable_binary" "$r2o_durable_c" "$r2o_durable_rust"
    rm -f -- "$r2o_state_binary" "$r2o_state_c" "$r2o_state_rust"
    printf '\nСверка baseline и путей keep-alive C/Rust на локальном HTTP-сервере\n'
    r2o_baseline_harness="$r2o_script_dir/crates/r2o-controller/tests/d2o_http_baseline_differential.c"
    r2o_baseline_binary="$r2o_log_dir/http-baseline-differential-$$"
    r2o_baseline_c="$r2o_log_dir/http-baseline-c-$$"
    r2o_baseline_rust="$r2o_log_dir/http-baseline-rust-$$"
    clang-18 -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
        -I"$r2o_donor_core/include" -I"$r2o_donor_core/../datapath/include" \
        -o "$r2o_baseline_binary" "$r2o_baseline_harness" \
        "$r2o_donor_core/httpsearch.c" "$r2o_donor_core/httpup_logic.c" \
        "$r2o_donor_core/plantlv.o" "$r2o_donor_core/quic.o" \
        "$r2o_donor_core/quicwire.o" "$r2o_donor_core/crypto.o" \
        "$r2o_donor_core/../datapath/plan_parse.c" \
        "$r2o_donor_core/../datapath/plan_apply.c" \
        "$r2o_donor_core/../datapath/wire.c" \
        "$r2o_donor_core/verify.o" "$r2o_donor_core/quicconn.o" \
        "$r2o_donor_core/h3.o" "$r2o_donor_core/tls12.o" \
        "$r2o_donor_core/p256.o" "$r2o_donor_core/compose.o" \
        "$r2o_donor_core/measured.o" "$r2o_donor_core/hello.o" \
        "$r2o_donor_core/meas.o" "$r2o_donor_core/link.o" \
        "$r2o_donor_core/tls13.o" "$r2o_donor_core/tls13core.o" \
        "$r2o_donor_core/x25519.o" -Wl,--gc-sections -pthread
    "$r2o_baseline_binary" >"$r2o_baseline_c"
    R2O_HTTP_BASELINE_DIFF_OUTPUT="$r2o_baseline_rust" \
        cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
            http_baseline_replays_donor_keepalive_paths_on_one_stream \
            --locked --offline -- --nocapture
    diff -u "$r2o_baseline_c" "$r2o_baseline_rust"
    printf 'C/Rust HTTP baseline: %s\n' "$(cat "$r2o_baseline_c")"
    printf '\nСопоставление классификатора C/Rust на общей фикстуре\n'
    r2o_judge_fixture="$r2o_script_dir/crates/r2o-controller/tests/fixtures/d2o_http_challenge_response.bin"
    r2o_judge_harness="$r2o_script_dir/crates/r2o-controller/tests/d2o_http_judge_differential.c"
    r2o_judge_binary="$r2o_log_dir/http-judge-differential-$$"
    r2o_rust_answer="$r2o_log_dir/http-judge-rust-answer-$$"
    clang-18 -std=c99 -O2 -Wall -Wextra -Werror \
        -I"$r2o_donor_core/include" -I"$r2o_donor_core/../datapath/include" \
        -o "$r2o_judge_binary" "$r2o_judge_harness" \
        "$r2o_donor_core/httpsearch.c" "$r2o_donor_core/httpup_logic.c" \
        "$r2o_donor_core/plantlv.o" "$r2o_donor_core/quic.o" \
        "$r2o_donor_core/quicwire.o" "$r2o_donor_core/crypto.o" \
        "$r2o_donor_core/../datapath/plan_parse.c" \
        "$r2o_donor_core/../datapath/plan_apply.c" \
        "$r2o_donor_core/../datapath/wire.c" \
        "$r2o_donor_core/verify.o" "$r2o_donor_core/quicconn.o" \
        "$r2o_donor_core/h3.o" "$r2o_donor_core/tls12.o" \
        "$r2o_donor_core/p256.o" "$r2o_donor_core/compose.o" \
        "$r2o_donor_core/measured.o" "$r2o_donor_core/hello.o" \
        "$r2o_donor_core/meas.o" "$r2o_donor_core/link.o" \
        "$r2o_donor_core/tls13.o" "$r2o_donor_core/tls13core.o" \
        "$r2o_donor_core/x25519.o"
    r2o_c_answer=$("$r2o_judge_binary" "$r2o_judge_fixture")
    r2o_run_timed 'суждение HTTP-ответа в Rust' \
        env R2O_HTTP_JUDGE_DIFF_OUTPUT="$r2o_rust_answer" \
        cargo +1.98.0 test -p r2o-controller --lib \
            cf_challenge_response_is_judged_like_donor --locked --offline -- --nocapture
    r2o_rust_answer_value=$(cat "$r2o_rust_answer")
    if [ "$r2o_c_answer" != "$r2o_rust_answer_value" ]; then
        printf 'C/Rust HTTP-judge mismatch: C=%s Rust=%s\n' \
            "$r2o_c_answer" "$r2o_rust_answer_value" >&2
        exit 1
    fi
    printf 'C/Rust HTTP-judge: %s (REAL)\n' "$r2o_c_answer"
    printf '\nСверка сохранённого CUT-контекста при последующем портале\n'
    r2o_cut_context_harness="$r2o_script_dir/crates/r2o-controller/tests/d2o_http_cut_context_differential.c"
    r2o_cut_context_binary="$r2o_log_dir/http-cut-context-differential-$$"
    r2o_cut_context_c="$r2o_log_dir/http-cut-context-c-$$"
    r2o_cut_context_rust="$r2o_log_dir/http-cut-context-rust-$$"
    clang-18 -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
        -I"$r2o_donor_core/include" -I"$r2o_donor_core/../datapath/include" \
        -o "$r2o_cut_context_binary" \
        "$r2o_cut_context_harness" "$r2o_donor_core/httpsearch.c" \
        "$r2o_donor_core/httpup_logic.c" "$r2o_donor_core/plantlv.o" \
        "$r2o_donor_core/quic.o" "$r2o_donor_core/quicwire.o" \
        "$r2o_donor_core/crypto.o" "$r2o_donor_core/../datapath/plan_parse.c" \
        "$r2o_donor_core/../datapath/plan_apply.c" \
        "$r2o_donor_core/../datapath/wire.c" "$r2o_donor_core/verify.o" \
        "$r2o_donor_core/quicconn.o" "$r2o_donor_core/h3.o" \
        "$r2o_donor_core/tls12.o" "$r2o_donor_core/p256.o" \
        "$r2o_donor_core/compose.o" "$r2o_donor_core/measured.o" \
        "$r2o_donor_core/hello.o" "$r2o_donor_core/meas.o" \
        "$r2o_donor_core/link.o" "$r2o_donor_core/tls13.o" \
        "$r2o_donor_core/tls13core.o" "$r2o_donor_core/x25519.o" \
        -Wl,--gc-sections -pthread
    "$r2o_cut_context_binary" >"$r2o_cut_context_c"
    R2O_HTTP_CUT_CONTEXT_DIFF_OUTPUT="$r2o_cut_context_rust" \
        cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
            r2o_http_cut_context_survives_a_later_portal \
            --locked --offline -- --nocapture
    diff -u "$r2o_cut_context_c" "$r2o_cut_context_rust"
    printf 'C/Rust HTTP CUT context: %s' "$(cat "$r2o_cut_context_c")"
    printf '\nСверка очереди HTTP на общей фикстуре\n'
    r2o_queue_fixture="$r2o_script_dir/crates/r2o-controller/tests/fixtures/d2o_http_queue.tsv"
    r2o_queue_harness="$r2o_script_dir/crates/r2o-controller/tests/d2o_http_queue_differential.c"
    r2o_queue_binary="$r2o_log_dir/http-queue-differential-$$"
    r2o_queue_rust="$r2o_log_dir/http-queue-rust-$$"
    clang-18 -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
        -I"$r2o_donor_core/include" -I"$r2o_donor_core/../datapath/include" \
        -o "$r2o_queue_binary" "$r2o_queue_harness" \
        "$r2o_donor_core/httpsearch.c" "$r2o_donor_core/httpup_logic.c" \
        "$r2o_donor_core/plantlv.o" "$r2o_donor_core/quic.o" \
        "$r2o_donor_core/quicwire.o" "$r2o_donor_core/crypto.o" \
        "$r2o_donor_core/../datapath/plan_parse.c" \
        "$r2o_donor_core/../datapath/plan_apply.c" \
        "$r2o_donor_core/../datapath/wire.c" \
        "$r2o_donor_core/verify.o" "$r2o_donor_core/quicconn.o" \
        "$r2o_donor_core/h3.o" "$r2o_donor_core/tls12.o" \
        "$r2o_donor_core/p256.o" "$r2o_donor_core/compose.o" \
        "$r2o_donor_core/measured.o" "$r2o_donor_core/hello.o" \
        "$r2o_donor_core/meas.o" "$r2o_donor_core/link.o" \
        "$r2o_donor_core/tls13.o" "$r2o_donor_core/tls13core.o" \
        "$r2o_donor_core/x25519.o" -Wl,--gc-sections -pthread
    r2o_queue_c=$("$r2o_queue_binary" "$r2o_queue_fixture")
    r2o_run_timed 'очередь HTTP в Rust' \
        env R2O_HTTP_QUEUE_DIFF_OUTPUT="$r2o_queue_rust" \
        cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
            http_search_queue_matches_the_unbounded_donor_queue --locked --offline -- --nocapture
    r2o_queue_rust_value=$(cat "$r2o_queue_rust")
    if [ "$r2o_queue_c" != "$r2o_queue_rust_value" ]; then
        printf 'C/Rust HTTP queue mismatch: C=%s Rust=%s\n' \
            "$r2o_queue_c" "$r2o_queue_rust_value" >&2
        exit 1
    fi
    printf 'C/Rust HTTP queued count: %s\n' "$r2o_queue_c"
    printf '\nСверка повтора при отсутствии судимых проб HTTP\n'
    r2o_no_exec_binary="$r2o_log_dir/http-no-executed-differential-$$"
    r2o_no_exec_c="$r2o_log_dir/http-no-executed-c-$$"
    r2o_no_exec_rust="$r2o_log_dir/http-no-executed-rust-$$"
    clang-18 -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
        -I"$r2o_donor_core" -I"$r2o_donor_core/include" -I"$r2o_donor_core/../datapath/include" \
        -o "$r2o_no_exec_binary" \
        "$r2o_script_dir/crates/r2o-controller/tests/d2o_http_no_executed_differential.c" \
        "$r2o_donor_core/httpup_logic.c" "$r2o_donor_core/plantlv.o" \
        "$r2o_donor_core/quic.o" "$r2o_donor_core/quicwire.o" "$r2o_donor_core/crypto.o" \
        "$r2o_donor_core/../datapath/plan_parse.c" \
        "$r2o_donor_core/../datapath/plan_apply.c" \
        "$r2o_donor_core/../datapath/wire.c" \
        "$r2o_donor_core/verify.o" "$r2o_donor_core/quicconn.o" "$r2o_donor_core/h3.o" \
        "$r2o_donor_core/tls12.o" "$r2o_donor_core/p256.o" "$r2o_donor_core/compose.o" \
        "$r2o_donor_core/measured.o" "$r2o_donor_core/hello.o" "$r2o_donor_core/meas.o" \
        "$r2o_donor_core/link.o" "$r2o_donor_core/tls13.o" "$r2o_donor_core/tls13core.o" \
        "$r2o_donor_core/x25519.o" -Wl,--gc-sections -pthread
    "$r2o_no_exec_binary" >"$r2o_no_exec_c"
    R2O_HTTP_NO_EXECUTED_DIFF_OUTPUT="$r2o_no_exec_rust" \
        cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline \
            http_no_executed_trial_matches_d2o
    diff -u "$r2o_no_exec_c" "$r2o_no_exec_rust"
    printf 'C/Rust HTTP no executed trial: %s\n' "$(cat "$r2o_no_exec_c")"
    printf '\nТест Rust повторов базового HTTP-зонда\n'
    r2o_run_timed 'повторы baseline в Rust' \
        cargo +1.98.0 test -p r2o-controller --bin r2o-controller \
            baseline_local_failure_and_cut_silence_follow_donor_retry_rules \
            --locked --offline -- --nocapture
} >"$r2o_log" 2>&1

grep -q 'test_httpsearch: все проверки прошли' "$r2o_log"
grep -q 'C/Rust HTTP-judge: 1 (REAL)' "$r2o_log"
grep -q 'C/Rust HTTP CUT context: request_path=/watch/first' "$r2o_log"
grep -q 'C/Rust HTTP queued count: http_queued=32' "$r2o_log"
grep -q 'C/Rust HTTP no executed trial: cooldown_ms=300000' "$r2o_log"
grep -q 'baseline_local_failure_and_cut_silence_follow_donor_retry_rules .*ok' "$r2o_log"
printf 'Журнал дифференциальной проверки: %s\n' "$r2o_log"
cat "$r2o_log"
trap - EXIT
