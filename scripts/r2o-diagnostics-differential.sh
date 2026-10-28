#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/d2o"}
donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
test "$(git -C "$donor_root" rev-parse HEAD)" = "$donor_sha"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/r2o-diagnostics-diff.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

clang-18 -std=c99 -O2 -Wall -Wextra -Werror \
    -DD2K_RELEASE_ID='"dev"' -I"$donor_root/core/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_diagnostics_differential.c" \
    "$donor_root/core/diagnostics.c" -o "$tmp_dir/d2o-diagnostics"
"$tmp_dir/d2o-diagnostics" >"$tmp_dir/c.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); e=d["events"][0]; e.pop("at"); s=d["samples"][0]; print("ring_bytes=%s\nevent_json=%s\nevent_id=%s\nreason_hex=%s\nsnapshots=%s\nhttp_records=%s\nhttp_queued=%s" % (d["ring_bytes"],json.dumps(e,sort_keys=True,separators=(",",":")),e["id"],e["reason"].encode().hex(),s["snapshots"],s["http_records"],s["http_queued"]))' "$tmp_dir/c.json" >"$tmp_dir/c.out"
cd "$repo_root"
R2O_DIAGNOSTICS_DIFF_OUTPUT="$tmp_dir/rust.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked --offline \
        diagnostics_id_and_counts_match_d2o
diff -u "$tmp_dir/c.out" "$tmp_dir/rust.out"
printf 'C/Rust diagnostic event and snapshot counters match d2o %s.\n' "$donor_sha"
cat "$tmp_dir/c.out"

mkdir -p "$tmp_dir/proc/123" "$tmp_dir/run"
printf '123\n' >"$tmp_dir/run/d2k.pid"
printf 'd2kc\n' >"$tmp_dir/proc/123/comm"
printf 'VmRSS: 1024 kB\n' >"$tmp_dir/proc/123/status"
"$tmp_dir/d2o-diagnostics" --process-exit "$tmp_dir" >"$tmp_dir/c-exit.json"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["memory_details"][0]; print("first_pid=%s\nlatest_null=%s" % (d["first"]["pid"], str(d["latest"] is None).lower()))' "$tmp_dir/c-exit.json" >"$tmp_dir/c-exit.out"
if ! R2O_DIAG_EXIT_DIFF_OUTPUT="$tmp_dir/rust-exit.out" cargo +1.98.0 test -p r2o-controller --lib --locked --offline first_process_detail_survives_process_exit_like_d2o; then
    diff -u "$tmp_dir/c-exit.out" "$tmp_dir/rust-exit.out" || true
    exit 1
fi
diff -u "$tmp_dir/c-exit.out" "$tmp_dir/rust-exit.out"
printf 'C/Rust first memory detail survives process exit.\n'

donor_core="$donor_root/core"
clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -DD2K_RELEASE_ID='"dev"' -I"$donor_core" -I"$donor_core/include" \
    -I"$donor_root/datapath/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_diagnostics_snapshot_differential.c" \
    -Wl,--gc-sections -pthread -o "$tmp_dir/d2o-snapshots"
"$tmp_dir/d2o-snapshots" >"$tmp_dir/c-snapshots.out"
R2O_DIAGNOSTICS_SNAPSHOT_DIFF_OUTPUT="$tmp_dir/rust-snapshots.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline \
        discovery_diagnostic_snapshot_count_matches_d2o_queued_quic_snapshot_rule
diff -u "$tmp_dir/c-snapshots.out" "$tmp_dir/rust-snapshots.out"
printf 'C/Rust discovery snapshot count matches d2o %s.\n' "$donor_sha"

make -s -C "$donor_core" test_httpsearch CC=clang-18
clang-18 -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -DD2K_RELEASE_ID='"dev"' -I"$donor_core/include" -I"$donor_root/datapath/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_http_diagnostic_differential.c" \
    "$donor_core/diagnostics.c" "$donor_core/httpsearch.c" "$donor_core/httpup_logic.c" \
    "$donor_core/plantlv.o" "$donor_core/quic.o" "$donor_core/quicwire.o" \
    "$donor_core/crypto.o" "$donor_root/datapath/plan_parse.c" \
    "$donor_root/datapath/plan_apply.c" "$donor_root/datapath/wire.c" \
    "$donor_core/verify.o" "$donor_core/quicconn.o" "$donor_core/h3.o" \
    "$donor_core/tls12.o" "$donor_core/p256.o" "$donor_core/compose.o" \
    "$donor_core/measured.o" "$donor_core/hello.o" "$donor_core/meas.o" \
    "$donor_core/link.o" "$donor_core/tls13.o" "$donor_core/tls13core.o" \
    "$donor_core/x25519.o" -Wl,--gc-sections -pthread -o "$tmp_dir/d2o-http-diagnostic"
"$tmp_dir/d2o-http-diagnostic" >"$tmp_dir/c-http.json"
R2O_HTTP_DIAGNOSTIC_DIFF_OUTPUT="$tmp_dir/rust-http.json" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline \
        http_search_diagnostic_event_matches_d2o_http_defaults
python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["events"][0]; c.pop("at"); r=json.load(open(sys.argv[2])); assert c==r, "C=%r Rust=%r" % (c,r)' "$tmp_dir/c-http.json" "$tmp_dir/rust-http.json"
printf 'C/Rust HTTP diagnostic event matches d2o %s.\n' "$donor_sha"

donor_core="$donor_root/core"
clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -DD2K_RELEASE_ID='"dev"' -I"$donor_core" -I"$donor_core/include" \
    -I"$donor_root/datapath/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_scheduler_diagnostic_differential.c" \
    -Wl,--gc-sections -pthread -o "$tmp_dir/d2o-scheduler-diagnostic"
"$tmp_dir/d2o-scheduler-diagnostic" >"$tmp_dir/c-scheduler-diagnostic.out"
R2O_SCHED_DIAGNOSTIC_DIFF_OUTPUT="$tmp_dir/rust-scheduler-diagnostic.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline \
        discovery_diagnostic_report_id_and_trigger_match_d2o
diff -u "$tmp_dir/c-scheduler-diagnostic.out" "$tmp_dir/rust-scheduler-diagnostic.out"
printf 'C/Rust scheduler report ID and trigger match d2o %s.\n' "$donor_sha"

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -DD2K_RELEASE_ID='"dev"' -I"$donor_core" -I"$donor_core/include" \
    -I"$donor_root/datapath/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_scheduler_queue_full_differential.c" \
    -Wl,--gc-sections -pthread -o "$tmp_dir/d2o-scheduler-queue-full"
"$tmp_dir/d2o-scheduler-queue-full" >"$tmp_dir/c-scheduler-queue-full.out"
R2O_SCHED_QUEUE_FULL_DIFF_OUTPUT="$tmp_dir/rust-scheduler-queue-full.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline \
        discovery_queue_full_consumes_the_d2o_report_id
diff -u "$tmp_dir/c-scheduler-queue-full.out" "$tmp_dir/rust-scheduler-queue-full.out"
printf 'C/Rust queue-full scheduler report matches d2o %s.\n' "$donor_sha"

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -DD2K_RELEASE_ID='"dev"' -I"$donor_core" -I"$donor_core/include" \
    -I"$donor_root/datapath/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_scheduler_timing_differential.c" \
    -Wl,--gc-sections -pthread -o "$tmp_dir/d2o-scheduler-timing"
"$tmp_dir/d2o-scheduler-timing" >"$tmp_dir/c-scheduler-timing.out"
R2O_SCHED_TIMING_DIFF_OUTPUT="$tmp_dir/rust-scheduler-timing.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline \
        discovery_diagnostic_elapsed_includes_queue_time_like_d2o
diff -u "$tmp_dir/c-scheduler-timing.out" "$tmp_dir/rust-scheduler-timing.out"
printf 'C/Rust scheduler elapsed, queue time and probe units match d2o %s.\n' "$donor_sha"

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -DD2K_RELEASE_ID='"dev"' -I"$donor_core" -I"$donor_core/include" \
    -I"$donor_root/datapath/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_scheduler_voice_diagnostic_differential.c" \
    -Wl,--gc-sections -pthread -o "$tmp_dir/d2o-scheduler-voice-diagnostic"
"$tmp_dir/d2o-scheduler-voice-diagnostic" >"$tmp_dir/c-scheduler-voice-diagnostic.out"
R2O_SCHED_VOICE_DIAGNOSTIC_DIFF_OUTPUT="$tmp_dir/rust-scheduler-voice-diagnostic.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline \
        voice_probe_clear_diagnostic_event_matches_d2o
diff -u "$tmp_dir/c-scheduler-voice-diagnostic.out" "$tmp_dir/rust-scheduler-voice-diagnostic.out"
printf 'C/Rust voice probe-clear diagnostic event matches d2o %s.\n' "$donor_sha"

: >"$tmp_dir/c-scheduler-voice-fallback.out"
"$tmp_dir/d2o-scheduler-voice-diagnostic" probe-clear unknown \
    >>"$tmp_dir/c-scheduler-voice-fallback.out"
"$tmp_dir/d2o-scheduler-voice-diagnostic" inconclusive none \
    >>"$tmp_dir/c-scheduler-voice-fallback.out"
R2O_SCHED_VOICE_FALLBACK_DIAGNOSTIC_DIFF_OUTPUT="$tmp_dir/rust-scheduler-voice-fallback.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline \
        voice_fallback_diagnostic_uses_the_d2o_measurement_verdict
diff -u "$tmp_dir/c-scheduler-voice-fallback.out" "$tmp_dir/rust-scheduler-voice-fallback.out"
printf 'C/Rust voice Discovery-to-fallback diagnostics match d2o %s.\n' "$donor_sha"

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -DD2K_RELEASE_ID='"dev"' -I"$donor_core" -I"$donor_core/include" \
    -I"$donor_root/datapath/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_scheduler_voice_terminal_diagnostic_differential.c" \
    -Wl,--gc-sections -pthread -o "$tmp_dir/d2o-scheduler-voice-terminal-diagnostic"
: >"$tmp_dir/c-scheduler-voice-terminal.out"
for outcome in discovery-confirmed stun-confirmed failed cancelled; do
    "$tmp_dir/d2o-scheduler-voice-terminal-diagnostic" "$outcome" >>"$tmp_dir/c-scheduler-voice-terminal.out"
done
R2O_SCHED_VOICE_TERMINAL_DIAGNOSTIC_DIFF_OUTPUT="$tmp_dir/rust-scheduler-voice-terminal.out" \
    cargo +1.98.0 test -p r2o-controller --bin r2o-controller --locked --offline \
        voice_trial_terminal_diagnostic_event_matches_d2o
diff -u "$tmp_dir/c-scheduler-voice-terminal.out" "$tmp_dir/rust-scheduler-voice-terminal.out"
printf 'C/Rust voice trial terminal diagnostic events match d2o %s.\n' "$donor_sha"

clang-18 -std=c99 -O2 -Wall -Wextra -Werror -DD2K_RELEASE_ID='"dev"' \
    -I"$donor_core/include" -I"$donor_root/datapath/include" -I"$donor_root/runtime" \
    "$repo_root/crates/r2o-controller/tests/d2o_quic_base_differential.c" \
    "$donor_core/props.c" "$donor_core/quicprobe.c" "$donor_core/quicsnap.c" \
    "$donor_core/quicsnap_reseal.c" "$donor_core/quicarms.c" "$donor_core/ipfrag.c" \
    "$donor_core/net4.c" "$donor_core/quichello.c" "$donor_core/hello.c" \
    "$donor_core/tls13core.c" "$donor_core/x25519.c" "$donor_core/quic.c" \
    "$donor_core/quicwire.c" "$donor_core/crypto.c" "$donor_core/meas.c" \
    "$donor_core/quicconn.c" "$donor_core/h3.c" "$donor_core/udpplan.c" \
    "$donor_core/udpruntime.c" "$donor_core/plantlv.c" \
    "$donor_root/datapath/plan_parse.c" "$donor_root/datapath/plan_apply.c" \
    "$donor_root/datapath/wire.c" "$donor_root/datapath/wire_udp.c" \
    -pthread -o "$tmp_dir/d2o-quic-base"
"$tmp_dir/d2o-quic-base" profile >"$tmp_dir/c-quic-profile.out"
R2O_QUIC_PROFILE_DIFF_OUTPUT="$tmp_dir/rust-quic-profile.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked --offline \
        r2o_quic_profile_clienthello_matches_d2o_donor_shape
diff -u "$tmp_dir/c-quic-profile.out" "$tmp_dir/rust-quic-profile.out"
printf 'C/Rust QUIC donor ClientHello profile matches d2o %s.\n' "$donor_sha"

"$tmp_dir/d2o-quic-base" verify >"$tmp_dir/c-quic-donor-verify.out"
R2O_QUIC_DONOR_VERIFY_DIFF_OUTPUT="$tmp_dir/rust-quic-donor-verify.out" \
    cargo +1.98.0 test -p r2k-core --lib --locked --offline \
        критерий_ответа_quic_совпадает_с_donor_parse
diff -u "$tmp_dir/c-quic-donor-verify.out" "$tmp_dir/rust-quic-donor-verify.out"
printf 'C/Rust QUIC donor response criterion matches d2o %s.\n' "$donor_sha"

"$tmp_dir/d2o-quic-base" parallel >"$tmp_dir/c-quic-parallel.out"
R2O_QUIC_DONOR_PARALLEL_DIFF_OUTPUT="$tmp_dir/rust-quic-parallel.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked --offline \
        r2o_quic_donor_parallel_control_matches_d2o
diff -u "$tmp_dir/c-quic-parallel.out" "$tmp_dir/rust-quic-parallel.out"
printf 'C/Rust parallel QUIC control, fresh ports and donor answers match d2o %s.\n' "$donor_sha"

"$tmp_dir/d2o-quic-base" vn >"$tmp_dir/c-quic-vn.out"
R2O_QUIC_VN_DIFF_OUTPUT="$tmp_dir/rust-quic-vn.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked --offline \
        r2o_quic_version_negotiation_uses_donor_parallel_answers
diff -u "$tmp_dir/c-quic-vn.out" "$tmp_dir/rust-quic-vn.out"
printf 'C/Rust QUIC silent-control Version Negotiation branch matches d2o %s.\n' "$donor_sha"

"$tmp_dir/d2o-quic-base" >"$tmp_dir/c-quic-base.out"
R2O_QUIC_BASE_DIFF_OUTPUT="$tmp_dir/rust-quic-base.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked --offline \
        r2o_quic_base_result_matches_d2o
diff -u "$tmp_dir/c-quic-base.out" "$tmp_dir/rust-quic-base.out"
printf 'C/Rust QUIC base decision matches d2o %s.\n' "$donor_sha"

"$tmp_dir/d2o-quic-base" decision >"$tmp_dir/c-quic-direct-action.out"
R2O_QUIC_DIRECT_ACTION_DIFF_OUTPUT="$tmp_dir/rust-quic-direct-action.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked --offline \
        r2o_quic_direct_action_matches_d2o_classify_run
diff -u "$tmp_dir/c-quic-direct-action.out" "$tmp_dir/rust-quic-direct-action.out"
printf 'C/Rust QUIC direct Initial follow-up matches d2o %s.\n' "$donor_sha"

"$tmp_dir/d2o-quic-base" data >"$tmp_dir/c-quic-direct-data.out"
R2O_QUIC_DIRECT_HTTP3_DIFF_OUTPUT="$tmp_dir/rust-quic-direct-data.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked --offline \
        r2o_quic_direct_http3_repeat_gate_matches_d2o_classify_run
diff -u "$tmp_dir/c-quic-direct-data.out" "$tmp_dir/rust-quic-direct-data.out"
printf 'C/Rust QUIC direct HTTP/3 repeat gate matches d2o %s.\n' "$donor_sha"

clang-18 -std=c99 -O2 -Wall -Wextra -Werror -I"$donor_core/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_quic_http3_differential.c" \
    -o "$tmp_dir/d2o-quic-http3"
"$tmp_dir/d2o-quic-http3" content-length >"$tmp_dir/c-quic-content-length.out"
R2O_QUIC_HTTP3_CONTENT_LENGTH_DIFF_OUTPUT="$tmp_dir/rust-quic-content-length.out" \
    cargo +1.98.0 test -p r2o-controller --test r2o_quic_http3 --locked --offline \
        content_length -- --nocapture
diff -u "$tmp_dir/c-quic-content-length.out" "$tmp_dir/rust-quic-content-length.out"
printf 'C/Rust HTTP/3 complete response ignores Content-Length mismatch like d2o.\n'

"$tmp_dir/d2o-quic-http3" large-body >"$tmp_dir/c-quic-large-body.out"
R2O_QUIC_HTTP3_LARGE_BODY_DIFF_OUTPUT="$tmp_dir/rust-quic-large-body.out" \
    cargo +1.98.0 test -p r2o-controller --test r2o_quic_http3 --locked --offline \
        не_обрезает_ответ -- --nocapture
diff -u "$tmp_dir/c-quic-large-body.out" "$tmp_dir/rust-quic-large-body.out"
printf 'C/Rust HTTP/3 response beyond 16 MiB matches d2o.\n'

"$tmp_dir/d2o-quic-http3" stream-bytes >"$tmp_dir/c-quic-stream-bytes.out"
R2O_QUIC_HTTP3_STREAM_BYTES_DIFF_OUTPUT="$tmp_dir/rust-quic-stream-bytes.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked --offline \
        незавершённый_http3_порог_использует_байты_потока
diff -u "$tmp_dir/c-quic-stream-bytes.out" "$tmp_dir/rust-quic-stream-bytes.out"
printf 'C/Rust HTTP/3 incomplete-response threshold uses target stream bytes like d2o.\n'

"$tmp_dir/d2o-quic-http3" budget-next-stream >"$tmp_dir/c-quic-budget-next-stream.out"
R2O_QUIC_HTTP3_NEXT_STREAM_DIFF_OUTPUT="$tmp_dir/rust-quic-budget-next-stream.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked --offline \
        r2o_quic_бюджет_может_пройти_по_заголовкам_следующего_потока_как_d2o
diff -u "$tmp_dir/c-quic-budget-next-stream.out" "$tmp_dir/rust-quic-budget-next-stream.out"
printf 'C/Rust HTTP/3 budget can pass on growth in the next response stream like d2o.\n'

"$tmp_dir/d2o-quic-base" residual >"$tmp_dir/c-quic-residual.out"
R2O_QUIC_RESIDUAL_DIFF_OUTPUT="$tmp_dir/rust-quic-residual.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked --offline \
        r2o_quic_residual_control_and_address_pool_match_d2o
diff -u "$tmp_dir/c-quic-residual.out" "$tmp_dir/rust-quic-residual.out"
printf 'C/Rust QUIC residual control and address rotation match d2o %s.\n' "$donor_sha"

diag_tick_dir="$tmp_dir/d2kc-diagnostics"
clang-18 -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -DD2K_RELEASE_ID='"dev"' "-DD2K_DIAG_DIR=\"$diag_tick_dir\"" \
    -I"$donor_core" -I"$donor_core/include" -I"$donor_root/runtime" \
    -I"$donor_root/datapath/include" \
    "$repo_root/crates/r2o-controller/tests/d2o_diagnostic_tick_differential.c" \
    "$donor_core/diagnostics.c" -Wl,--gc-sections -o "$tmp_dir/d2o-diagnostic-tick"
"$tmp_dir/d2o-diagnostic-tick" >"$tmp_dir/c-diagnostic-tick.out"
R2O_DIAGNOSTIC_TICK_DIFF_OUTPUT="$tmp_dir/rust-diagnostic-tick.out" \
    cargo +1.98.0 test -p r2o-controller --lib --locked --offline \
        diagnostic_tick_lifecycle_matches_d2o -- --nocapture
diff -u "$tmp_dir/c-diagnostic-tick.out" "$tmp_dir/rust-diagnostic-tick.out"
printf 'C/Rust d2kc diagnostic tick lifecycle matches d2o %s.\n' "$donor_sha"
