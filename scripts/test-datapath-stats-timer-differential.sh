#!/bin/sh
set -eu

d2o_datapath=${D2O_DATAPATH:-/tmp/d2kd-stats-c}
r2o_datapath=${R2O_DATAPATH:-/tmp/r2o-datapath}
queue=${R2O_TEST_QUEUE:-2002}
test_tmpdir=${R2O_TEST_TMPDIR:-${TMPDIR:-/tmp}}
running_pid=

mkdir -p "$test_tmpdir"

cleanup() {
    if [ -n "$running_pid" ]; then
        kill -TERM "$running_pid" 2>/dev/null || true
        wait "$running_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

run_case() {
    name=$1
    binary=$2
    pattern=$3
    log="$test_tmpdir/r2o-stats-diff-${name}.log"
    rm -f "$log"
    "$binary" --queue "$queue" --mode observe --stats 1 >"$log" 2>&1 &
    running_pid=$!
    sleep 3
    kill -TERM "$running_pid"
    wait "$running_pid"
    running_pid=
    count=$(grep -Fc -e "$pattern" "$log" || true)
    echo "${name}_summary_lines=$count"
    if [ "$count" -lt 2 ]; then cat "$log"; exit 1; fi
}

run_case d2o "$d2o_datapath" '--- d2kd['
run_case r2o "$r2o_datapath" 'r2o-datapath: TCP'

c_values=$(grep -E 'TCP.*UDP' "$test_tmpdir/r2o-stats-diff-d2o.log" | head -n 2 | sed -E 's/[^0-9]+/ /g' | sed '/^ *$/d')
r_values=$(grep -E 'TCP.*UDP' "$test_tmpdir/r2o-stats-diff-r2o.log" | head -n 2 | sed -E 's/^r2o-datapath: //' | sed -E 's/[^0-9]+/ /g' | sed '/^ *$/d')
if [ "$c_values" != "$r_values" ]; then
    echo "D2O flow-table statistics differ from R2O" >&2
    printf 'C:\n%s\nRust:\n%s\n' "$c_values" "$r_values" >&2
    exit 1
fi
echo 'flow_table_stats_numeric_trace=identical'

c_capture_count=$(grep -Fc 'снимки TCP:' "$test_tmpdir/r2o-stats-diff-d2o.log" || true)
r_capture_count=$(grep -Fc 'снимки TLS/TCP:' "$test_tmpdir/r2o-stats-diff-r2o.log" || true)
c_stats_count=$(grep -Fc -- '--- d2kd[' "$test_tmpdir/r2o-stats-diff-d2o.log" || true)
r_stats_count=$(grep -Fc 'r2o-datapath: TCP' "$test_tmpdir/r2o-stats-diff-r2o.log" || true)
if [ "$c_capture_count" -lt 2 ] || [ "$r_capture_count" -lt 2 ]; then
    echo "expected periodic and shutdown capture summaries, got C=$c_capture_count Rust=$r_capture_count" >&2
    exit 1
fi
if [ "$c_capture_count" -ne "$c_stats_count" ] || [ "$r_capture_count" -ne "$r_stats_count" ]; then
    echo "capture summaries must appear exactly once per full stats summary: C=$c_capture_count/$c_stats_count Rust=$r_capture_count/$r_stats_count" >&2
    exit 1
fi
c_capture_values=$(grep 'снимки TCP:' "$test_tmpdir/r2o-stats-diff-d2o.log" | head -n 2 | sed -E 's/^.*: *//' | sed -E 's/[^0-9]+/ /g')
r_capture_values=$(grep 'снимки TLS/TCP:' "$test_tmpdir/r2o-stats-diff-r2o.log" | head -n 2 | sed -E 's/^.*: *//' | sed -E 's/[^0-9]+/ /g')
if [ "$c_capture_values" != "$r_capture_values" ]; then
    echo "D2O capture statistics differ from R2O" >&2
    printf 'C:\n%s\nRust:\n%s\n' "$c_capture_values" "$r_capture_values" >&2
    exit 1
fi
echo 'capture_stats_numeric_trace=identical'

c_visibility_count=$(grep -Fc 'ответ невидим очереди:' "$test_tmpdir/r2o-stats-diff-d2o.log" || true)
r_visibility_count=$(grep -Fc 'ответ невидим очереди:' "$test_tmpdir/r2o-stats-diff-r2o.log" || true)
if [ "$c_visibility_count" -ne "$c_stats_count" ] || [ "$r_visibility_count" -ne "$r_stats_count" ]; then
    echo "reply-visibility counters must appear once per full stats summary: C=$c_visibility_count/$c_stats_count Rust=$r_visibility_count/$r_stats_count" >&2
    exit 1
fi
c_visibility_values=$(grep 'ответ невидим очереди:' "$test_tmpdir/r2o-stats-diff-d2o.log" | head -n 2 | sed -E 's/[^0-9]+/ /g')
r_visibility_values=$(grep 'ответ невидим очереди:' "$test_tmpdir/r2o-stats-diff-r2o.log" | head -n 2 | sed -E 's/^r2o-datapath: //' | sed -E 's/[^0-9]+/ /g')
if [ "$c_visibility_values" != "$r_visibility_values" ]; then
    echo "D2O reply-visibility statistics differ from R2O" >&2
    printf 'C:\n%s\nRust:\n%s\n' "$c_visibility_values" "$r_visibility_values" >&2
    exit 1
fi
echo 'reply_visibility_stats_numeric_trace=identical'

c_hold_count=$(grep -Fc 'составной вход:' "$test_tmpdir/r2o-stats-diff-d2o.log" || true)
r_hold_count=$(grep -Fc 'составной вход:' "$test_tmpdir/r2o-stats-diff-r2o.log" || true)
if [ "$c_hold_count" -ne "$c_stats_count" ] || [ "$r_hold_count" -ne "$r_stats_count" ]; then
    echo "hold counters must appear once per full stats summary: C=$c_hold_count/$c_stats_count Rust=$r_hold_count/$r_stats_count" >&2
    exit 1
fi
c_hold_values=$(grep 'составной вход:' "$test_tmpdir/r2o-stats-diff-d2o.log" | head -n 2 | sed -E 's/^.*: *//' | sed -E 's/[^0-9]+/ /g')
r_hold_values=$(grep 'составной вход:' "$test_tmpdir/r2o-stats-diff-r2o.log" | head -n 2 | sed -E 's/^r2o-datapath: составной вход: //' | sed -E 's/[^0-9]+/ /g')
if [ "$c_hold_values" != "$r_hold_values" ]; then
    echo "D2O hold statistics differ from R2O" >&2
    printf 'C:\n%s\nRust:\n%s\n' "$c_hold_values" "$r_hold_values" >&2
    exit 1
fi
echo 'hold_stats_numeric_trace=identical'

c_payload_count=$(grep -Fc 'нагрузка мимо приветствия:' "$test_tmpdir/r2o-stats-diff-d2o.log" || true)
r_payload_count=$(grep -Fc 'нагрузка мимо приветствия:' "$test_tmpdir/r2o-stats-diff-r2o.log" || true)
c_next_segment_count=$(grep -Fc 'имя уехало во второй сегмент:' "$test_tmpdir/r2o-stats-diff-d2o.log" || true)
r_next_segment_count=$(grep -Fc 'имя ClientHello в следующем сегменте:' "$test_tmpdir/r2o-stats-diff-r2o.log" || true)
if [ "$c_payload_count" -ne "$c_stats_count" ] || [ "$r_payload_count" -ne "$r_stats_count" ] \
    || [ "$c_next_segment_count" -ne "$c_stats_count" ] || [ "$r_next_segment_count" -ne "$r_stats_count" ]; then
    echo "payload/session counters must appear once per full stats summary: payload C=$c_payload_count/$c_stats_count Rust=$r_payload_count/$r_stats_count, next-segment C=$c_next_segment_count/$c_stats_count Rust=$r_next_segment_count/$r_stats_count" >&2
    exit 1
fi
c_payload_values=$(grep 'нагрузка мимо приветствия:' "$test_tmpdir/r2o-stats-diff-d2o.log" | head -n 2 | sed -E 's/ \(первый байт.*$//' | sed -E 's/^.*: *//' | sed -E 's/[^0-9]+/ /g')
r_payload_values=$(grep 'нагрузка мимо приветствия:' "$test_tmpdir/r2o-stats-diff-r2o.log" | head -n 2 | sed -E 's/ \(первый байт.*$//' | sed -E 's/^.*: *//' | sed -E 's/[^0-9]+/ /g')
c_next_segment_values=$(grep 'имя уехало во второй сегмент:' "$test_tmpdir/r2o-stats-diff-d2o.log" | head -n 2 | sed -E 's/^.*: *//' | sed -E 's/[^0-9]+/ /g')
r_next_segment_values=$(grep 'имя ClientHello в следующем сегменте:' "$test_tmpdir/r2o-stats-diff-r2o.log" | head -n 2 | sed -E 's/^.*: *//' | sed -E 's/[^0-9]+/ /g')
if [ "$c_payload_values" != "$r_payload_values" ] || [ "$c_next_segment_values" != "$r_next_segment_values" ]; then
    echo "D2O payload/session counters differ from R2O" >&2
    printf 'C payload:\n%s\nRust payload:\n%s\nC second-segment:\n%s\nRust second-segment:\n%s\n' \
        "$c_payload_values" "$r_payload_values" "$c_next_segment_values" "$r_next_segment_values" >&2
    exit 1
fi
echo 'payload_session_stats_numeric_trace=identical'
