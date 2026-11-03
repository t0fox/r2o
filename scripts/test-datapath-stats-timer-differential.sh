#!/bin/sh
set -eu

d2o_datapath=${D2O_DATAPATH:-/tmp/d2kd-stats-c}
r2o_datapath=${R2O_DATAPATH:-/tmp/r2o-datapath}
queue=${R2O_TEST_QUEUE:-2002}
test_tmpdir=${R2O_TEST_TMPDIR:-${TMPDIR:-/tmp}}
test_control_tmpdir=${R2O_TEST_CONTROL_TMPDIR:-$test_tmpdir}
namespace="r2o-stats-diff-$$"
peer_namespace="r2o-stats-peer-$$"
client_if="rsc$$"
peer_if="rsp$$"
peer_address=198.51.100.2
traffic_port=39992
running_pid=
server_pid=
control=
ready=

mkdir -p "$test_tmpdir"
mkdir -p "$test_control_tmpdir"

cleanup() {
    if [ -n "$running_pid" ]; then
        kill -TERM "$running_pid" 2>/dev/null || true
        wait "$running_pid" 2>/dev/null || true
    fi
    if [ -n "$server_pid" ]; then
        kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -f "" "" 2>/dev/null || true
    if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
        ip netns del "$namespace" 2>/dev/null || true
    fi
    if ip netns list | awk '{print $1}' | grep -Fxq "$peer_namespace"; then
        ip netns del "$peer_namespace" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

if [ "$(id -u)" -ne 0 ]; then
    echo "запустите от root: нужны NFQUEUE и отдельное сетевое пространство" >&2
    exit 1
fi
ip netns add "$namespace"
ip netns exec "$namespace" ip link set lo up
ip netns add "$peer_namespace"
ip link add "$client_if" type veth peer name "$peer_if"
ip link set "$client_if" netns "$namespace"
ip link set "$peer_if" netns "$peer_namespace"
ip netns exec "$namespace" ip addr add 198.51.100.1/30 dev "$client_if"
ip netns exec "$peer_namespace" ip addr add "$peer_address/30" dev "$peer_if"
ip netns exec "$namespace" ip link set "$client_if" up
ip netns exec "$peer_namespace" ip link set lo up
ip netns exec "$peer_namespace" ip link set "$peer_if" up
ip netns exec "$namespace" ip route add default via "$peer_address" dev "$client_if"
ip netns exec "$namespace" nft add table inet stats
ip netns exec "$namespace" nft 'add chain inet stats output { type filter hook output priority filter; policy accept; }'
ip netns exec "$namespace" nft add rule inet stats output ip daddr 127.0.0.1 udp dport "$traffic_port" queue num "$queue"
ip netns exec "$namespace" nft add rule inet stats output oifname "$client_if" ip daddr "$peer_address" tcp dport 443 queue num "$queue"

send_traffic() {
    ip netns exec "$namespace" python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); [s.sendto(bytes([i])*(i+1),("127.0.0.1",39992)) for i in range(1,9)]; s.sendto(b"x"*512,("127.0.0.1",39992))'
}

run_hello_case() {
    name=$1
    binary=$2
    pattern=$3
    mss=${4:-0}
    log="$test_tmpdir/r2o-stats-hello-$name.log"
    server_log="$test_tmpdir/r2o-stats-hello-server-$name.log"
    ready="$test_tmpdir/r2o-stats-hello-$name.ready"
    rm -f "$log" "$server_log" "$ready"
    ip netns exec "$peer_namespace" python3 -c 'import socket,sys; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("198.51.100.2",443)); s.listen(1); open(sys.argv[1],"w").close(); c,_=s.accept(); c.settimeout(3); c.recv(8192); c.close(); s.close()' "$ready" >"$server_log" 2>&1 &
    server_pid=$!
    attempt=0
    while [ ! -e "$ready" ]; do
        if ! kill -0 "$server_pid" 2>/dev/null; then cat "$server_log"; exit 1; fi
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 50 ]; then
            echo "TLS test server did not become ready" >&2
            cat "$server_log" >&2
            exit 1
        fi
        sleep 0.1
    done
    ip netns exec "$namespace" "$binary" --queue "$queue" --mode observe --copy-range 1600 --stats 1 >"$log" 2>&1 &
    running_pid=$!
    sleep 1
    if ! kill -0 "$running_pid" 2>/dev/null; then cat "$log"; exit 1; fi
    ip netns exec "$namespace" python3 -c 'import socket,ssl,sys; s=socket.socket(); mss=int(sys.argv[2]); mss and s.setsockopt(socket.IPPROTO_TCP,socket.TCP_MAXSEG,mss); s.settimeout(3); s.connect((sys.argv[1],443)); c=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname=False; c.maximum_version=ssl.TLSVersion.TLSv1_2; c.verify_mode=ssl.CERT_NONE; t=c.wrap_socket(s,server_hostname="example.com",do_handshake_on_connect=False); exec("try:\n t.do_handshake()\nexcept (ssl.SSLError,OSError,TimeoutError):\n pass"); t.close()' "$peer_address" "$mss"
    sleep 2
    kill -TERM "$running_pid"
    wait "$running_pid"
    running_pid=
    wait "$server_pid" 2>/dev/null || true
    server_pid=
    count=$(grep -Fc -e "$pattern" "$log" || true)
    echo "$name hello_summary_lines=$count"
    if [ "$count" -lt 2 ]; then cat "$log"; cat "$server_log"; exit 1; fi
}

run_case() {
    name=$1
    binary=$2
    pattern=$3
    log="$test_tmpdir/r2o-stats-diff-${name}.log"
    rm -f "$log"
    ip netns exec "$namespace" "$binary" --queue "$queue" --mode observe --stats 1 >"$log" 2>&1 &
    running_pid=$!
    sleep 3
    kill -TERM "$running_pid"
    wait "$running_pid"
    running_pid=
    count=$(grep -Fc -e "$pattern" "$log" || true)
    echo "${name}_summary_lines=$count"
    if [ "$count" -lt 2 ]; then cat "$log"; exit 1; fi
}

run_traffic_case() {
    name=$1
    binary=$2
    pattern=$3
    log="$test_tmpdir/r2o-stats-traffic-$name.log"
    rm -f "$log"
    ip netns exec "$namespace" "$binary" --queue "$queue" --mode observe --copy-range 128 --stats 1 >"$log" 2>&1 &
    running_pid=$!
    sleep 1
    if ! kill -0 "$running_pid" 2>/dev/null; then cat "$log"; exit 1; fi
    send_traffic
    sleep 2
    kill -TERM "$running_pid"
    wait "$running_pid"
    running_pid=
    count=$(grep -Fc -e "$pattern" "$log" || true)
    echo "$name traffic_summary_lines=$count"
    if [ "$count" -lt 2 ]; then cat "$log"; exit 1; fi
}

run_capture_expiry_case() {
    name=$1
    binary=$2
    log="$test_tmpdir/r2o-stats-capture-expiry-$name.log"
    server_log="$test_tmpdir/r2o-stats-capture-expiry-server-$name.log"
    ready="$test_tmpdir/r2o-stats-capture-expiry-$name.ready"
    server_capture="$test_tmpdir/r2o-stats-capture-expiry-$name.payload"
    rm -f "$log" "$server_log" "$ready" "$server_capture"
    ip netns exec "$peer_namespace" python3 -c 'import socket,sys; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("198.51.100.2",443)); s.listen(1); open(sys.argv[1],"w").close(); c,_=s.accept(); payload=bytearray();
while True:
 chunk=c.recv(128)
 if not chunk: break
 payload.extend(chunk)
open(sys.argv[2],"wb").write(payload); c.close(); s.close()' "$ready" "$server_capture" >"$server_log" 2>&1 &
    server_pid=$!
    attempt=0
    while [ ! -e "$ready" ]; do
        if ! kill -0 "$server_pid" 2>/dev/null || [ "$attempt" -ge 50 ]; then cat "$server_log" >&2; exit 1; fi
        attempt=$((attempt + 1))
        sleep 0.05
    done
    ip netns exec "$namespace" "$binary" --queue "$queue" --mode observe --stats 1 >"$log" 2>&1 &
    running_pid=$!
    sleep 0.3
    if ! kill -0 "$running_pid" 2>/dev/null; then cat "$log" >&2; exit 1; fi
    ip netns exec "$namespace" python3 -c 'import socket,sys,time; s=socket.create_connection((sys.argv[1],443),timeout=3); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1); s.sendall(bytes.fromhex("1603010020")); time.sleep(5.2); s.sendall(b"\x01"); s.close()' "$peer_address"
    wait "$server_pid"
    server_pid=
    python3 - "$server_capture" <<'PY'
from pathlib import Path
import sys
actual = Path(sys.argv[1]).read_bytes()
expected = bytes.fromhex("160301002001")
if actual != expected:
    raise SystemExit(f"incomplete TLS record did not reach the peer intact: {actual.hex()}")
PY
    sleep 0.2
    kill -TERM "$running_pid"
    wait "$running_pid"
    running_pid=
    c_values=$(grep 'снимки TCP:' "$log" | tail -n 1 | sed -E 's/.*полных=([0-9]+) отвергнутых=([0-9]+) истекших=([0-9]+) отказов ёмкости=([0-9]+).*/\1 \2 \3 \4/')
    r_values=$(grep 'снимки TLS/TCP:' "$log" | tail -n 1 | sed -E 's/.*завершено ([0-9]+), отклонено ([0-9]+), истекло ([0-9]+), отказов ёмкости ([0-9]+).*/\1 \2 \3 \4/')
    if [ "$c_values" != '0 0 1 0' ] || [ "$r_values" != '0 0 1 0' ]; then
        cat "$log" >&2
        echo "$name capture expiry counters differ: C=$c_values Rust=$r_values" >&2
        exit 1
    fi
    printf '%s capture_expiry_stats=%s\n' "$name" "$c_values"
}

run_capture_expiry_case d2o "$d2o_datapath"
run_capture_expiry_case r2o "$r2o_datapath"
echo 'tcp_capture_expiry_periodic_stats_trace=identical (production IPv4 NFQUEUE processes)'

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

c_scheduler_count=$(grep -Fc 'в очереди отправки' "$test_tmpdir/r2o-stats-diff-d2o.log" || true)
r_scheduler_count=$(grep -Fc 'в очереди отправки' "$test_tmpdir/r2o-stats-diff-r2o.log" || true)
if [ "$c_scheduler_count" -ne "$c_stats_count" ] || [ "$r_scheduler_count" -ne "$r_stats_count" ]; then
    echo "scheduler statistics must appear once per full stats summary: C=$c_scheduler_count/$c_stats_count Rust=$r_scheduler_count/$r_stats_count" >&2
    exit 1
fi
c_scheduler_values=$(grep 'в очереди отправки' "$test_tmpdir/r2o-stats-diff-d2o.log" | head -n 2 | sed -E 's/[^0-9]+/ /g' | sed '/^ *$/d')
r_scheduler_values=$(grep 'в очереди отправки' "$test_tmpdir/r2o-stats-diff-r2o.log" | head -n 2 | sed -E 's/^r2o-datapath: //' | sed -E 's/[^0-9]+/ /g' | sed '/^ *$/d')
if [ "$c_scheduler_values" != "$r_scheduler_values" ]; then
    echo "D2O scheduled queue statistics differ from R2O" >&2
    printf 'C:\n%s\nRust:\n%s\n' "$c_scheduler_values" "$r_scheduler_values" >&2
    exit 1
fi
echo 'scheduled_queue_stats_numeric_trace=identical'
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

run_traffic_case d2o "$d2o_datapath" '--- d2kd['
run_traffic_case r2o "$r2o_datapath" 'r2o-datapath: TCP'

c_traffic_stats_count=$(grep -Fc -- '--- d2kd[' "$test_tmpdir/r2o-stats-traffic-d2o.log" || true)
r_traffic_stats_count=$(grep -Fc 'r2o-datapath: TCP' "$test_tmpdir/r2o-stats-traffic-r2o.log" || true)
c_queue_count=$(grep -Ec 'пакетов [0-9]+, байт [0-9]+, пропущено [0-9]+, снято [0-9]+' "$test_tmpdir/r2o-stats-traffic-d2o.log" || true)
r_queue_count=$(grep -Ec 'пакетов [0-9]+, байт [0-9]+, пропущено [0-9]+, снято [0-9]+' "$test_tmpdir/r2o-stats-traffic-r2o.log" || true)
if [ "$c_queue_count" -ne "$c_traffic_stats_count" ] || [ "$r_queue_count" -ne "$r_traffic_stats_count" ]; then
    echo "NFQUEUE traffic counters must appear once per summary: C=$c_queue_count/$c_traffic_stats_count Rust=$r_queue_count/$r_traffic_stats_count" >&2
    exit 1
fi
# Ignore an idle timer tick before the test sends packets.
c_queue_values=$(grep -E 'пакетов [0-9]+, байт [0-9]+, пропущено [0-9]+, снято [0-9]+' "$test_tmpdir/r2o-stats-traffic-d2o.log"  | sed -E 's/[^0-9]+/ /g' | sed '/^ *$/d' | sed -E '/^ *0 +0 +0 +0 *$/d')
r_queue_values=$(grep -E 'пакетов [0-9]+, байт [0-9]+, пропущено [0-9]+, снято [0-9]+' "$test_tmpdir/r2o-stats-traffic-r2o.log"  | sed -E 's/^r2o-datapath: //' | sed -E 's/[^0-9]+/ /g' | sed '/^ *$/d' | sed -E '/^ *0 +0 +0 +0 *$/d')
c_periodic_nonzero=$(grep -E 'пакетов [0-9]+, байт [0-9]+, пропущено [0-9]+, снято [0-9]+' "$test_tmpdir/r2o-stats-traffic-d2o.log" | sed '$d' | grep -Fc 'пакетов 9, байт 396, пропущено 9, снято 0' || true)
r_periodic_nonzero=$(grep -E 'пакетов [0-9]+, байт [0-9]+, пропущено [0-9]+, снято [0-9]+' "$test_tmpdir/r2o-stats-traffic-r2o.log" | sed '$d' | grep -Fc 'пакетов 9, байт 396, пропущено 9, снято 0' || true)
if [ "$c_periodic_nonzero" -lt 1 ] || [ "$r_periodic_nonzero" -lt 1 ]; then
    echo "expected nonzero periodic traffic totals: C=$c_periodic_nonzero Rust=$r_periodic_nonzero" >&2
    exit 1
fi
if [ "$c_queue_values" != "$r_queue_values" ]; then
    echo "D2O NFQUEUE packet/verdict statistics differ from R2O" >&2
    printf 'C:\n%s\nRust:\n%s\n' "$c_queue_values" "$r_queue_values" >&2
    exit 1
fi
if ! printf '%s\n' "$c_queue_values" | grep -Eq '^ 9 396 9 0$'; then
    echo "NFQUEUE test did not account for the nine sent packets including one truncated packet: $c_queue_values" >&2
    exit 1
fi
echo 'nfqueue_traffic_stats_numeric_trace=identical (9 packets, 396 bytes, 9 accepted)'

c_truncated_count=$(grep -Ec 'обрезано [0-9]+, без нагрузки [0-9]+, без заголовка [0-9]+' "$test_tmpdir/r2o-stats-traffic-d2o.log" || true)
r_truncated_count=$(grep -Ec 'r2o-datapath: обрезано [0-9]+, без нагрузки [0-9]+, без заголовка [0-9]+' "$test_tmpdir/r2o-stats-traffic-r2o.log" || true)
if [ "$c_truncated_count" -ne "$c_traffic_stats_count" ] || [ "$r_truncated_count" -ne "$r_traffic_stats_count" ]; then
    echo "copy-range counters must appear once per summary: C=$c_truncated_count/$c_traffic_stats_count Rust=$r_truncated_count/$r_traffic_stats_count" >&2
    exit 1
fi
c_truncated_values=$(grep -E 'обрезано [0-9]+, без нагрузки [0-9]+, без заголовка [0-9]+' "$test_tmpdir/r2o-stats-traffic-d2o.log" | sed -E 's/[^0-9]+/ /g' | sed '/^ *$/d')
r_truncated_values=$(grep -E 'r2o-datapath: обрезано [0-9]+, без нагрузки [0-9]+, без заголовка [0-9]+' "$test_tmpdir/r2o-stats-traffic-r2o.log" | sed -E 's/^r2o-datapath: //' | sed -E 's/[^0-9]+/ /g' | sed '/^ *$/d')
if [ "$c_truncated_values" != "$r_truncated_values" ]; then
    echo "D2O NFQUEUE copy-range statistics differ from R2O" >&2
    printf 'C:\n%s\nRust:\n%s\n' "$c_truncated_values" "$r_truncated_values" >&2
    exit 1
fi
if ! printf '%s\n' "$c_truncated_values" | grep -Eq '^ 1 0 0$'; then
    echo "expected one truncated packet, no missing payloads, and no headerless packets: $c_truncated_values" >&2
    exit 1
fi
c_truncated_periodic=$(grep -E 'обрезано [0-9]+, без нагрузки [0-9]+' "$test_tmpdir/r2o-stats-traffic-d2o.log" | sed '$d' | grep -Fc 'обрезано 1, без нагрузки 0' || true)
r_truncated_periodic=$(grep -E 'r2o-datapath: обрезано [0-9]+, без нагрузки [0-9]+' "$test_tmpdir/r2o-stats-traffic-r2o.log" | sed '$d' | grep -Fc 'обрезано 1, без нагрузки 0' || true)
if [ "$c_truncated_periodic" -lt 1 ] || [ "$r_truncated_periodic" -lt 1 ]; then
    echo "expected nonzero periodic copy-range counters: C=$c_truncated_periodic Rust=$r_truncated_periodic" >&2
    exit 1
fi
echo 'nfqueue_copy_stats_trace=identical (one truncated packet)'

run_hello_case d2o "$d2o_datapath" '--- d2kd['
run_hello_case r2o "$r2o_datapath" 'r2o-datapath: TCP-потоки'
run_hello_case d2o-split "$d2o_datapath" '--- d2kd[' 128
run_hello_case r2o-split "$r2o_datapath" 'r2o-datapath: TCP-потоки' 128

c_split_hello_values=$(grep 'узнано приветствий ' "$test_tmpdir/r2o-stats-hello-d2o-split.log" | sed -E 's/.*узнано приветствий ([0-9]+), из них с именем ([0-9]+).*/\1 \2/')
r_split_hello_values=$(grep 'r2o-datapath: распознано TCP ClientHello ' "$test_tmpdir/r2o-stats-hello-r2o-split.log" | sed -E 's/.*распознано TCP ClientHello ([0-9]+), из них с именем ([0-9]+).*/\1 \2/')
if [ "$c_split_hello_values" != "$r_split_hello_values" ]; then
    echo "D2O and R2O hello/SNI totals differ when SNI arrives in a later TCP segment" >&2
    printf 'C:\n%s\nRust:\n%s\n' "$c_split_hello_values" "$r_split_hello_values" >&2
    exit 1
fi
c_split_next_values=$(grep 'имя уехало во второй сегмент:' "$test_tmpdir/r2o-stats-hello-d2o-split.log" | sed -E 's/^.*: *//')
r_split_next_values=$(grep 'имя ClientHello в следующем сегменте:' "$test_tmpdir/r2o-stats-hello-r2o-split.log" | sed -E 's/^.*: *//')
if [ "$c_split_next_values" != "$r_split_next_values" ] ||
    ! printf '%s\n' "$c_split_next_values" | sed '$d' | grep -Fxq '1'; then
    echo "split-SNI fixture must trigger the matching second-segment counter: C=$c_split_next_values Rust=$r_split_next_values" >&2
    exit 1
fi
echo 'tcp_clienthello_split_sni_stats_trace=identical (SNI arrives in a later TCP segment)'

c_hello_stats_count=$(grep -Fc -- '--- d2kd[' "$test_tmpdir/r2o-stats-hello-d2o.log" || true)
r_hello_stats_count=$(grep -Fc 'r2o-datapath: TCP-потоки' "$test_tmpdir/r2o-stats-hello-r2o.log" || true)
c_hello_count=$(grep -Fc 'узнано приветствий ' "$test_tmpdir/r2o-stats-hello-d2o.log" || true)
r_hello_count=$(grep -Fc 'r2o-datapath: распознано TCP ClientHello ' "$test_tmpdir/r2o-stats-hello-r2o.log" || true)
if [ "$c_hello_count" -ne "$c_hello_stats_count" ] || [ "$r_hello_count" -ne "$r_hello_stats_count" ]; then
    echo "TCP ClientHello totals must appear once per summary: C=$c_hello_count/$c_hello_stats_count Rust=$r_hello_count/$r_hello_stats_count" >&2
    exit 1
fi
c_hello_values=$(grep 'узнано приветствий ' "$test_tmpdir/r2o-stats-hello-d2o.log" | sed -E 's/.*узнано приветствий ([0-9]+), из них с именем ([0-9]+).*/\1 \2/')
r_hello_values=$(grep 'r2o-datapath: распознано TCP ClientHello ' "$test_tmpdir/r2o-stats-hello-r2o.log" | sed -E 's/.*распознано TCP ClientHello ([0-9]+), из них с именем ([0-9]+).*/\1 \2/')
if [ "$c_hello_values" != "$r_hello_values" ]; then
    echo "D2O TCP ClientHello statistics differ from R2O" >&2
    printf 'C:\n%s\nRust:\n%s\n' "$c_hello_values" "$r_hello_values" >&2
    exit 1
fi
c_hello_periodic=$(grep 'узнано приветствий ' "$test_tmpdir/r2o-stats-hello-d2o.log" | sed '$d' | grep -Fc 'узнано приветствий 1, из них с именем 1' || true)
r_hello_periodic=$(grep 'распознано TCP ClientHello ' "$test_tmpdir/r2o-stats-hello-r2o.log" | sed '$d' | grep -Fc 'распознано TCP ClientHello 1, из них с именем 1' || true)
if [ "$c_hello_periodic" -lt 1 ] || [ "$r_hello_periodic" -lt 1 ]; then
    echo "expected one periodic TCP ClientHello with SNI: C=$c_hello_periodic Rust=$r_hello_periodic" >&2
    exit 1
fi
c_rst_metric_lines=$(grep -Fc 'снято чужих сбросов ' "$test_tmpdir/r2o-stats-hello-d2o.log" || true)
r_rst_metric_lines=$(grep -Fc 'r2o-datapath: снято чужих сбросов ' "$test_tmpdir/r2o-stats-hello-r2o.log" || true)
if [ "$c_rst_metric_lines" -ne "$c_hello_stats_count" ] || [ "$r_rst_metric_lines" -ne "$r_hello_stats_count" ]; then
    echo "alien-RST drop metric must appear once per hello summary: C=$c_rst_metric_lines/$c_hello_stats_count Rust=$r_rst_metric_lines/$r_hello_stats_count" >&2
    exit 1
fi
c_rst_values=$(grep 'узнано приветствий ' "$test_tmpdir/r2o-stats-hello-d2o.log" | grep -oE 'снято чужих сбросов [0-9]+' | grep -oE '[0-9]+$')
r_rst_values=$(grep 'r2o-datapath: снято чужих сбросов ' "$test_tmpdir/r2o-stats-hello-r2o.log" | grep -oE '[0-9]+$')
if [ "$c_rst_values" != "$r_rst_values" ]; then
    echo "D2O and R2O alien-RST drop totals differ" >&2
    echo "C: $c_rst_values Rust: $r_rst_values" >&2
    exit 1
fi
echo 'tcp_alien_rst_drop_stats_trace=identical'

echo 'tcp_clienthello_stats_trace=identical (one TLS ClientHello with SNI)'


# Reuse the pinned RFC 9001 Initial fixture from the C session tests.
quic_initial="$test_tmpdir/r2o-stats-quic-v1-initial.bin"
python3 - "$d2o_datapath" "$quic_initial" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).resolve().with_name("test_quic_session.c")
match = re.search(
    r"static const uint8_t v1_initial\[1200\]\s*=\s*\{(.*?)\};",
    source.read_text(),
    re.S,
)
if not match:
    raise SystemExit(f"missing RFC 9001 v1_initial fixture in {source}")
payload = bytes(int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{1,2})", match.group(1)))
if len(payload) != 1200:
    raise SystemExit(f"expected 1200-byte Initial, found {len(payload)}")
Path(sys.argv[2]).write_bytes(payload)
PY
ip netns exec "$namespace" nft add rule inet stats output oifname "$client_if" ip daddr "$peer_address" udp dport 443 queue num "$queue"

run_quic_hello_case() {
    name=$1
    binary=$2
    controller_only=$3
    pattern=$4
    log="$test_tmpdir/r2o-stats-quic-$name.log"
    control="$test_control_tmpdir/quic-$name-control.sock"
    ready="$control.ready"
    rm -f "$log" "$control" "$ready"
    if [ "$controller_only" = yes ]; then
        ip netns exec "$namespace" "$binary" --queue "$queue" --mode observe --stats 1 --controller-only --control "$control" >"$log" 2>&1 &
    else
        ip netns exec "$namespace" "$binary" --queue "$queue" --mode observe --stats 1 --control "$control" >"$log" 2>&1 &
    fi
    running_pid=$!
    attempt=0
    while [ ! -S "$control" ]; do
        if ! kill -0 "$running_pid" 2>/dev/null; then cat "$log"; exit 1; fi
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 50 ]; then
            echo "QUIC stats test control socket did not become ready" >&2
            cat "$log" >&2
            exit 1
        fi
        sleep 0.1
    done
    python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); end=time.monotonic()+5
while True:
 try:
  s.connect(sys.argv[1]); break
 except OSError:
  if time.monotonic()>=end: raise
  time.sleep(0.1)
open(sys.argv[2],"w").close()
while True: time.sleep(1)' "$control" "$ready" >"$test_tmpdir/quic-$name-control.log" 2>&1 &
    server_pid=$!
    attempt=0
    while [ ! -e "$ready" ]; do
        if ! kill -0 "$server_pid" 2>/dev/null; then cat "$test_tmpdir/quic-$name-control.log"; exit 1; fi
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 50 ]; then
            echo "QUIC stats test controller did not connect" >&2
            cat "$test_tmpdir/quic-$name-control.log" >&2
            exit 1
        fi
        sleep 0.1
    done
    sleep 0.3
    ip netns exec "$namespace" python3 -c 'import socket,sys; packet=open(sys.argv[1],"rb").read(); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(packet,(sys.argv[2],443))' "$quic_initial" "$peer_address"
    sleep 2
    kill -TERM "$running_pid"
    wait "$running_pid"
    running_pid=
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=
    count=$(grep -Fc -e "$pattern" "$log" || true)
    echo "$name quic_summary_lines=$count"
    if [ "$count" -lt 2 ]; then cat "$log"; exit 1; fi
}

run_quic_hello_case d2o "$d2o_datapath" no '--- d2kd['
run_quic_hello_case r2o "$r2o_datapath" yes 'r2o-datapath: TCP'
c_quic_hello_values=$(grep 'узнано приветствий ' "$test_tmpdir/r2o-stats-quic-d2o.log" | sed -E 's/.*узнано приветствий ([0-9]+), из них с именем ([0-9]+).*/\1 \2/')
r_quic_hello_values=$(grep 'узнано приветствий ' "$test_tmpdir/r2o-stats-quic-r2o.log" | sed -E 's/.*узнано приветствий ([0-9]+), из них с именем ([0-9]+).*/\1 \2/')
if [ -z "$c_quic_hello_values" ] || [ "$c_quic_hello_values" != "$r_quic_hello_values" ] ||
    ! printf '%s\n' "$c_quic_hello_values" | grep -Fxq '1 1'; then
    echo "D2O and R2O aggregate hello/SNI totals differ for one QUIC Initial" >&2
    printf 'C:\n%s\nRust:\n%s\n' "$c_quic_hello_values" "$r_quic_hello_values" >&2
    exit 1
fi
echo 'quic_clienthello_stats_trace=identical (one named QUIC Initial)'

# Compare a live held-packet timeout in production D2O and R2O processes.
hold_plan_r2o="$test_tmpdir/r2o-stats-hold.r2op"
hold_plan_d2o="$test_tmpdir/r2o-stats-hold.d2kp"
python3 - "$hold_plan_r2o" "$hold_plan_d2o" <<'PY'
import struct
import sys

def tlv(kind, value):
    return struct.pack("!HH", kind, len(value)) + value

records = [
    tlv(0x0002, b"\x06\x01"),
    tlv(0x0100, b"\x00\x05\x00\x00"),
    tlv(0x0109, b"\x01"),
    tlv(0x010a, b""),
]
for magic, path in ((b"R2OP", sys.argv[1]), (b"D2KP", sys.argv[2])):
    header = magic + struct.pack("!HHHH", 1, 5, 0, len(records))
    with open(path, "wb") as output:
        output.write(header + b"".join(records))
PY

run_hold_timeout_case() {
    name=$1
    binary=$2
    plan=$3
    log="$test_tmpdir/r2o-stats-hold-$name.log"
    server_log="$test_tmpdir/r2o-stats-hold-server-$name.log"
    ready="$test_tmpdir/r2o-stats-hold-$name.ready"
    server_capture="$test_tmpdir/r2o-stats-hold-$name.payload"
    rm -f "$log" "$server_log" "$ready" "$server_capture"
    ip netns exec "$peer_namespace" python3 -c 'import socket,sys; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("198.51.100.2",443)); s.listen(1); open(sys.argv[1],"w").close(); c,_=s.accept(); payload=c.recv(128); open(sys.argv[2],"wb").write(payload); c.close(); s.close()' "$ready" "$server_capture" >"$server_log" 2>&1 &
    server_pid=$!
    attempt=0
    while [ ! -e "$ready" ]; do
        if ! kill -0 "$server_pid" 2>/dev/null || [ "$attempt" -ge 50 ]; then cat "$server_log" >&2; exit 1; fi
        attempt=$((attempt + 1))
        sleep 0.05
    done
    if [ "$name" = d2o ]; then
        ip netns exec "$namespace" "$binary" --queue "$queue" --mode apply --mark 180001 --plan "$plan" --stats 1 >"$log" 2>&1 &
    else
        ip netns exec "$namespace" "$binary" --queue "$queue" --family ipv4 --mode apply --mark 180001 --plan "$plan" --stats 1 >"$log" 2>&1 &
    fi
    running_pid=$!
    sleep 0.3
    if ! kill -0 "$running_pid" 2>/dev/null; then cat "$log" >&2; exit 1; fi
    ip netns exec "$namespace" python3 -c 'import socket,sys,time; s=socket.create_connection((sys.argv[1],443),timeout=3); s.sendall(bytes.fromhex("16030300200100")); time.sleep(0.7); s.close()' "$peer_address" &
    client_pid=$!
    sleep 0.03
    if [ -s "$server_capture" ]; then
        cat "$log" >&2
        echo "$name released an incomplete ClientHello before the hold timeout" >&2
        exit 1
    fi
    wait "$client_pid"
    client_pid=
    sleep 0.5
    kill -TERM "$running_pid"
    wait "$running_pid"
    running_pid=
    wait "$server_pid" 2>/dev/null || true
    server_pid=
    python3 - "$server_capture" <<'PY'
from pathlib import Path
import sys
actual = Path(sys.argv[1]).read_bytes()
expected = bytes.fromhex("16030300200100")
if actual != expected:
    raise SystemExit(f"held packet was not released intact: {actual.hex()}")
PY
    count=$(grep -Fc 'составной вход:' "$log" || true)
    if [ "$count" -lt 2 ]; then cat "$log" >&2; echo "$name missing periodic and shutdown hold summaries" >&2; exit 1; fi
    hold_line=$(grep 'составной вход:' "$log" | tail -n 1 | sed -E 's/^.*составной вход: //')
    hold_values=$(printf '%s\n' "$hold_line" | sed -E 's/[^0-9]+/ /g; s/^ +//; s/ +$//')
    expected_hold_values='1 0 1 1 1 0 0 0 0 0 0 0'
    if [ "$hold_values" != "$expected_hold_values" ]; then
        cat "$log" >&2
        echo "$name hold counters differ: expected=$expected_hold_values actual=$hold_values" >&2
        exit 1
    fi
    printf '%s hold_timeout_stats=%s\n' "$name" "$hold_values"
}

run_hold_timeout_case d2o "$d2o_datapath" "$hold_plan_d2o"
run_hold_timeout_case r2o "$r2o_datapath" "$hold_plan_r2o"
c_hold_values=$(grep 'составной вход:' "$test_tmpdir/r2o-stats-hold-d2o.log" | tail -n 1 | sed -E 's/^.*составной вход: //' | sed -E 's/[^0-9]+/ /g; s/^ +//; s/ +$//')
r_hold_values=$(grep 'составной вход:' "$test_tmpdir/r2o-stats-hold-r2o.log" | tail -n 1 | sed -E 's/^.*составной вход: //' | sed -E 's/[^0-9]+/ /g; s/^ +//; s/ +$//')
if [ "$c_hold_values" != "$r_hold_values" ]; then
    echo "D2O and R2O held-packet timeout statistics differ: C=$c_hold_values Rust=$r_hold_values" >&2
    exit 1
fi
echo 'held_packet_timeout_stats_trace=identical (production IPv4 NFQUEUE processes)'
