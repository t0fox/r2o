#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT/target"}
R2OD_BIN=${R2OD_BIN:-"$TARGET_DIR/release/r2o-datapath"}
R2OC_BIN=${R2OC_BIN:-"$TARGET_DIR/release/r2o-controller"}
WORK_ROOT=${R2O_TEST_WORK_ROOT:-"$TARGET_DIR/test-work"}
QUEUE=65512
VOICE_MARK=21082
CONTROLLER_MARK=291
SERVER_PORT=50005
CLIENT_PORT=40155
TRIAL_CLIENT_PORT=40156
VERIFY_CLIENT_PORT=40157
NS="r2o-discovery-$$"
SOCKET_ROOT="/dev/shm/r2o-discovery-$$"
DATAPATH_PID=
CONTROLLER_PID=
SERVER_PID=

mkdir -p "$WORK_ROOT"
WORK=$(mktemp -d "$WORK_ROOT/discord-discovery.XXXXXX")
mkdir -m 700 "$SOCKET_ROOT"
printf '%s\n' '{"boxes":[]}' >"$WORK/catalog.json"

cleanup() {
    test_status=$?
    trap - EXIT HUP INT TERM
    for test_pid in "$CONTROLLER_PID" "$DATAPATH_PID" "$SERVER_PID"; do
        if [ -n "$test_pid" ]; then
            kill -TERM "$test_pid" 2>/dev/null || true
            wait "$test_pid" 2>/dev/null || true
        fi
    done
    if ip netns list | awk '{print $1}' | grep -Fxq "$NS"; then
        ip netns pids "$NS" | xargs -r kill -TERM 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
    rm -rf "$SOCKET_ROOT"
    case "$WORK" in
        "$WORK_ROOT"/*)
            if [ "$test_status" -eq 0 ]; then
                rm -rf "$WORK"
            else
                echo "сохранены журналы проверки: $WORK" >&2
                for test_log in "$WORK"/*.log; do
                    if [ -f "$test_log" ]; then
                        echo "--- $test_log" >&2
                        tail -n 60 "$test_log" >&2 || true
                    fi
                done
            fi
            ;;
        *)
            echo "небезопасный временный путь проверки: $WORK" >&2
            test_status=1
            ;;
    esac
    exit "$test_status"
}
trap cleanup EXIT HUP INT TERM

if [ "$(id -u)" -ne 0 ]; then
    echo "запустите от root, например: sudo sh scripts/test-discord-discovery-nfq.sh" >&2
    exit 1
fi
for test_tool in ip nft python3; do
    command -v "$test_tool" >/dev/null 2>&1 || {
        echo "не найдена обязательная команда: $test_tool" >&2
        exit 1
    }
done
for test_bin in "$R2OD_BIN" "$R2OC_BIN"; do
    if [ ! -x "$test_bin" ]; then
        echo "не найден исполняемый файл: $test_bin" >&2
        exit 1
    fi
done

ip netns add "$NS"
ip -n "$NS" link set lo up
ip -n "$NS" route add default dev lo
ip -n "$NS" -6 route add default dev lo
ip netns exec "$NS" nft add table inet r2o_discovery
ip netns exec "$NS" nft add chain inet r2o_discovery output '{ type filter hook output priority 0; policy accept; }'
ip netns exec "$NS" nft add chain inet r2o_discovery input '{ type filter hook input priority 0; policy accept; }'
ip netns exec "$NS" nft add rule inet r2o_discovery output ip daddr 127.0.0.1 udp dport "$SERVER_PORT" counter meta mark != "$VOICE_MARK" meta mark != "$CONTROLLER_MARK" queue num "$QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o_discovery output ip saddr 127.0.0.1 udp sport "$SERVER_PORT" udp dport "$TRIAL_CLIENT_PORT" counter meta mark != "$VOICE_MARK" meta mark != "$CONTROLLER_MARK" queue num "$QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o_discovery input ip saddr 127.0.0.1 udp sport "$SERVER_PORT" counter meta mark != "$VOICE_MARK" meta mark != "$CONTROLLER_MARK" queue num "$QUEUE" bypass

ip netns exec "$NS" python3 -u - "$SERVER_PORT" "$CLIENT_PORT" "$VERIFY_CLIENT_PORT" >"$WORK/discovery-server.log" 2>&1 <<'PY' &
import signal
import socket
import struct
import sys
import threading
import time
from collections import defaultdict

port = int(sys.argv[1])
client_port = int(sys.argv[2])
verify_client_port = int(sys.argv[3])
stopping = threading.Event()
direct_counts = defaultdict(int)
direct_times = defaultdict(float)
candidate_peers = set()

def stop(_signum, _frame):
    stopping.set()

def discovery_response(request):
    response = bytearray(74)
    response[:4] = b"\x00\x02\x00\x46"
    response[4:8] = request[4:8]
    response[8:19] = b"203.0.113.7"
    response[72:74] = struct.pack("!H", 50000)
    return response

signal.signal(signal.SIGTERM, stop)
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", port))
server.settimeout(0.1)
total_packets = 0
print("READY", flush=True)
while not stopping.is_set():
    try:
        request, peer = server.recvfrom(2048)
    except TimeoutError:
        continue
    total_packets += 1
    if peer[1] == client_port:
        if len(request) == 74 and request[:4] == b"\x00\x01\x00\x46":
            server.sendto(discovery_response(request), peer)
        continue
    if (
        peer[1] == verify_client_port
        and peer not in candidate_peers
        and len(request) == 74
        and request[:4] == b"\x00\x01\x00\x46"
        and not any(request[8:72])
    ):
        continue
    if len(request) == 20 and request[:8] == b"\x00\x01\x00\x00\x21\x12\xa4\x42":
        candidate_peers.add(peer)
        continue
    if len(request) != 74 or request[:4] != b"\x00\x01\x00\x46":
        continue
    if peer in candidate_peers or any(request[8:72]):
        candidate_peers.add(peer)
        server.sendto(discovery_response(request), peer)
    else:
        now = time.monotonic()
        if now - direct_times[peer] >= 0.5:
            direct_counts[peer] = 0
        direct_times[peer] = now
        direct_counts[peer] += 1
        if direct_counts[peer] <= 24:
            server.sendto(discovery_response(request), peer)
server.close()
print(f"STOP packets={total_packets} direct={len(direct_counts)} candidates={len(candidate_peers)}", flush=True)
PY
SERVER_PID=$!
server_attempt=0
while ! grep -Fq READY "$WORK/discovery-server.log"; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null || [ "$server_attempt" -ge 50 ]; then
        echo "UDP Discovery responder did not start" >&2
        exit 1
    fi
    sleep 0.05
    server_attempt=$((server_attempt + 1))
done

ip netns exec "$NS" "$R2OD_BIN" \
    --mode apply --queue "$QUEUE" --family ipv4 --controller-only \
    --mark "$VOICE_MARK" --control "$SOCKET_ROOT/datapath.sock" \
    --r2o-udp-reverse-visible >"$WORK/datapath.log" 2>&1 &
DATAPATH_PID=$!
datapath_attempt=0
while [ ! -S "$SOCKET_ROOT/datapath.sock" ]; do
    if ! kill -0 "$DATAPATH_PID" 2>/dev/null || [ "$datapath_attempt" -ge 100 ]; then
        echo "r2o-datapath did not open its control socket" >&2
        exit 1
    fi
    sleep 0.05
    datapath_attempt=$((datapath_attempt + 1))
done
ip netns exec "$NS" cat /proc/net/netfilter/nfnetlink_queue >"$WORK/nfqueue.log"

ip netns exec "$NS" "$R2OC_BIN" --serve "$SOCKET_ROOT/datapath.sock" "$WORK/catalog.json" --discover --mark "$CONTROLLER_MARK" >"$WORK/controller.log" 2>&1 &
CONTROLLER_PID=$!
sleep 0.2
if ! kill -0 "$CONTROLLER_PID" 2>/dev/null; then
    echo "r2o-controller did not stay alive" >&2
    exit 1
fi

ip netns exec "$NS" python3 - "$SERVER_PORT" "$CLIENT_PORT" <<'PY'
import socket
import sys
import time

server_port = int(sys.argv[1])
client_port = int(sys.argv[2])
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.bind(("127.0.0.1", client_port))
request = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + bytes(range(12))
client.sendto(request, ("127.0.0.1", server_port))
time.sleep(0.1)
client.sendto(request, ("127.0.0.1", server_port))
client.close()
PY
ip netns exec "$NS" nft list ruleset >"$WORK/nft.log"

voice_attempt=0
while ! grep -Fq "обнаружен Discord voice" "$WORK/controller.log"; do
    if ! kill -0 "$CONTROLLER_PID" 2>/dev/null || [ "$voice_attempt" -ge 100 ]; then
        echo "controller did not receive a voice-suspect event" >&2
        exit 1
    fi
    sleep 0.05
    voice_attempt=$((voice_attempt + 1))
done

trial_attempt=0
while ! grep -Fq "временный адресный план поставлен для следующего потока" "$WORK/controller.log"; do
    if ! kill -0 "$CONTROLLER_PID" 2>/dev/null || [ "$trial_attempt" -ge 600 ]; then
        echo "controller did not install a Discord Discovery trial" >&2
        exit 1
    fi
    sleep 0.1
    trial_attempt=$((trial_attempt + 1))
done

ip netns exec "$NS" python3 - "$SERVER_PORT" "$TRIAL_CLIENT_PORT" <<'PY'
import socket
import sys
import time

server_port = int(sys.argv[1])
client_port = int(sys.argv[2])
request = b"\x00\x01\x00\x46\x21\x12\xa4\x42" + bytes(66)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.bind(("127.0.0.1", client_port))
client.settimeout(5)
time.sleep(0.2)
client.sendto(request, ("127.0.0.1", server_port))
response, _ = client.recvfrom(2048)
client.close()
if len(response) != 74 or response[:4] != b"\x00\x02\x00\x46" or response[4:8] != request[4:8]:
    raise SystemExit(f"wrong Discord Discovery response: {response.hex()}")
print("ПРОЙДЕНО: клиент получил Discovery response через production NFQUEUE")
PY

proof_attempt=0
while ! grep -Fq "Ответ Discord Discovery подтверждён" "$WORK/controller.log"; do
    if ! kill -0 "$CONTROLLER_PID" 2>/dev/null || [ "$proof_attempt" -ge 100 ]; then
        echo "controller did not receive exact Discord Discovery proof" >&2
        exit 1
    fi
    sleep 0.05
    proof_attempt=$((proof_attempt + 1))
done

# The controller batches catalog writes; a clean shutdown flushes the confirmed binding.
kill -TERM "$CONTROLLER_PID"
if wait "$CONTROLLER_PID"; then
    CONTROLLER_PID=
else
    echo "r2o-controller did not shut down cleanly after Discovery proof" >&2
    exit 1
fi

python3 - "$WORK/catalog.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as catalog_file:
    catalog = json.load(catalog_file)
bindings = [
    binding
    for box in catalog["boxes"]
    for binding in box.get("bindings", [])
]
if not any(
    binding.get("kind") == "addr"
    and binding.get("target") == "127.0.0.1"
    and binding.get("transport") == 17
    and binding.get("verified_by") == 4
    for binding in bindings
):
    raise SystemExit("catalog lacks the Discovery-confirmed UDP voice binding")
print("ПРОЙДЕНО: controller сохранил Discovery-confirmed voice binding")
PY

# Restart the production datapath so the next check can only pass if the
# confirmed catalog entry is replayed into a fresh runtime.
kill -TERM "$DATAPATH_PID"
if wait "$DATAPATH_PID"; then
    DATAPATH_PID=
else
    echo "r2o-datapath did not shut down cleanly before catalog reapply" >&2
    exit 1
fi

RESTARTED_SOCKET="$SOCKET_ROOT/datapath-restarted.sock"
ip netns exec "$NS" "$R2OD_BIN" \
    --mode apply --queue "$QUEUE" --family ipv4 --controller-only \
    --mark "$VOICE_MARK" --control "$RESTARTED_SOCKET" \
    --r2o-udp-reverse-visible >"$WORK/datapath-restarted.log" 2>&1 &
DATAPATH_PID=$!
datapath_attempt=0
while [ ! -S "$RESTARTED_SOCKET" ]; do
    if ! kill -0 "$DATAPATH_PID" 2>/dev/null || [ "$datapath_attempt" -ge 100 ]; then
        echo "restarted r2o-datapath did not open its control socket" >&2
        exit 1
    fi
    sleep 0.05
    datapath_attempt=$((datapath_attempt + 1))
done

"$R2OC_BIN" --apply-catalog "$RESTARTED_SOCKET" "$WORK/catalog.json" >"$WORK/reapply.log" 2>&1 || {
    echo "r2o-controller did not reapply the saved voice binding" >&2
    exit 1
}
if ! grep -Fq "отправлено 1, пропущено неподдерживаемых 0" "$WORK/reapply.log"; then
    echo "r2o-controller did not apply exactly one saved voice binding" >&2
    exit 1
fi

ip netns exec "$NS" python3 - "$SERVER_PORT" "$VERIFY_CLIENT_PORT" <<'PY'
import socket
import sys

server_port = int(sys.argv[1])
client_port = int(sys.argv[2])
request = b"\x00\x01\x00\x46\x21\x12\xa4\x42" + bytes(66)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.bind(("127.0.0.1", client_port))
client.settimeout(5)
client.sendto(request, ("127.0.0.1", server_port))
response, _ = client.recvfrom(2048)
client.close()
if len(response) != 74 or response[:4] != b"\x00\x02\x00\x46" or response[4:8] != request[4:8]:
    raise SystemExit(f"wrong response after restart/reapply: {response.hex()}")
print("ПРОЙДЕНО: сохранённый voice-план работает через production NFQUEUE после перезапуска datapath")
PY
