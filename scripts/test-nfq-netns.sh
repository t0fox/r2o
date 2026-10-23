#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT/target"}
BUILD_DEFAULT_BINARIES=0
if [ "${R2OD_BIN+x}" != x ] || [ "${R2OC_BIN+x}" != x ]; then
    BUILD_DEFAULT_BINARIES=1
fi
R2OD_BIN=${R2OD_BIN:-"$TARGET_DIR/release/r2o-datapath"}
R2OC_BIN=${R2OC_BIN:-"$TARGET_DIR/release/r2o-controller"}
FIXTURE="$ROOT/crates/r2k-core/tests/fixtures/quic_v1_initial.bin"
EXPECTED_SHA256=f809a9eb845c020192bfc4a4b83ff19ffc85ecbb8e458deca8c480cda5d2d6e3
QUEUE=65530
TCP_QUEUE=65527
TCP_MARK=21074
TCP6_QUEUE=65526
TCP6_MARK=21075
TCP_DELAY_QUEUE=65524
TCP_DELAY_MARK=21076
TCP_CONTROL_QUEUE=65522
TCP_CONTROL_MARK=21078
TCP_HOLD_QUEUE=65520
TCP_HOLD_MARK=21080
VOICE_QUEUE=65519
VOICE_MARK=21081
OBSERVE_QUEUE=65518
NS="r2o-nfq-test-$$"
WORK=$(mktemp -d)

cleanup() {
    if ip netns list | awk '{print $1}' | grep -Fxq "$NS"; then
        ip netns pids "$NS" | xargs -r kill 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
    if [ "${KEEP_TEST_WORK:-0}" = "1" ]; then
        echo "сохранены файлы проверки: $WORK" >&2
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT HUP INT TERM

if [ "$(id -u)" -ne 0 ]; then
    echo "запустите от root, например: sudo sh scripts/test-nfq-netns.sh" >&2
    exit 1
fi
for tool in ip nft python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "не найдена обязательная команда: $tool" >&2
        exit 1
    }
done
if [ "$BUILD_DEFAULT_BINARIES" -eq 1 ] || \
    [ ! -x "$R2OD_BIN" ] || [ ! -x "$R2OC_BIN" ]; then
    cargo build --release --locked --package r2o-datapath --package r2o-controller
fi
r2o_version=$("$R2OD_BIN" --version)
R2O_CONTROL_WIRE=${r2o_version##*wire=}
case $R2O_CONTROL_WIRE in
    ''|*[!0-9]*)
        echo "не удалось прочитать версию control wire из r2o-datapath --version" >&2
        exit 1
        ;;
esac
R2OD_BIN="$R2OD_BIN" R2OC_BIN="$R2OC_BIN" sh "$SCRIPT_DIR/r2o-quic-silence-netns.sh"

printf '\122\062\117\120\000\001\000\012\000\000\000\002\000\002\000\002\021\002\001\017\000\001\001' >"$WORK/quicsplit.r2op"
printf '\122\062\117\120\000\001\000\013\000\000\000\002\000\002\000\002\021\002\001\020\000\001\001' >"$WORK/quicdeny.r2op"
printf '\122\062\117\120\000\001\000\011\000\000\000\002\000\002\000\002\021\002\001\016\000\002\000\007' >"$WORK/udplen.r2op"
printf '\122\062\117\120\000\001\000\002\000\000\000\002\000\002\000\002\006\001\001\000\000\004\000\005\000\000' >"$WORK/tcp-split.r2op"
python3 - "$WORK/tcp-hold.r2op" <<'PY'
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
header = b"R2OP" + struct.pack("!HHHH", 1, 5, 0, len(records))
with open(sys.argv[1], "wb") as output:
    output.write(header + b"".join(records))
PY
python3 - "$WORK/tcp-empty.r2op" <<'PY'
import struct
import sys

record = struct.pack("!HHBB", 0x0002, 2, 6, 1)
header = b"R2OP" + struct.pack("!HHHH", 1, 0, 0, 1)
with open(sys.argv[1], "wb") as output:
    output.write(header + record)
PY
python3 - "$WORK/tcp-delay.r2op" <<'PY'
import struct
import sys

def tlv(kind, value):
    return struct.pack("!HH", kind, len(value)) + value

records = [
    tlv(0x0002, b"\x06\x01"),
    tlv(0x0010, b"\x00\x01FAKE"),
    tlv(0x0011, b"\x00\x01\x00\x01\x00\x00\x00\x00"),
    tlv(0x0101, b"\x00\x01\x00\x01\x02\x00" + (100_000).to_bytes(4, "big")),
]
header = b"R2OP" + struct.pack("!HHHH", 1, 0, 0, len(records))
with open(sys.argv[1], "wb") as output:
    output.write(header + b"".join(records))
PY
python3 - "$WORK/voice.r2op" <<'PY'
import struct
import sys

def tlv(kind, value):
    return struct.pack("!HH", kind, len(value)) + value

records = [
    tlv(0x0002, b"\x11\x03"),
    tlv(0x0010, b"\x00\x01FAKE"),
    tlv(0x0011, b"\x00\x01\x02\x00\x00\x00\x00\x00"),
    tlv(0x0101, b"\x00\x01\x00\x01\x01\x00\x00\x00\x00\x00"),
]
header = b"R2OP" + struct.pack("!HHHH", 1, 1, 0, len(records))
with open(sys.argv[1], "wb") as output:
    output.write(header + b"".join(records))
PY
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add default dev lo
ip netns exec "$NS" ip -6 route add default dev lo
ip netns exec "$NS" nft add table inet r2o
ip netns exec "$NS" nft 'add chain inet r2o output { type filter hook output priority 0; policy accept; }'
ip netns exec "$NS" nft 'add chain inet r2o input { type filter hook input priority 0; policy accept; }'
ip netns exec "$NS" nft add rule inet r2o output udp dport 443 queue num "$QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o output udp dport 4444 queue num 65528 bypass
ip netns exec "$NS" nft add rule inet r2o output ip daddr 127.0.0.1 udp dport 50004 meta mark != "$VOICE_MARK" queue num "$VOICE_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o input ip saddr 127.0.0.1 udp sport 50004 queue num "$VOICE_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o output ip daddr 127.0.0.1 tcp dport 4445 meta mark != "$TCP_MARK" queue num "$TCP_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o input ip saddr 127.0.0.1 tcp sport 4445 queue num "$TCP_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o output ip daddr 127.0.0.1 tcp dport 4447 meta mark != "$TCP_DELAY_MARK" queue num "$TCP_DELAY_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o input ip saddr 127.0.0.1 tcp sport 4447 queue num "$TCP_DELAY_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o output ip daddr 127.0.0.1 tcp dport 4449 meta mark != "$TCP_CONTROL_MARK" queue num "$TCP_CONTROL_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o input ip saddr 127.0.0.1 tcp sport 4449 queue num "$TCP_CONTROL_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o output ip daddr 127.0.0.1 tcp sport 40131 tcp dport 80 queue num "$OBSERVE_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o output ip daddr 127.0.0.1 tcp dport 80 queue num "$TCP_CONTROL_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o input ip saddr 127.0.0.1 tcp sport 80 tcp dport 40129 queue num "$TCP_CONTROL_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o input ip saddr 127.0.0.1 tcp sport 80 queue num "$OBSERVE_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o output ip daddr 127.0.0.1 tcp dport 4450 meta mark != "$TCP_HOLD_MARK" queue num "$TCP_HOLD_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o input ip saddr 127.0.0.1 tcp sport 4450 queue num "$TCP_HOLD_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o output ip6 daddr ::1 tcp dport 4446 meta mark != "$TCP6_MARK" queue num "$TCP6_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o input ip6 saddr ::1 tcp sport 4446 queue num "$TCP6_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o output ip daddr 127.0.0.1 udp dport 4451 queue num "$OBSERVE_QUEUE" bypass
ip netns exec "$NS" nft add rule inet r2o output ip daddr 127.0.0.1 tcp dport 4452 queue num "$OBSERVE_QUEUE" bypass
ip netns exec "$NS" nft add chain inet r2o quic_observe '{ type filter hook output priority 1; policy accept; }'
ip netns exec "$NS" nft add rule inet r2o quic_observe ip daddr 127.0.0.1 udp dport 443 queue num "$OBSERVE_QUEUE" bypass
ip netns exec "$NS" nft add chain inet r2o quic_control '{ type filter hook output priority 2; policy accept; }'
ip netns exec "$NS" nft add rule inet r2o quic_control ip daddr 127.0.0.1 udp dport 443 queue num "$TCP_CONTROL_QUEUE" bypass

ip netns exec "$NS" "$R2OD_BIN" \
    --queue "$QUEUE" --family ipv4 --plan "$WORK/quicsplit.r2op" \
    >"$WORK/r2o-datapath.log" 2>&1 &
R2OD_PID=$!
sleep 0.2
if ! kill -0 "$R2OD_PID" 2>/dev/null; then
    cat "$WORK/r2o-datapath.log" >&2
    exit 1
fi

ip netns exec "$NS" "$R2OD_BIN" \
    --queue 65528 --family ipv4 --plan "$WORK/udplen.r2op" \
    >"$WORK/r2o-datapath-udplen.log" 2>&1 &
R2OD_UDPLEN_PID=$!
sleep 0.2
if ! kill -0 "$R2OD_UDPLEN_PID" 2>/dev/null; then
    cat "$WORK/r2o-datapath-udplen.log" >&2
    exit 1
fi

ip netns exec "$NS" "$R2OD_BIN" \
    --queue "$TCP_QUEUE" --family ipv4 --plan "$WORK/tcp-split.r2op" --mark "$TCP_MARK" \
    >"$WORK/r2o-datapath-tcp.log" 2>&1 &
R2OD_TCP_PID=$!
sleep 0.2
if ! kill -0 "$R2OD_TCP_PID" 2>/dev/null; then
    cat "$WORK/r2o-datapath-tcp.log" >&2
    exit 1
fi

ip netns exec "$NS" "$R2OD_BIN" \
    --queue "$TCP6_QUEUE" --family ipv6 --plan "$WORK/tcp-split.r2op" --mark "$TCP6_MARK" \
    >"$WORK/r2o-datapath-tcp6.log" 2>&1 &
R2OD_TCP6_PID=$!
sleep 0.2
if ! kill -0 "$R2OD_TCP6_PID" 2>/dev/null; then
    cat "$WORK/r2o-datapath-tcp6.log" >&2
    exit 1
fi

ip netns exec "$NS" "$R2OD_BIN" \
    --queue "$TCP_DELAY_QUEUE" --family ipv4 --plan "$WORK/tcp-delay.r2op" --mark "$TCP_DELAY_MARK" \
    >"$WORK/r2o-datapath-tcp-delay.log" 2>&1 &
R2OD_TCP_DELAY_PID=$!
sleep 0.2
if ! kill -0 "$R2OD_TCP_DELAY_PID" 2>/dev/null; then
    cat "$WORK/r2o-datapath-tcp-delay.log" >&2
    exit 1
fi

ip netns exec "$NS" "$R2OD_BIN" \
    --queue "$TCP_CONTROL_QUEUE" --family ipv4 --controller-only \
    --mark "$TCP_CONTROL_MARK" --control "$WORK/r2o-datapath-control.sock" \
    >"$WORK/r2o-datapath-control.log" 2>&1 &
R2OD_CONTROL_PID=$!
sleep 0.2
if ! kill -0 "$R2OD_CONTROL_PID" 2>/dev/null; then
    cat "$WORK/r2o-datapath-control.log" >&2
    exit 1
fi
ip netns exec "$NS" "$R2OD_BIN" \
    --queue "$VOICE_QUEUE" --family ipv4 --controller-only \
    --mark "$VOICE_MARK" --control "$WORK/r2o-datapath-voice.sock" \
    --r2o-udp-reverse-visible \
    >"$WORK/r2o-datapath-voice.log" 2>&1 &
R2OD_VOICE_PID=$!
sleep 0.2
if ! kill -0 "$R2OD_VOICE_PID" 2>/dev/null; then
    cat "$WORK/r2o-datapath-voice.log" >&2
    exit 1
fi
ip netns exec "$NS" "$R2OD_BIN" \
    --queue "$OBSERVE_QUEUE" --family ipv4 --mode observe --control "$WORK/r2o-datapath-observe.sock" \
    >"$WORK/r2o-datapath-observe.log" 2>&1 &
R2OD_OBSERVE_PID=$!
sleep 0.2
if ! kill -0 "$R2OD_OBSERVE_PID" 2>/dev/null; then
    cat "$WORK/r2o-datapath-observe.log" >&2
    exit 1
fi
printf '%s\n' '{"boxes":[]}' >"$WORK/observe-catalog.json"
ip netns exec "$NS" "$R2OC_BIN" --serve "$WORK/r2o-datapath-observe.sock" "$WORK/observe-catalog.json" \
    >"$WORK/r2o-controller-observe.log" 2>&1 &
R2OC_OBSERVE_PID=$!
observe_attempt=0
while ! grep -Fq "наблюдение активно" "$WORK/r2o-controller-observe.log"; do
    if ! kill -0 "$R2OC_OBSERVE_PID" 2>/dev/null || [ "$observe_attempt" -ge 20 ]; then
        cat "$WORK/r2o-controller-observe.log" >&2
        exit 1
    fi
    sleep 0.05
    observe_attempt=$((observe_attempt + 1))
done
ip netns exec "$NS" "$R2OC_BIN" --set-name "$WORK/r2o-datapath-voice.sock" \
    @discord-voice ipv4 voice "$WORK/voice.r2op"
ip netns exec "$NS" "$R2OD_BIN" \
    --queue "$TCP_HOLD_QUEUE" --family ipv4 --plan "$WORK/tcp-hold.r2op" --mark "$TCP_HOLD_MARK" \
    >"$WORK/r2o-datapath-hold.log" 2>&1 &
R2OD_HOLD_PID=$!
sleep 0.2
if ! kill -0 "$R2OD_HOLD_PID" 2>/dev/null; then
    cat "$WORK/r2o-datapath-hold.log" >&2
    exit 1
fi
python3 - "$WORK/catalog.json" <<'PY'
import json
import sys

plan = (
    "r2o-plan 1 0\n"
    "id 00000000000000000000000000000000\n"
    "proto tcp tls\n"
    "payload 1 46414b45\n"
    "poison 1 badsum\n"
    "fake payload=1 poison=1 repeats=2 gap_us=100000 place=before\n"
)
http_plan = (
    "r2o-plan 1 11\n"
    "id 11111111111111111111111111111111\n"
    "proto tcp http\n"
    "split sni_middle 0\n"
)
now = "2026-10-18T00:00:00Z"
catalog = {
    "schema": 1,
    "updated": now,
    "boxes": [{
        "id": "netns-control",
        "created": now,
        "updated": now,
        "plans": [
            {
                "id": "netns-delay",
                "proto": "tls",
                "text": plan,
                "added": now,
                "successes": 1,
                "enabled": True,
            },
            {
                "id": "netns-http",
                "proto": "http",
                "text": http_plan,
                "added": now,
                "successes": 1,
                "enabled": True,
            },
        ],
        "bindings": [
            {
                "kind": "name",
                "target": "example.test",
                "plan_id": "netns-delay",
                "level": 1,
                "confirmed": now,
                "successes": 1,
                "enabled": True,
                "transport": 6,
                "family": 4,
                "shape": 1,
            },
            {
                "kind": "name",
                "target": "example.test",
                "plan_id": "netns-http",
                "level": 1,
                "confirmed": now,
                "successes": 1,
                "enabled": True,
                "transport": 6,
                "family": 4,
                "shape": 7,
            },
        ],
    }],
}
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump(catalog, output)
PY
ip netns exec "$NS" "$R2OC_BIN" --apply-catalog \
    "$WORK/r2o-datapath-control.sock" "$WORK/catalog.json"

ip netns exec "$NS" python3 - "$FIXTURE" <<'PY'
import socket
import sys
import threading

with open(sys.argv[1], "rb") as fixture:
    initial = fixture.read()
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", 4444))
server.settimeout(4)
received = {}

def receive():
    received["payload"], _ = server.recvfrom(4096)

thread = threading.Thread(target=receive)
thread.start()
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.sendto(initial, ("127.0.0.1", 4444))
thread.join(5)
if thread.is_alive():
    raise SystemExit("ОШИБКА: UDP-датаграмма с удлинённой нагрузкой не дошла до сервера")
expected = initial + b"\x00" * 7
if received["payload"] != expected:
    raise SystemExit(f"ОШИБКА: неожиданные данные UDP после удлинения: {received['payload']!r}")
print("ПРОЙДЕНО: удлинение IPv4 UDP выполнено через NFQUEUE с корректными длиной и контрольными суммами")
PY

ip netns exec "$NS" python3 - "$FIXTURE" "$EXPECTED_SHA256" <<'PY'
import hashlib
import socket
import sys
import threading

fixture, expected = sys.argv[1:]
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", 443))
server.settimeout(4)
result = {}

def receive():
    payload, _ = server.recvfrom(4096)
    result["sha256"] = hashlib.sha256(payload).hexdigest()

thread = threading.Thread(target=receive)
thread.start()
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
with open(fixture, "rb") as source:
    client.sendto(source.read(), ("127.0.0.1", 443))
thread.join(5)
if thread.is_alive():
    raise SystemExit("ОШИБКА: UDP-пакет не дошёл до сервера")
print("SHA-256 принятого пакета:", result["sha256"])
if result["sha256"] != expected:
    raise SystemExit("ОШИБКА: NFQUEUE не передал ожидаемую после разделения QUIC-нагрузку")
print("ПРОЙДЕНО: r2o-datapath преобразовал IPv4 QUIC Initial и передал его через NFQUEUE")
PY

quic_event_attempt=0
while ! grep -Fq 'наблюдение QUIC: IPv4, форма=QUIC, SNI="example.com"' "$WORK/r2o-controller-observe.log"; do
    if ! kill -0 "$R2OC_OBSERVE_PID" 2>/dev/null || [ "$quic_event_attempt" -ge 20 ]; then
        cat "$WORK/r2o-controller-observe.log" >&2
        exit 1
    fi
    sleep 0.05
    quic_event_attempt=$((quic_event_attempt + 1))
done
echo "ПРОЙДЕНО: r2o-controller --serve принял проверенное событие QUIC HELLO из NFQUEUE"

ip netns exec "$NS" "$R2OC_BIN" --set-name "$WORK/r2o-datapath-control.sock" \
    example.com ipv4 quic "$WORK/quicdeny.r2op"
ip netns exec "$NS" python3 - "$FIXTURE" <<'PY'
import socket
import sys

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", 443))
server.settimeout(0.5)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
with open(sys.argv[1], "rb") as source:
    client.sendto(source.read(), ("127.0.0.1", 443))
try:
    server.recvfrom(4096)
except socket.timeout:
    print("ПРОЙДЕНО: план QUIC с SNI, установленный контроллером, отбросил проверенный Initial")
else:
    raise SystemExit("ОШИБКА: план QUIC с SNI, установленный контроллером, не отбросил Initial")
PY

ip netns exec "$NS" python3 - <<'PY'
import socket

payload = b"observe mode passes this datagram unchanged"
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", 4451))
server.settimeout(1)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.sendto(payload, ("127.0.0.1", 4451))
received, _ = server.recvfrom(4096)
if received != payload:
    raise SystemExit("ОШИБКА: режим наблюдения изменил UDP-датаграмму из очереди")
print("ПРОЙДЕНО: режим наблюдения запустился без плана и пропустил трафик NFQUEUE без изменений")
PY

ip netns exec "$NS" python3 - <<'PY'
import socket
import threading

def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise RuntimeError("TCP stream closed before ClientHello was complete")
        data.extend(part)
    return bytes(data)

host = b"passive.example.test"
sni = len(host + b"\x00\x00\x00").to_bytes(2, "big") + b"\x00" + len(host).to_bytes(2, "big") + host
extension = b"\x00\x00" + len(sni).to_bytes(2, "big") + sni
body = (b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00" +
        len(extension).to_bytes(2, "big") + extension)
handshake = b"\x01" + len(body).to_bytes(3, "big") + body
hello = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 4452))
server.listen(1)
server.settimeout(3)
received = {}

def receive_hello():
    connection, _ = server.accept()
    with connection:
        connection.settimeout(3)
        received["hello"] = read_exact(connection, len(hello))

thread = threading.Thread(target=receive_hello)
thread.start()
client = socket.create_connection(("127.0.0.1", 4452), timeout=3)
client.sendall(hello)
client.close()
thread.join(3)
server.close()
if thread.is_alive() or received.get("hello") != hello:
    raise SystemExit("ОШИБКА: режим наблюдения задержал, изменил или потерял поток ClientHello")
print("ПРОЙДЕНО: режим наблюдения пропустил исходный поток ClientHello без изменений")
PY

observe_attempt=0
while ! grep -Fq 'SNI="passive.example.test"' "$WORK/r2o-controller-observe.log"; do
    if ! kill -0 "$R2OC_OBSERVE_PID" 2>/dev/null || [ "$observe_attempt" -ge 20 ]; then
        cat "$WORK/r2o-controller-observe.log" >&2
        exit 1
    fi
    sleep 0.05
    observe_attempt=$((observe_attempt + 1))
done
echo "ПРОЙДЕНО: r2o-controller --serve принял событие TLS HELLO из NFQUEUE"

ip netns exec "$NS" python3 <<'PY'
import socket
import threading

request = b"GET /observed HTTP/1.1\r\nHost: passive.example.test\r\nConnection: close\r\n\r\n"
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 80))
server.listen(1)
server.settimeout(3)
received = {}

def receive_request():
    connection, _ = server.accept()
    with connection:
        connection.settimeout(3)
        received["request"] = connection.recv(4096)
        response = b"HTTP/1.1 302 Found\r\nLocation: http://lawfilter.example/blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        connection.sendall(response)

thread = threading.Thread(target=receive_request)
thread.start()
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.bind(("127.0.0.1", 40131))
client.settimeout(3)
client.connect(("127.0.0.1", 80))
client.sendall(request)
response = client.recv(4096)
client.close()
thread.join(3)
server.close()
if thread.is_alive() or received.get("request") != request:
    raise SystemExit("ОШИБКА: пассивное наблюдение HTTP изменило или задержало запрос")
if response != b"HTTP/1.1 302 Found\r\nLocation: http://lawfilter.example/blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n":
    raise SystemExit("ОШИБКА: пассивное наблюдение HTTP изменило ответ сервера")
print("ПРОЙДЕНО: режим наблюдения пропустил HTTP-запрос без изменений")
PY

observe_attempt=0
while ! grep -Fq 'наблюдение HTTP: IPv4, форма=HTTP-запрос, Host="passive.example.test"' "$WORK/r2o-controller-observe.log"; do
    if ! kill -0 "$R2OC_OBSERVE_PID" 2>/dev/null || [ "$observe_attempt" -ge 20 ]; then
        cat "$WORK/r2o-controller-observe.log" >&2
        exit 1
    fi
    sleep 0.05
    observe_attempt=$((observe_attempt + 1))
done
echo "ПРОЙДЕНО: r2o-controller --serve принял событие полного HTTP-запроса из NFQUEUE"

observe_attempt=0
while ! grep -Fq 'наблюдение HTTP-ответа: IPv4, Host="passive.example.test", исход=обнаружен портал' "$WORK/r2o-controller-observe.log"; do
    if ! kill -0 "$R2OC_OBSERVE_PID" 2>/dev/null || [ "$observe_attempt" -ge 20 ]; then
        cat "$WORK/r2o-controller-observe.log" >&2
        exit 1
    fi
    sleep 0.05
    observe_attempt=$((observe_attempt + 1))
done
echo "ПРОЙДЕНО: r2o-controller --serve распознал портальный исход HTTP-ответа из NFQUEUE"

ip netns exec "$NS" python3 - "$TCP_MARK" <<'PY'
import socket
import struct
import sys
import threading

mark = int(sys.argv[1])
host = b"example.test"
sni_data = len(host + b"\x00\x00\x00").to_bytes(2, "big") + b"\x00" + len(host).to_bytes(2, "big") + host
sni_extension = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data
padding = b"\x00\x15" + (400).to_bytes(2, "big") + bytes([0x5A]) * 400
extensions = sni_extension + padding
body = (b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00" +
        len(extensions).to_bytes(2, "big") + extensions)
handshake = b"\x01" + len(body).to_bytes(3, "big") + body
hello = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
first_segment_len = 73
split_offset = 61 + len(host) // 2
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 4445))
server.listen(1)
server.settimeout(3)
received = {}

def accept_and_read():
    connection, _ = server.accept()
    connection.settimeout(3)
    data = bytearray()
    while len(data) < len(hello):
        part = connection.recv(512)
        if not part:
            break
        data.extend(part)
    received["hello"] = bytes(data)
    connection.close()

capture = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
capture.bind(("127.0.0.1", 0))
capture.settimeout(0.1)
captured = []
stop = threading.Event()

def capture_packets():
    while not stop.is_set():
        try:
            packet, _ = capture.recvfrom(65535)
        except socket.timeout:
            continue
        if len(packet) < 40 or packet[0] >> 4 != 4:
            continue
        ip_header = (packet[0] & 0x0f) * 4
        if packet[9] != socket.IPPROTO_TCP or len(packet) < ip_header + 20:
            continue
        tcp = packet[ip_header:]
        source, destination = struct.unpack("!HH", tcp[:4])
        if destination != 4445:
            continue
        tcp_header = (tcp[12] >> 4) * 4
        sequence = struct.unpack("!I", tcp[4:8])[0]
        captured.append((source, sequence, len(tcp) - tcp_header))

server_thread = threading.Thread(target=accept_and_read)
capture_thread = threading.Thread(target=capture_packets)
server_thread.start()
capture_thread.start()
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.bind(("127.0.0.1", 40123))
client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client.connect(("127.0.0.1", 4445))
client.sendall(hello[:first_segment_len])
threading.Event().wait(0.05)
client.sendall(hello[first_segment_len:])
server_thread.join(4)
client.close()
stop.set()
capture_thread.join(1)
server.close()
capture.close()
if server_thread.is_alive():
    raise SystemExit("ОШИБКА: TCP ClientHello не дошёл до сервера")
if received.get("hello") != hello:
    raise SystemExit(f"ОШИБКА: TCP-поток после разделения отличается: {received.get('hello')!r}")
payloads = [(seq, size) for source, seq, size in captured if source == 40123]
if not any(size == split_offset and (seq + split_offset, first_segment_len - split_offset) in payloads
           for seq, size in payloads):
    raise SystemExit(f"ОШИБКА: NFQUEUE не разделил неполный ClientHello на границе SNI: {payloads!r}")
print("ПРОЙДЕНО: разделённый на SNI ClientHello и последующие TCP-данные дошли до сервера без изменений")
PY

ip netns exec "$NS" python3 - <<'PY'
import socket
import struct
import threading

host = b"example.test"
sni_data = len(host + b"\x00\x00\x00").to_bytes(2, "big") + b"\x00" + len(host).to_bytes(2, "big") + host
sni_extension = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data
padding = b"\x00\x15" + (400).to_bytes(2, "big") + bytes([0x5A]) * 400
extensions = sni_extension + padding
body = (b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00" +
        len(extensions).to_bytes(2, "big") + extensions)
handshake = b"\x01" + len(body).to_bytes(3, "big") + body
hello = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
first_segment_len = 73
split_offset = 61 + len(host) // 2

server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("::1", 4446))
server.listen(1)
server.settimeout(3)
received = {}

def accept_and_read():
    connection, _ = server.accept()
    connection.settimeout(3)
    data = bytearray()
    while len(data) < len(hello):
        part = connection.recv(512)
        if not part:
            break
        data.extend(part)
    received["hello"] = bytes(data)
    connection.close()

capture = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
capture.bind(("::1", 0))
capture.settimeout(0.1)
captured = []
stop = threading.Event()

def capture_packets():
    while not stop.is_set():
        try:
            packet, _ = capture.recvfrom(65535)
        except socket.timeout:
            continue
        if len(packet) < 20:
            continue
        source, destination = struct.unpack("!HH", packet[:4])
        if destination != 4446:
            continue
        tcp_header = (packet[12] >> 4) * 4
        sequence = struct.unpack("!I", packet[4:8])[0]
        captured.append((source, sequence, len(packet) - tcp_header))

server_thread = threading.Thread(target=accept_and_read)
capture_thread = threading.Thread(target=capture_packets)
server_thread.start()
capture_thread.start()
client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
client.bind(("::1", 40124))
client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client.connect(("::1", 4446))
client.sendall(hello[:first_segment_len])
threading.Event().wait(0.05)
client.sendall(hello[first_segment_len:])
server_thread.join(4)
client.close()
stop.set()
capture_thread.join(1)
server.close()
capture.close()
if server_thread.is_alive():
    raise SystemExit("ОШИБКА: IPv6 TCP ClientHello не дошёл до сервера")
if received.get("hello") != hello:
    raise SystemExit(f"ОШИБКА: IPv6-поток после разделения отличается: {received.get('hello')!r}")
payloads = [(seq, size) for source, seq, size in captured if source == 40124]
if not any(size == split_offset and (seq + split_offset, first_segment_len - split_offset) in payloads
           for seq, size in payloads):
    raise SystemExit(f"ОШИБКА: IPv6 NFQUEUE не разделил поток на границе SNI: {payloads!r}")
print("ПРОЙДЕНО: IPv6 ClientHello разделён на границе SNI и дошёл до сервера без изменений")
PY

ip netns exec "$NS" python3 <<'PY'
import socket
import struct
import threading
import time

body = b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00\x00\x00"
handshake = b"\x01" + len(body).to_bytes(3, "big") + body
hello = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 4447))
server.listen(1)
server.settimeout(3)
received = {}

def accept_and_read():
    connection, _ = server.accept()
    connection.settimeout(3)
    data = bytearray()
    while len(data) < len(hello):
        part = connection.recv(512)
        if not part:
            break
        data.extend(part)
    received["hello"] = bytes(data)
    threading.Event().wait(0.25)
    connection.close()

capture = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
capture.bind(("127.0.0.1", 0))
capture.settimeout(0.1)
fake_times = []
stop = threading.Event()

def capture_fakes():
    while not stop.is_set():
        try:
            packet, _ = capture.recvfrom(65535)
        except socket.timeout:
            continue
        if len(packet) < 40 or packet[0] >> 4 != 4:
            continue
        ip_header = (packet[0] & 0x0f) * 4
        if packet[9] != socket.IPPROTO_TCP or len(packet) < ip_header + 20:
            continue
        tcp = packet[ip_header:]
        source, destination = struct.unpack("!HH", tcp[:4])
        tcp_header = (tcp[12] >> 4) * 4
        if source == 40125 and destination == 4447 and tcp[tcp_header:] == b"FAKE":
            fake_times.append(time.monotonic())

server_thread = threading.Thread(target=accept_and_read)
capture_thread = threading.Thread(target=capture_fakes)
server_thread.start()
capture_thread.start()
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.bind(("127.0.0.1", 40125))
client.connect(("127.0.0.1", 4447))
client.sendall(hello)
server_thread.join(3)
time.sleep(0.35)
client.close()
stop.set()
capture_thread.join(1)
server.close()
capture.close()
if server_thread.is_alive() or received.get("hello") != hello:
    raise SystemExit("ОШИБКА: план отложенных подделок изменил или заблокировал исходный TLS-поток")
if len(fake_times) < 2:
    raise SystemExit(f"ОШИБКА: планировщик не отправил оба поддельных пакета: {fake_times!r}")
gap = fake_times[1] - fake_times[0]
if not 0.08 <= gap <= 0.5:
    raise SystemExit(f"ОШИБКА: интервал планировщика вместо 100 мс составил {gap:.3f} с")
print(f"ПРОЙДЕНО: NFQUEUE отправил отложенный TCP-пакет по расписанию с интервалом {gap:.3f} с")
PY

ip netns exec "$NS" python3 <<'PY'
import socket
import struct
import threading
import time

host = b"example.test"
sni_data = len(host + b"\x00\x00\x00").to_bytes(2, "big") + b"\x00" + len(host).to_bytes(2, "big") + host
sni = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data
versions = b"\x00\x2b\x00\x03\x02\x03\x04"
extensions = sni + versions
body = (b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00" +
        len(extensions).to_bytes(2, "big") + extensions)
handshake = b"\x01" + len(body).to_bytes(3, "big") + body
hello = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 4449))
server.listen(1)
server.settimeout(3)
received = {}

def accept_and_read():
    connection, _ = server.accept()
    connection.settimeout(3)
    data = bytearray()
    while len(data) < len(hello):
        part = connection.recv(512)
        if not part:
            break
        data.extend(part)
    received["hello"] = bytes(data)
    time.sleep(0.25)
    connection.close()

capture = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
capture.bind(("127.0.0.1", 0))
capture.settimeout(0.1)
fake_times = []
stop = threading.Event()

def capture_fakes():
    while not stop.is_set():
        try:
            packet, _ = capture.recvfrom(65535)
        except socket.timeout:
            continue
        if len(packet) < 40 or packet[0] >> 4 != 4:
            continue
        ip_header = (packet[0] & 0x0f) * 4
        if packet[9] != socket.IPPROTO_TCP or len(packet) < ip_header + 20:
            continue
        tcp = packet[ip_header:]
        source, destination = struct.unpack("!HH", tcp[:4])
        tcp_header = (tcp[12] >> 4) * 4
        if source == 40127 and destination == 4449 and tcp[tcp_header:] == b"FAKE":
            fake_times.append(time.monotonic())

server_thread = threading.Thread(target=accept_and_read)
capture_thread = threading.Thread(target=capture_fakes)
server_thread.start()
capture_thread.start()
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.bind(("127.0.0.1", 40127))
client.connect(("127.0.0.1", 4449))
client.sendall(hello)
server_thread.join(3)
time.sleep(0.35)
client.close()
stop.set()
capture_thread.join(1)
server.close()
capture.close()
if server_thread.is_alive() or received.get("hello") != hello:
    actual = received.get("hello", b"")
    raise SystemExit(
        "ОШИБКА: план, установленный контроллером, изменил или заблокировал TLS-поток: "
        f"expected {len(hello)} bytes, received {len(actual)}, fake packets {len(fake_times)}"
    )
if len(fake_times) < 2:
    raise SystemExit(f"ОШИБКА: план, установленный контроллером, не отправил отложенные подделки: {fake_times!r}")
gap = fake_times[1] - fake_times[0]
if not 0.08 <= gap <= 0.5:
    raise SystemExit(f"ОШИБКА: интервал плана, установленного контроллером, составил {gap:.3f} с")
print(f"ПРОЙДЕНО: контроллер установил SNI-план, а datapath применил его с интервалом {gap:.3f} с")
PY

ip netns exec "$NS" python3 <<'PY'
import socket

request = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + bytes(range(12))
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", 50004))
server.settimeout(2)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.bind(("127.0.0.1", 40150))
client.sendto(request, ("127.0.0.1", 50004))
received = [server.recvfrom(2048)[0], server.recvfrom(2048)[0]]
client.close()
server.close()
if received != [b"FAKE", request]:
    raise SystemExit(f"ОШИБКА: неверный порядок UDP-подделки Discord RTC и исходного пакета: {received!r}")
print("ПРОЙДЕНО: контроллер установил @discord-voice, datapath отправил подделку перед исходным STUN-запросом")
PY

ip netns exec "$NS" python3 - "$WORK/r2o-datapath-voice.sock" "$R2O_CONTROL_WIRE" "$WORK/voice.r2op" <<'PY'
import socket
import struct
import sys
import threading
import time

def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise RuntimeError("контрольный сокет закрыл соединение")
        data.extend(chunk)
    return bytes(data)

def read_frame(stream):
    length = struct.unpack("!I", read_exact(stream, 4))[0]
    payload = read_exact(stream, length)
    return struct.unpack("!H", payload[:2])[0], payload[2:]

controller = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
controller.settimeout(6)
controller.connect(sys.argv[1])
kind, greeting = read_frame(controller)
wire_version = int(sys.argv[2])
if kind != 0x000A or len(greeting) < 40 or struct.unpack("!H", greeting[38:40])[0] != wire_version:
    raise SystemExit(
        "ОШИБКА: datapath отправил неверное приветствие control wire: "
        f"kind=0x{kind:04x}, body={greeting.hex()}, ожидалась версия {wire_version}"
    )

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", 50004))
server.settimeout(3)
received = []

def receive_datagrams():
    for _ in range(3):
        received.append(server.recvfrom(2048))

receiver = threading.Thread(target=receive_datagrams)
receiver.start()
request = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + bytes(range(12))
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.bind(("127.0.0.1", 40151))
client.sendto(request, ("127.0.0.1", 50004))
time.sleep(0.1)
client.sendto(request, ("127.0.0.1", 50004))
receiver.join(3)
if receiver.is_alive() or [payload for payload, _ in received] != [b"FAKE", request, request]:
    raise SystemExit(f"ОШИБКА: voice-план повторно применён к одному UDP-потоку или изменил пакет: {received!r}")

deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    kind, event = read_frame(controller)
    if kind != 0x000D:
        continue
    if len(event) != 39 or event[0] != 4 or event[37] != 17 or event[38] != 1:
        raise SystemExit(f"ОШИБКА: неверный ключ или направление voice-события: {event!r}")
    first_suspect = event
    print(f"ПРОЙДЕНО: NFQUEUE передала голосовое подозрение контроллеру по wire {wire_version}")
    break
else:
    raise SystemExit("ОШИБКА: datapath не передал событие голосового подозрения")

controller.close()
time.sleep(0.2)
controller = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
controller.settimeout(6)
controller.connect(sys.argv[1])
kind, greeting = read_frame(controller)
if kind != 0x000A or len(greeting) < 40 or struct.unpack("!H", greeting[38:40])[0] != wire_version:
    raise SystemExit(f"ОШИБКА: control reconnect отправил неверное приветствие: {kind:#x}, {greeting!r}")
deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    kind, event = read_frame(controller)
    if kind != 0x000D:
        continue
    if event != first_suspect:
        raise SystemExit(f"ОШИБКА: reconnect изменил поток голосового подозрения: {event!r}")
    print("ПРОЙДЕНО: после control reconnect datapath повторно сообщил неразрешённый voice-поток")
    break
else:
    raise SystemExit("ОШИБКА: после control reconnect datapath не повторил voice-подозрение")

def send_command(command, body):
    payload = struct.pack("!H", command) + body
    controller.sendall(struct.pack("!I", len(payload)) + payload)

def wait_ack(command, trial_id=None):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        kind, body = read_frame(controller)
        if kind != 0x0008:
            continue
        if len(body) < 42 or struct.unpack("!H", body[38:40])[0] != command or body[40] != 1:
            raise SystemExit(f"ОШИБКА: команда 0x{command:04x} не принята datapath: {body!r}")
        if trial_id is not None and (len(body) != 58 or body[42:58] != trial_id):
            raise SystemExit(f"ОШИБКА: ACK не подтвердил voice trial ID: {body!r}")
        return
    raise SystemExit(f"ОШИБКА: datapath не подтвердил команду 0x{command:04x}")

send_command(0x0085, b"")
wait_ack(0x0085)
trial_id = bytes([0x55]) * 16
with open(sys.argv[3], "rb") as plan_file:
    voice_plan = plan_file.read()
probe_body = (
    socket.inet_aton("127.0.0.1")
    + socket.inet_aton("127.0.0.1")
    + struct.pack("!HI", 50004, 120_000)
    + voice_plan
    + trial_id
)
send_command(0x0092, probe_body)
wait_ack(0x0092, trial_id)

trial_request = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + bytes(range(12, 24))
trial_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
trial_client.bind(("127.0.0.1", 40152))
trial_client.sendto(trial_request, ("127.0.0.1", 50004))
trial_datagrams = []
for _ in range(2):
    try:
        trial_datagrams.append(server.recvfrom(2048))
    except TimeoutError:
        break
if [payload for payload, _ in trial_datagrams] != [b"FAKE", trial_request]:
    raise SystemExit(f"ОШИБКА: временный voice-план не применился к точному потоку: {trial_datagrams!r}")
response = b"\x01\x01\x00\x00\x21\x12\xa4\x42" + trial_request[8:20]
server.sendto(response, trial_datagrams[1][1])
trial_client.settimeout(3)
if trial_client.recvfrom(2048)[0] != response:
    raise SystemExit("ОШИБКА: клиент не получил STUN Binding Response через NFQUEUE")

deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    kind, event = read_frame(controller)
    if kind != 0x001D:
        continue
    if len(event) != 54 or event[0] != 4 or event[37] != 17 or event[38:54] == bytes(16):
        raise SystemExit(f"ОШИБКА: неверное STUN-подтверждение voice-пробы: {event!r}")
    if event[38:54] != trial_id:
        raise SystemExit(f"ОШИБКА: STUN-подтверждение относится к другому trial: {event[38:54]!r}")
    print("ПРОЙДЕНО: NFQUEUE передала STUN Binding proof временной voice-пробы")
    break
else:
    raise SystemExit("ОШИБКА: datapath не подтвердил STUN Binding response")

def rtp(sequence, ssrc):
    return b"\x80\x60" + sequence.to_bytes(2, "big") + (sequence * 960).to_bytes(4, "big") + ssrc.to_bytes(4, "big") + b"\x00"

for sequence in range(100, 103):
    trial_client.sendto(rtp(sequence, 0x11223344), ("127.0.0.1", 50004))
    payload, client_address = server.recvfrom(2048)
    if payload != rtp(sequence, 0x11223344):
        raise SystemExit(f"ОШИБКА: исходный RTP пакет изменён: {payload!r}")
    server.sendto(rtp(sequence + 100, 0x55667788), client_address)
    if trial_client.recvfrom(2048)[0] != rtp(sequence + 100, 0x55667788):
        raise SystemExit("ОШИБКА: входящий RTP пакет не прошёл NFQUEUE без изменений")

deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    kind, event = read_frame(controller)
    if kind != 0x001E:
        continue
    if (
        len(event) != 56
        or event[0] != 4
        or event[37] != 17
        or event[38:54] != trial_id
        or event[54:56] != b"\x03\x03"
    ):
        raise SystemExit(f"ОШИБКА: неверное подтверждение двустороннего RTP: {event!r}")
    print("ПРОЙДЕНО: NFQUEUE подтвердила три исходящих и три входящих RTP-пакета")
    break
else:
    raise SystemExit("ОШИБКА: NFQUEUE не передала подтверждение двустороннего RTP")

client.close()
trial_client.close()
server.close()
controller.close()
PY

ip netns exec "$NS" python3 <<'PY'
import socket
import struct
import threading
import time

host = b"example.test"
request = b"GET /held HTTP/1.1\r\nHost: " + host + b"\r\nConnection: close\r\n\r\n"
split_offset = request.index(host) + len(host) // 2
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 80))
server.listen(1)
server.settimeout(3)
received = {}

def accept_and_read():
    connection, _ = server.accept()
    connection.settimeout(3)
    data = bytearray()
    while len(data) < len(request):
        part = connection.recv(512)
        if not part:
            break
        data.extend(part)
    received["request"] = bytes(data)
    connection.close()

capture = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
capture.bind(("127.0.0.1", 0))
capture.settimeout(0.1)
captured = []
stop = threading.Event()

def capture_packets():
    while not stop.is_set():
        try:
            packet, _ = capture.recvfrom(65535)
        except socket.timeout:
            continue
        if len(packet) < 40 or packet[0] >> 4 != 4:
            continue
        ip_header = (packet[0] & 0x0f) * 4
        if packet[9] != socket.IPPROTO_TCP or len(packet) < ip_header + 20:
            continue
        tcp = packet[ip_header:]
        source, destination = struct.unpack("!HH", tcp[:4])
        tcp_header = (tcp[12] >> 4) * 4
        sequence = struct.unpack("!I", tcp[4:8])[0]
        if source == 40129 and destination == 80:
            captured.append((sequence, len(tcp) - tcp_header))

server_thread = threading.Thread(target=accept_and_read)
capture_thread = threading.Thread(target=capture_packets)
server_thread.start()
capture_thread.start()
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.bind(("127.0.0.1", 40129))
client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client.connect(("127.0.0.1", 80))
client.sendall(request[:20])
threading.Event().wait(0.05)
client.sendall(request[20:])
server_thread.join(3)
time.sleep(0.1)
client.close()
stop.set()
capture_thread.join(1)
server.close()
capture.close()
if server_thread.is_alive() or received.get("request") != request:
    raise SystemExit("ОШИБКА: удержанный и разделённый HTTP-запрос не дошёл до сервера без изменений")
if not any(size == split_offset and
           (sequence + split_offset, len(request) - split_offset) in captured
           for sequence, size in captured):
    raise SystemExit(f"ОШИБКА: HTTP-план имени не применён к собранному запросу: {captured!r}")
print("ПРОЙДЕНО: NFQUEUE удержал разделённый HTTP Host, применил план и выпустил исходные пакеты")
PY

ip netns exec "$NS" python3 <<'PY'
import socket
import struct
import threading
import time

host = b"example.test"
sni_data = len(host + b"\x00\x00\x00").to_bytes(2, "big") + b"\x00" + len(host).to_bytes(2, "big") + host
sni_extension = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data
padding = b"\x00\x15" + (400).to_bytes(2, "big") + bytes(400)
extensions = sni_extension + padding
body = (b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00" +
        len(extensions).to_bytes(2, "big") + extensions)
handshake = b"\x01" + len(body).to_bytes(3, "big") + body
hello = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 4450))
server.listen(1)
server.settimeout(3)
received = {}

def accept_and_read():
    connection, _ = server.accept()
    connection.settimeout(3)
    data = bytearray()
    while len(data) < len(hello):
        part = connection.recv(512)
        if not part:
            break
        data.extend(part)
    received["hello"] = bytes(data)
    connection.close()

capture = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
capture.bind(("127.0.0.1", 0))
capture.settimeout(0.1)
captured = []
stop = threading.Event()

def capture_packets():
    while not stop.is_set():
        try:
            packet, _ = capture.recvfrom(65535)
        except socket.timeout:
            continue
        if len(packet) < 40 or packet[0] >> 4 != 4:
            continue
        ip_header = (packet[0] & 0x0f) * 4
        if packet[9] != socket.IPPROTO_TCP or len(packet) < ip_header + 20:
            continue
        tcp = packet[ip_header:]
        source, destination = struct.unpack("!HH", tcp[:4])
        tcp_header = (tcp[12] >> 4) * 4
        sequence = struct.unpack("!I", tcp[4:8])[0]
        if source == 40128 and destination == 4450:
            captured.append((sequence, len(tcp) - tcp_header))

server_thread = threading.Thread(target=accept_and_read)
capture_thread = threading.Thread(target=capture_packets)
server_thread.start()
capture_thread.start()
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.bind(("127.0.0.1", 40128))
client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client.connect(("127.0.0.1", 4450))
client.sendall(hello[:73])
threading.Event().wait(0.05)
client.sendall(hello[73:])
server_thread.join(3)
time.sleep(0.1)
client.close()
stop.set()
capture_thread.join(1)
server.close()
capture.close()
if server_thread.is_alive() or received.get("hello") != hello:
    raise SystemExit("ОШИБКА: удержанный и разделённый ClientHello не дошёл до сервера без изменений")
split_offset = 61 + len(host) // 2
if not any(size == split_offset and
           (sequence + split_offset, len(hello) - split_offset) in captured
           for sequence, size in captured):
    with open("/proc/net/netfilter/nfnetlink_queue", encoding="ascii") as queues:
        queue_stats = queues.read().strip()
    raise SystemExit(
        "ОШИБКА: план TCP-потока не разделил собранный ClientHello: "
        f"пакеты={captured!r}, NFQUEUE={queue_stats!r}"
    )
print("ПРОЙДЕНО: NFQUEUE удержал разделённый ClientHello, применил TLS-план и выпустил исходные пакеты")
PY

ip netns exec "$NS" python3 - "$R2OD_HOLD_PID" <<'PY'
import os
import signal
import socket
import threading
import time
import sys

pid = int(sys.argv[1])
host = b"example.test"
sni_data = len(host + b"\x00\x00\x00").to_bytes(2, "big") + b"\x00" + len(host).to_bytes(2, "big") + host
sni_extension = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data
padding = b"\x00\x15" + (400).to_bytes(2, "big") + bytes(400)
extensions = sni_extension + padding
body = (b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00" +
        len(extensions).to_bytes(2, "big") + extensions)
handshake = b"\x01" + len(body).to_bytes(3, "big") + body
hello = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 4450))
server.listen(1)
server.settimeout(3)
received = bytearray()
first_at = []

def accept_and_read():
    connection, _ = server.accept()
    connection.settimeout(3)
    while len(received) < len(hello):
        part = connection.recv(512)
        if not part:
            break
        if not received:
            first_at.append(time.monotonic())
        received.extend(part)
    connection.close()

thread = threading.Thread(target=accept_and_read)
thread.start()
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.bind(("127.0.0.1", 40130))
client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client.connect(("127.0.0.1", 4450))
started = time.monotonic()
client.sendall(hello[:73])
time.sleep(0.01)
os.kill(pid, signal.SIGTERM)
deadline = time.monotonic() + 0.06
while not first_at and time.monotonic() < deadline:
    time.sleep(0.001)
if not first_at:
    raise SystemExit("ОШИБКА: SIGTERM не освободил удержанный пакет вовремя")
if first_at[0] - started >= 0.09:
    raise SystemExit("ОШИБКА: удержанный пакет ждал таймаут 100 мс вместо завершения по SIGTERM")
client.sendall(hello[73:])
thread.join(2)
client.close()
server.close()
if thread.is_alive() or bytes(received) != hello:
    raise SystemExit("ОШИБКА: штатное завершение по сигналу потеряло остаток удержанного потока")
print("ПРОЙДЕНО: SIGTERM освободил удержанные пакеты NFQUEUE до выхода демона")
PY
if wait "$R2OD_HOLD_PID"; then
    R2OD_HOLD_PID=
else
    cat "$WORK/r2o-datapath-hold.log" >&2
    echo "ОШИБКА: r2o-datapath не завершился корректно после SIGTERM" >&2
    exit 1
fi

ip netns exec "$NS" nft add rule inet r2o output ip6 daddr ::1 udp dport 4443 queue num 65529 bypass
ip netns exec "$NS" "$R2OD_BIN" \
    --queue 65529 --family ipv6 --plan "$WORK/quicdeny.r2op" \
    >"$WORK/r2o-datapath-ipv6.log" 2>&1 &
R2OD_IPV6_PID=$!
sleep 0.2
if ! kill -0 "$R2OD_IPV6_PID" 2>/dev/null; then
    cat "$WORK/r2o-datapath-ipv6.log" >&2
    exit 1
fi

ip netns exec "$NS" python3 - "$FIXTURE" <<'PY'
import socket
import sys

server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
server.bind(("::1", 4443))
server.settimeout(0.5)
client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
with open(sys.argv[1], "rb") as source:
    client.sendto(source.read(), ("::1", 4443))
try:
    server.recvfrom(4096)
except socket.timeout:
    print("ПРОЙДЕНО: r2o-datapath отбросил проверенный IPv6 QUIC Initial через NFQUEUE")
else:
    raise SystemExit("ОШИБКА: пакет qdeny дошёл до UDP-сервера")
PY

kill -TERM "$R2OD_OBSERVE_PID"
if wait "$R2OD_OBSERVE_PID"; then
    R2OD_OBSERVE_PID=
else
    cat "$WORK/r2o-datapath-observe.log" >&2
    echo "ОШИБКА: режим наблюдения не завершился после SIGTERM" >&2
    exit 1
fi
if ! grep -Eq '^r2o-datapath: UDP-потоки [1-9][0-9]* из 2048, отказов 0$' \
    "$WORK/r2o-datapath-observe.log"; then
    cat "$WORK/r2o-datapath-observe.log" >&2
    echo "ОШИБКА: runtime не сохранил UDP-потоки из NFQUEUE в итоговой сводке" >&2
    exit 1
fi
echo "ПРОЙДЕНО: UDP-потоки из NFQUEUE сохранены и показаны в итоговой сводке"

cat "$WORK/r2o-datapath.log" "$WORK/r2o-datapath-udplen.log" "$WORK/r2o-datapath-tcp.log" "$WORK/r2o-datapath-tcp6.log" "$WORK/r2o-datapath-tcp-delay.log" "$WORK/r2o-datapath-control.log" "$WORK/r2o-datapath-voice.log" "$WORK/r2o-datapath-observe.log" "$WORK/r2o-controller-observe.log" "$WORK/r2o-datapath-hold.log" "$WORK/r2o-datapath-ipv6.log"
