#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
TARGET_DIR="$ROOT/target"
TARGET_DIR_OVERRIDE=$(printenv CARGO_TARGET_DIR 2>/dev/null || true)
if [ -n "$TARGET_DIR_OVERRIDE" ]; then
    TARGET_DIR=$TARGET_DIR_OVERRIDE
fi
R2OD_BIN_OVERRIDE=$(printenv R2OD_BIN 2>/dev/null || true)
R2OD_BIN="$TARGET_DIR/release/r2o-datapath"
if [ -n "$R2OD_BIN_OVERRIDE" ]; then
    R2OD_BIN=$R2OD_BIN_OVERRIDE
fi
CLIENT_NS="r2o-v6-client-$$"
GATEWAY_NS="r2o-v6-gateway-$$"
SERVER_NS="r2o-v6-server-$$"
CLIENT_IF="c$$"
GATEWAY_CLIENT_IF="g0$$"
GATEWAY_SERVER_IF="g1$$"
SERVER_IF="s$$"
QUEUE=65530
MARK=0x123
DATAPATH_MARK=119
PORT=4454
TCP_PORT=4455
TCP_CLIENT_PORT=40121
CLIENT_PORT=40120
CLIENT_IP=2001:db8:201::2
GATEWAY_CLIENT_IP=2001:db8:201::1
GATEWAY_SERVER_IP=2001:db8:202::1
SERVER_IP=2001:db8:202::2
WORK=$(mktemp -d)
R2OD_PID=
SERVER_PID=
TCP_SERVER_PID=
BULK_CLIENT_PID=
KEEP_TEST_WORK_VALUE=$(printenv KEEP_TEST_WORK 2>/dev/null || true)

cleanup() {
    test_exit_status=$?
    if [ -n "$R2OD_PID" ]; then
        kill -CONT "$R2OD_PID" 2>/dev/null || true
        kill -TERM "$R2OD_PID" 2>/dev/null || true
        wait "$R2OD_PID" 2>/dev/null || true
        R2OD_PID=
    fi
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=
    fi
    if [ -n "$TCP_SERVER_PID" ]; then
        kill "$TCP_SERVER_PID" 2>/dev/null || true
        wait "$TCP_SERVER_PID" 2>/dev/null || true
        TCP_SERVER_PID=
    fi
    if [ -n "$BULK_CLIENT_PID" ]; then
        kill "$BULK_CLIENT_PID" 2>/dev/null || true
        wait "$BULK_CLIENT_PID" 2>/dev/null || true
        BULK_CLIENT_PID=
    fi
    for test_ns in "$CLIENT_NS" "$GATEWAY_NS" "$SERVER_NS"; do
        if ip netns list | awk '{print $1}' | grep -Fxq "$test_ns"; then
            ip netns pids "$test_ns" | xargs -r kill 2>/dev/null || true
            ip netns del "$test_ns" 2>/dev/null || true
        fi
    done
    if [ "$test_exit_status" -ne 0 ]; then
        for test_log in "$WORK/r2o-datapath.log" "$WORK/server.log"; do
            if [ -f "$test_log" ]; then
                cat "$test_log" >&2 || true
            fi
        done
    fi
    if [ "$KEEP_TEST_WORK_VALUE" = "1" ]; then
        echo "сохранены файлы проверки: $WORK" >&2
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT HUP INT TERM

if [ "$(id -u)" -ne 0 ]; then
    echo "запустите от root, например: sudo sh scripts/test-nfq-ipv6-forward-netns.sh" >&2
    exit 1
fi
for tool in ip nft python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "не найдена обязательная команда: $tool" >&2
        exit 1
    }
done
if [ ! -x "$R2OD_BIN" ]; then
    cargo build --release --locked --package r2o-datapath
fi

printf '\122\062\117\120\000\001\000\000\000\000\000\001\000\002\000\002\006\001' \
    >"$WORK/tcp-only.r2op"
"$R2OD_BIN" --check --plan "$WORK/tcp-only.r2op" >/dev/null

cat >"$WORK/server.py" <<'PY'
import socket
import sys

address = sys.argv[1]
port = int(sys.argv[2])
client_address = sys.argv[3]
ready_path = sys.argv[4]
overflow_path = sys.argv[5]
server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
server.settimeout(15)
server.bind((address, port))
with open(ready_path, "w", encoding="ascii") as ready:
    ready.write("ready")
payload, peer = server.recvfrom(8192)
if len(payload) != 4096 or peer[0] != client_address:
    raise SystemExit(f"unexpected request length/source: {len(payload)}, {peer!r}")
server.sendto(payload, peer)
print(f"request=4096 from={peer[0]}; reply=4096")
received = set()
while len(received) < 100:
    payload, peer = server.recvfrom(8192)
    if not payload.startswith(b"bulk:") or peer[0] != client_address:
        raise SystemExit(f"unexpected bulk packet: {payload!r}, {peer!r}")
    index = int(payload[5:])
    if index < 0 or index >= 100 or index in received:
        raise SystemExit(f"invalid or duplicate bulk packet: {payload!r}")
    received.add(index)
    if len(received) == 33:
        with open(overflow_path, "w", encoding="ascii") as overflow:
            overflow.write("33")
    server.sendto(payload, peer)
print(f"bulk={len(received)}")
PY

cat >"$WORK/client.py" <<'PY'
import socket
import sys

client_address = sys.argv[1]
server_address = sys.argv[2]
port = int(sys.argv[3])
client_port = int(sys.argv[4])
client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
client.bind((client_address, client_port))
client.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), 0x123)
client.settimeout(5)
payload = bytes(range(256)) * 16
client.sendto(payload, (server_address, port))
reply, peer = client.recvfrom(8192)
if reply != payload or peer[0] != server_address:
    raise SystemExit(f"unexpected reply/source: {len(reply)}, {peer!r}")
print(f"reply=4096 from={peer[0]}; SO_MARK=0x123")
PY

cat >"$WORK/tcp-server.py" <<'PY'
import socket
import sys

address, port, ready_path = sys.argv[1:]
expected = bytes(range(256)) * 256
listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.settimeout(15)
listener.bind((address, int(port)))
listener.listen(1)
with open(ready_path, "w", encoding="ascii") as ready:
    ready.write("ready")
connection, peer = listener.accept()
connection.settimeout(15)
received = bytearray()
while True:
    chunk = connection.recv(16384)
    if not chunk:
        break
    received.extend(chunk)
if bytes(received) != expected:
    raise SystemExit(f"unexpected IPv6 TCP request: {len(received)} bytes from {peer!r}")
connection.sendall(received)
connection.shutdown(socket.SHUT_WR)
print(f"tcp_request={len(received)} tcp_reply={len(received)} from={peer[0]}")
connection.close()
listener.close()
PY

cat >"$WORK/tcp-client.py" <<'PY'
import socket
import sys

client_address, server_address = sys.argv[1:3]
server_port = int(sys.argv[3])
client_port = int(sys.argv[4])
client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
client.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), 0x123)
client.bind((client_address, client_port))
client.settimeout(15)
client.connect((server_address, server_port))
payload = bytes(range(256)) * 256
client.sendall(payload)
client.shutdown(socket.SHUT_WR)
received = bytearray()
while True:
    chunk = client.recv(16384)
    if not chunk:
        break
    received.extend(chunk)
if bytes(received) != payload:
    raise SystemExit(f"unexpected IPv6 TCP reply: {len(received)} bytes from {server_address}")
print(f"tcp_reply={len(received)} from={server_address}; SO_MARK=0x123")
client.close()
PY
cat >"$WORK/bulk-client.py" <<'PY'
import socket
import sys

client_address, server_address, ready_path = sys.argv[1:4]
port = int(sys.argv[4])
client_port = int(sys.argv[5])
client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
client.bind((client_address, client_port))
client.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), 0x123)
client.settimeout(15)
for index in range(100):
    client.sendto(f"bulk:{index}".encode(), (server_address, port))
with open(ready_path, "w", encoding="ascii") as ready:
    ready.write("sent")
received = set()
while len(received) < 100:
    payload, peer = client.recvfrom(1024)
    if peer[0] != server_address or not payload.startswith(b"bulk:"):
        raise SystemExit(f"unexpected bulk reply: {payload!r}, {peer!r}")
    index = int(payload[5:])
    if index < 0 or index >= 100 or index in received:
        raise SystemExit(f"invalid or duplicate bulk reply: {payload!r}")
    received.add(index)
print(f"bulk_received={len(received)}; SO_MARK=0x123")
PY

ip netns add "$CLIENT_NS"
ip netns add "$GATEWAY_NS"
ip netns add "$SERVER_NS"
for test_ns in "$CLIENT_NS" "$GATEWAY_NS" "$SERVER_NS"; do
    ip netns exec "$test_ns" ip link set lo up
done

ip link add "$CLIENT_IF" type veth peer name "$GATEWAY_CLIENT_IF"
ip link set "$CLIENT_IF" netns "$CLIENT_NS"
ip link set "$GATEWAY_CLIENT_IF" netns "$GATEWAY_NS"
ip link add "$GATEWAY_SERVER_IF" type veth peer name "$SERVER_IF"
ip link set "$GATEWAY_SERVER_IF" netns "$GATEWAY_NS"
ip link set "$SERVER_IF" netns "$SERVER_NS"

ip netns exec "$CLIENT_NS" ip link set "$CLIENT_IF" mtu 1280 up
ip netns exec "$GATEWAY_NS" ip link set "$GATEWAY_CLIENT_IF" mtu 1280 up
ip netns exec "$GATEWAY_NS" ip link set "$GATEWAY_SERVER_IF" mtu 1280 up
ip netns exec "$SERVER_NS" ip link set "$SERVER_IF" mtu 1280 up

ip netns exec "$CLIENT_NS" ip -6 addr add "$CLIENT_IP"/64 dev "$CLIENT_IF" nodad
ip netns exec "$GATEWAY_NS" ip -6 addr add "$GATEWAY_CLIENT_IP"/64 dev "$GATEWAY_CLIENT_IF" nodad
ip netns exec "$GATEWAY_NS" ip -6 addr add "$GATEWAY_SERVER_IP"/64 dev "$GATEWAY_SERVER_IF" nodad
ip netns exec "$SERVER_NS" ip -6 addr add "$SERVER_IP"/64 dev "$SERVER_IF" nodad

ip netns exec "$GATEWAY_NS" sysctl -q -w net.ipv6.conf.all.forwarding=1
ip netns exec "$CLIENT_NS" ip -6 route add default via "$GATEWAY_CLIENT_IP" dev "$CLIENT_IF"
ip netns exec "$SERVER_NS" ip -6 route add default via "$GATEWAY_SERVER_IP" dev "$SERVER_IF"
ip netns exec "$CLIENT_NS" ip -6 route add default via "$GATEWAY_CLIENT_IP" dev "$CLIENT_IF" table 100
ip netns exec "$CLIENT_NS" ip -6 rule add priority 100 fwmark "$MARK"/0xffffffff table 100
route=$(ip netns exec "$CLIENT_NS" ip -6 route get "$SERVER_IP" from "$CLIENT_IP" mark "$MARK")
printf '%s\n' "$route" | grep -Fq "via $GATEWAY_CLIENT_IP" || {
    echo "ОШИБКА: SO_MARK не выбрал IPv6 table 100 через gateway" >&2
    printf '%s\n' "$route" >&2
    exit 1
}

ip netns exec "$GATEWAY_NS" nft add table inet r2o
ip netns exec "$GATEWAY_NS" nft 'add chain inet r2o forward { type filter hook forward priority 0; policy accept; }'
ip netns exec "$GATEWAY_NS" nft 'add rule inet r2o forward ct state { new, established } counter'
ip netns exec "$GATEWAY_NS" nft add rule inet r2o forward \
    ip6 saddr "$CLIENT_IP" ip6 daddr "$SERVER_IP" udp dport "$PORT" \
    meta mark != "$DATAPATH_MARK" counter queue num "$QUEUE"
ip netns exec "$GATEWAY_NS" nft add rule inet r2o forward \
    ip6 saddr "$SERVER_IP" ip6 daddr "$CLIENT_IP" udp sport "$PORT" \
    meta mark != "$DATAPATH_MARK" counter queue num "$QUEUE"
ip netns exec "$GATEWAY_NS" nft add rule inet r2o forward \
    ip6 saddr "$CLIENT_IP" ip6 daddr "$SERVER_IP" tcp dport "$TCP_PORT" \
    meta mark != "$DATAPATH_MARK" counter queue num "$QUEUE"
ip netns exec "$GATEWAY_NS" nft add rule inet r2o forward \
    ip6 saddr "$SERVER_IP" ip6 daddr "$CLIENT_IP" tcp sport "$TCP_PORT" \
    meta mark != "$DATAPATH_MARK" counter queue num "$QUEUE"

ip netns exec "$GATEWAY_NS" "$R2OD_BIN" \
    --queue "$QUEUE" --family ipv6 --plan "$WORK/tcp-only.r2op" \
    --mark "$DATAPATH_MARK" --queue-len 32 --stats 0 \
    >"$WORK/r2o-datapath.log" 2>&1 &
R2OD_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    grep -Fq "r2o-datapath: очередь $QUEUE, IPv6" "$WORK/r2o-datapath.log" && break
    kill -0 "$R2OD_PID" 2>/dev/null || {
        cat "$WORK/r2o-datapath.log" >&2
        exit 1
    }
    sleep 0.05
done
grep -Fq "r2o-datapath: очередь $QUEUE, IPv6" "$WORK/r2o-datapath.log" || {
    cat "$WORK/r2o-datapath.log" >&2
    echo "ОШИБКА: IPv6 NFQUEUE consumer не запустился" >&2
    exit 1
}

ip netns exec "$SERVER_NS" python3 "$WORK/server.py" \
    "$SERVER_IP" "$PORT" "$CLIENT_IP" "$WORK/server.ready" "$WORK/bulk.overflow" \
    >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -f "$WORK/server.ready" ] && break
    kill -0 "$SERVER_PID" 2>/dev/null || {
        cat "$WORK/server.log" >&2
        exit 1
    }
    sleep 0.05
done
[ -f "$WORK/server.ready" ] || {
    cat "$WORK/server.log" >&2
    echo "ОШИБКА: IPv6 UDP echo listener не запустился" >&2
    exit 1
}

ip netns exec "$CLIENT_NS" python3 "$WORK/client.py" \
    "$CLIENT_IP" "$SERVER_IP" "$PORT" "$CLIENT_PORT"
ip netns exec "$SERVER_NS" python3 "$WORK/tcp-server.py" \
    "$SERVER_IP" "$TCP_PORT" "$WORK/tcp-server.ready" \
    >"$WORK/tcp-server.log" 2>&1 &
TCP_SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -f "$WORK/tcp-server.ready" ] && break
    kill -0 "$TCP_SERVER_PID" 2>/dev/null || {
        cat "$WORK/tcp-server.log" >&2
        exit 1
    }
    sleep 0.05
done
[ -f "$WORK/tcp-server.ready" ] || {
    cat "$WORK/tcp-server.log" >&2
    echo "IPv6 TCP echo listener did not start" >&2
    exit 1
}
ip netns exec "$CLIENT_NS" python3 "$WORK/tcp-client.py" \
    "$CLIENT_IP" "$SERVER_IP" "$TCP_PORT" "$TCP_CLIENT_PORT"
wait "$TCP_SERVER_PID"
TCP_SERVER_PID=
kill -STOP "$R2OD_PID"
ip netns exec "$CLIENT_NS" python3 "$WORK/bulk-client.py" \
    "$CLIENT_IP" "$SERVER_IP" "$WORK/bulk.ready" "$PORT" "$CLIENT_PORT" &
BULK_CLIENT_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -f "$WORK/bulk.ready" ] && break
    kill -0 "$BULK_CLIENT_PID" 2>/dev/null || {
        echo "IPv6 queue-overflow client exited before sending all packets" >&2
        exit 1
    }
    sleep 0.05
done
[ -f "$WORK/bulk.ready" ] || {
    echo "IPv6 queue-overflow client did not send its packet batch" >&2
    exit 1
}
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -f "$WORK/bulk.overflow" ] && break
    sleep 0.05
done
[ -f "$WORK/bulk.overflow" ] || {
    echo "IPv6 fail-open did not forward 33 packets while datapath was stopped" >&2
    exit 1
}
echo "IPv6 fail-open forwarded 33 packets while datapath was stopped"
kill -CONT "$R2OD_PID"
wait "$BULK_CLIENT_PID"
BULK_CLIENT_PID=
wait "$SERVER_PID"
SERVER_PID=
if ! ip netns exec "$GATEWAY_NS" nft list chain inet r2o forward | \
    grep -Eq "udp dport $PORT .*counter packets 101 bytes" ||
    ! ip netns exec "$GATEWAY_NS" nft list chain inet r2o forward | \
    grep -Eq "udp sport $PORT .*counter packets 101 bytes" ||
    ! ip netns exec "$GATEWAY_NS" nft list chain inet r2o forward |
    grep -Eq "tcp dport $TCP_PORT .*counter packets [1-9][0-9]* bytes" ||
    ! ip netns exec "$GATEWAY_NS" nft list chain inet r2o forward |
    grep -Eq "tcp sport $TCP_PORT .*counter packets [1-9][0-9]* bytes"; then
    ip netns exec "$GATEWAY_NS" nft list chain inet r2o forward >&2
    echo "ОШИБКА: IPv6 request/reply не прошли оба NFQUEUE forward rule" >&2
    exit 1
fi
ip netns exec "$GATEWAY_NS" python3 - "$CLIENT_IP" "$SERVER_IP" "$CLIENT_PORT" "$PORT" "$WORK/proc-nf-conntrack-unavailable" <<'PY'
import ipaddress
import sys

client = ipaddress.IPv6Address(sys.argv[1])
server = ipaddress.IPv6Address(sys.argv[2])
client_port = sys.argv[3]
server_port = sys.argv[4]
candidates = []
try:
    table = open("/proc/net/nf_conntrack", encoding="ascii")
except FileNotFoundError:
    open(sys.argv[5], "w", encoding="ascii").close()
    print("proc conntrack table is unavailable; packets and nft counters verify IPv6 forwarding")
else:
    with table:
        for line in table:
            fields = {}
            for field in line.split():
                if "=" in field:
                    key, value = field.split("=", 1)
                    fields.setdefault(key, []).append(value)
            if server_port in fields.get("sport", []) or server_port in fields.get("dport", []):
                candidates.append(line.rstrip())
            if (
                len(fields.get("src", [])) > 1
                and len(fields.get("dst", [])) > 1
                and ipaddress.IPv6Address(fields["src"][0]) == client
                and ipaddress.IPv6Address(fields["dst"][0]) == server
                and fields.get("sport", [""])[0] == client_port
                and fields.get("dport", [""])[0] == server_port
                and ipaddress.IPv6Address(fields["src"][1]) == server
                and ipaddress.IPv6Address(fields["dst"][1]) == client
            ):
                print("conntrack contains IPv6 original/reply tuples through gateway")
                break
        else:
            print("conntrack candidates:", candidates, file=sys.stderr)
            raise SystemExit("conntrack does not contain the full IPv6 request/reply tuple")
PY

kill -TERM "$R2OD_PID"
if wait "$R2OD_PID"; then
    R2OD_PID=
else
    cat "$WORK/r2o-datapath.log" >&2
    echo "ОШИБКА: IPv6 gateway datapath не завершился после SIGTERM" >&2
    exit 1
fi
if [ -f "$WORK/proc-nf-conntrack-unavailable" ]; then
    echo "ПРОЙДЕНО: IPv6 SO_MARK, UDP/TCP request/reply NFQUEUE, 64-KiB TCP echo и fail-open (proc conntrack tuple check unavailable)"
else
    echo "ПРОЙДЕНО: IPv6 SO_MARK, UDP/TCP request/reply NFQUEUE, 64-KiB TCP echo, conntrack и fail-open переполнения 32-пакетной очереди (100/100 UDP)"
fi
cat "$WORK/r2o-datapath.log" "$WORK/server.log"
