#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
target=${CARGO_TARGET_DIR:-"$root/target"}
datapath=${R2OD_BIN:-"$target/release/r2o-datapath"}
[ -x "$datapath" ] || { echo "соберите r2o-datapath или задайте R2OD_BIN" >&2; exit 2; }
if [ "${1:-}" != --netns ]; then
    if [ "$(id -u)" = 0 ]; then
        exec unshare -n sh "$0" --netns "$@"
    fi
    if [ "${1:-}" = --stun ]; then
        echo "режим --stun требует root для чтения /proc/net/nf_conntrack" >&2
        exit 2
    fi
    exec unshare -Urn sh "$0" --netns "$@"
fi
shift
stun=0
if [ "${1:-}" = --stun ]; then stun=1; fi

temp=$(mktemp -d)
pid4=
pid6=
cleanup() {
    for pid in $pid4 $pid6; do kill "$pid" 2>/dev/null || true; done
    for pid in $pid4 $pid6; do wait "$pid" 2>/dev/null || true; done
    rm -rf -- "$temp"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
ip link set lo up
ip route add default dev lo
ip -6 route add default dev lo
nft -f - <<'NFT'
add table inet r2o_endpoint
add chain inet r2o_endpoint out { type filter hook output priority 0; policy accept; }
add rule inet r2o_endpoint out meta mark 19051 return
add rule inet r2o_endpoint out ip daddr 127.0.0.1 udp dport { 3478, 3479, 8443, 8543 } counter queue num 65121
add rule inet r2o_endpoint out ip6 daddr ::1 udp dport { 3478, 3479, 8443, 8543 } counter queue num 65122
NFT
if [ "$stun" = 1 ]; then
    nft add chain inet r2o_endpoint dns_out '{ type filter hook postrouting priority mangle; policy accept; }'
    nft add rule inet r2o_endpoint dns_out meta mark 19051 return
    nft add rule inet r2o_endpoint dns_out ip daddr 127.0.0.1 udp dport 5353 counter queue num 65121
    nft add rule inet r2o_endpoint dns_out ip6 daddr ::1 udp dport 5353 counter queue num 65122
    nft add chain inet r2o_endpoint dns_block '{ type filter hook postrouting priority -149; policy accept; }'
    nft add rule inet r2o_endpoint dns_block meta mark 19052 udp dport 5353 @th,64,16 0x1234 counter drop
    nft add rule inet r2o_endpoint dns_block meta mark 19052 udp dport 5353 counter
    nft add rule inet r2o_endpoint dns_block udp dport 5353 @th,64,16 0x1234 counter
    nft insert rule inet r2o_endpoint out udp dport '{ 3478, 5353 }' ct state '{ new, established }' counter
    nft add chain inet r2o_endpoint in '{ type filter hook input priority 0; policy accept; }'
    nft add rule inet r2o_endpoint in ip saddr 127.0.0.1 udp sport 3478 counter queue num 65121
    nft add rule inet r2o_endpoint in ip6 saddr ::1 udp sport 3478 counter queue num 65122
    [ -r /proc/net/nf_conntrack ] || { echo "нет доступа к /proc/net/nf_conntrack" >&2; exit 2; }
fi
"$datapath" --mode apply --controller-only --udp-reverse-hook --mark 19051 --probe-mark 19052 --family ipv4 --queue 65121 --control "$temp/v4.sock" >"$temp/v4.log" 2>&1 &
pid4=$!
"$datapath" --mode apply --controller-only --udp-reverse-hook --mark 19051 --probe-mark 19052 --family ipv6 --queue 65122 --control "$temp/v6.sock" >"$temp/v6.log" 2>&1 &
pid6=$!

if ! python3 - "$temp" "$root/crates/r2k-core/tests/fixtures" "$stun" <<'PY'
import hashlib
import pathlib
import socket
import struct
import sys
import time

work, fixtures = map(pathlib.Path, sys.argv[1:3])
test_stun = sys.argv[3] == "1"
anonymous = (fixtures / "quic_v1_initial_no_sni.bin").read_bytes()
named = (fixtures / "quic_v1_initial.bin").read_bytes()

def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise RuntimeError("датапат закрыл R2OP")
        data.extend(chunk)
    return bytes(data)

def frame(stream):
    (size,) = struct.unpack("!I", exact(stream, 4))
    p = exact(stream, size)
    return int.from_bytes(p[:2], "big"), p[2:]

def command(stream, opcode, data, trial=None, rejection=None):
    stream.sendall(struct.pack("!IH", len(data) + 2, opcode) + data)
    while True:
        kind, body = frame(stream)
        if kind == 8 and body[38:40] == opcode.to_bytes(2, "big"):
            result = bytes([0, rejection]) if rejection is not None else b"\x01\x00"
            assert body[40:42] == result, (opcode, body.hex())
            if trial is not None:
                assert body[42:58] == trial, body.hex()
            return body

def wait_apply(stream, plan, want, port=8443, trial=None, shape=5):
    deadline = time.monotonic() + (3 if want else .3)
    seen = []
    while time.monotonic() < deadline:
        stream.settimeout(max(.01, deadline - time.monotonic()))
        try:
            kind, body = frame(stream)
        except TimeoutError:
            break
        seen.append((kind, body[:74].hex()))
        if kind == 9 and body[38:54] == plan:
            assert want, "привязка сработала на чужом порту, форме или после DEL"
            assert body[37] == 17
            ports = {int.from_bytes(body[33:35], "big"), int.from_bytes(body[35:37], "big")}
            assert port in ports, body.hex()
            if trial is not None:
                assert body[54:70] == trial, body.hex()
                assert int.from_bytes(body[70:78], "big") > 0, body.hex()
                assert body[86:90] == bytes([2, body[0], shape, 1]), body.hex()
            stream.settimeout(3)
            return body
    stream.settimeout(3)
    assert not want, ("событие точного APPLIED не получено", seen)

def wait_stun_exchange(stream, applied, want):
    deadline = time.monotonic() + (3 if want else .3)
    while time.monotonic() < deadline:
        stream.settimeout(max(.01, deadline - time.monotonic()))
        try:
            kind, body = frame(stream)
        except TimeoutError:
            break
        if kind == 0x20:
            assert want and body == applied, (want, body.hex(), applied.hex())
            stream.settimeout(3)
            return
    stream.settimeout(3)
    assert not want, "событие STUN-обмена не получено"

def wait_stun_suspect(stream, family, address, local_port):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        stream.settimeout(max(.01, deadline - time.monotonic()))
        kind, body = frame(stream)
        if kind == 0x1f:
            expected = bytes([family]) + address + address + struct.pack("!HHBBB", 3478, local_port, 17, 0, 0)
            assert body == expected, (body.hex(), expected.hex())
            stream.settimeout(3)
            return
    raise AssertionError("событие молчания STUN не получено")

def expect_dns_block(server):
    server.settimeout(.2)
    try:
        received = server.recv(512)
    except TimeoutError:
        return
    finally:
        server.settimeout(3)
    raise AssertionError(("DNS-запрос неожиданно прошёл блокировку", received))

for family, af, address in [(4, socket.AF_INET, "127.0.0.1"), (6, socket.AF_INET6, "::1")]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as ctl:
        ctl.settimeout(3)
        path = work / f"v{family}.sock"
        for _ in range(100):
            if path.exists():
                break
            time.sleep(.025)
        ctl.connect(str(path))
        kind, body = frame(ctl)
        assert kind == 10 and body[38:40] == b"\x00\x30"
        plan = bytes([family]) * 16
        key = bytes([family]) + socket.inet_pton(af, address).ljust(16, b"\0") + b"\x03" + struct.pack("!H", 8443)
        tlv = b"R2OP" + struct.pack("!4H", 1, 9, 0, 3)
        tlv += b"\x00\x01\x00\x10" + plan + b"\x00\x02\x00\x02\x11\x02\x01\x0e\x00\x02\x00\x64"
        command(ctl, 0x00a0, key + tlv)
        with socket.socket(af, socket.SOCK_DGRAM) as udp:
            udp.sendto(anonymous, (address, 8543))
            udp.sendto(named, (address, 8443))
            wait_apply(ctl, plan, False)
        with socket.socket(af, socket.SOCK_DGRAM) as udp:
            udp.sendto(anonymous, (address, 8443))
            wait_apply(ctl, plan, True)
        command(ctl, 0x00a1, key)
        with socket.socket(af, socket.SOCK_DGRAM) as udp:
            udp.sendto(anonymous, (address, 8443))
            wait_apply(ctl, plan, False)
        print(f"IPv{family}: точный APPLIED через NFQUEUE, изоляция порта и SNI, DEL")

        if not test_stun:
            continue
        with socket.socket(af, socket.SOCK_DGRAM) as server, socket.socket(af, socket.SOCK_DGRAM) as client:
            server.bind((address, 3478))
            server.settimeout(3)
            client.connect((address, 3478))
            client.settimeout(3)
            local_port = client.getsockname()[1]
            # Первая контрольная датаграмма подтверждает кортеж conntrack до IP-фрагментации.
            client.send(b"conntrack")
            assert server.recv(64) == b"conntrack"
            ip = socket.inet_pton(af, address).ljust(16, b"\0")
            flow = bytes([family]) + ip + ip + struct.pack("!HHB", local_port, 3478, 17)
            request = b"\0\x01\0\0\x21\x12\xa4\x42" + bytes(range(12))
            for _ in range(2):
                client.send(request)
                assert server.recv(64) == request
            wait_stun_suspect(ctl, family, ip, local_port)
            request = request[:8] + bytes(range(1, 13))
            trial = bytes([17 + family]) * 16
            plan = bytes([33 + family]) * 16
            tlv = b"R2OP" + struct.pack("!4H", 1, 7, 0, 3)
            tlv += b"\0\x01\0\x10" + plan + b"\0\x02\0\x02\x11\x03\x01\x0c\0\x01\x01"
            command(ctl, 0x0089, flow + trial + struct.pack("!I", 10000) + tlv, trial)

            with socket.socket(af, socket.SOCK_DGRAM) as foreign:
                foreign.sendto(request, (address, 3478))
                assert server.recv(64) == request
                wait_apply(ctl, plan, False, 3478, trial)
            client.send(b"generic UDP")
            assert server.recv(64) == b"generic UDP"
            wait_apply(ctl, plan, False, 3478, trial)

            client.send(request)
            applied = wait_apply(ctl, plan, True, 3478, trial)
            recovered, peer = server.recvfrom(64)
            assert recovered == request and peer[1] == local_port, (recovered, peer)
            mapped_ip = socket.inet_pton(af, address)
            encoded_ip = bytes(a ^ b for a, b in zip(mapped_ip, request[4:]))
            mapped = struct.pack("!BBH", 0, 1 if family == 4 else 2, local_port ^ 0x2112) + encoded_ip
            reply = struct.pack("!HH", 0x0101, 4 + len(mapped)) + request[4:]
            reply += struct.pack("!HH", 0x20, len(mapped)) + mapped
            foreign_reply = reply[:8] + bytes([reply[8] ^ 0xff]) + reply[9:]
            for wrong in [b"RAW UDP", b"\x01\x01" + request[2:], foreign_reply]:
                server.sendto(wrong, peer)
                assert client.recv(64) == wrong
            wait_stun_exchange(ctl, applied, False)
            server.sendto(reply, peer)
            assert client.recv(64) == reply
            wait_stun_exchange(ctl, applied, True)
            command(ctl, 0x008a, flow + trial, trial)
            print(f"IPv{family}: молчание STUN, точный APPLIED через NFQUEUE, сборка фрагментов, Binding Response, DEL")

        with socket.socket(af, socket.SOCK_DGRAM) as server, socket.socket(af, socket.SOCK_DGRAM) as client:
            server.bind((address, 5353))
            server.settimeout(3)
            client.connect((address, 5353))
            client.settimeout(3)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 19052)
            local_port = client.getsockname()[1]
            flow = bytes([family]) + ip + ip + struct.pack("!HHB", local_port, 5353, 17)
            query = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
            baseline = b"\x56\x78" + query[2:]
            reply = query[:2] + bytes.fromhex("81800001000100000000") + query[12:]
            reply += bytes.fromhex("c00c000100010000003c0004c000020a")
            trial = bytes([49 + family]) * 16
            plan = bytes([65 + family]) * 16
            tlv = b"R2OP" + struct.pack("!4H", 1, 7, 0, 3)
            tlv += b"\0\x01\0\x10" + plan + b"\0\x02\0\x02\x11\x02\x01\x0c\0\x01\x01"
            guard = struct.pack("!IH", 10000, len(query)) + hashlib.sha256(query).digest()
            command(ctl, 0x009c, flow + trial + guard + tlv, trial)
            command(ctl, 0x009c, flow + trial + guard + tlv, trial, rejection=3)
            foreign_trial = bytes([81 + family]) * 16
            command(ctl, 0x008a, flow + foreign_trial, foreign_trial)

            # Иной ID подтверждает кортеж, но не считается обработанным запросом.
            client.send(baseline)
            assert server.recv(512) == baseline
            wait_apply(ctl, plan, False, 5353, trial, shape=14)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0)
            client.send(query)
            assert server.recv(512) == query
            wait_apply(ctl, plan, False, 5353, trial, shape=14)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 19052)
            with socket.socket(af, socket.SOCK_DGRAM) as other:
                other.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 19052)
                other.sendto(query, (address, 5353))
            wait_apply(ctl, plan, False, 5353, trial, shape=14)
            expect_dns_block(server)

            client.send(query)
            applied = wait_apply(ctl, plan, True, 5353, trial, shape=14)
            assert applied[:33] == bytes([family]) + ip + ip
            assert set(struct.unpack("!HH", applied[33:37])) == {local_port, 5353}
            received, peer = server.recvfrom(512)
            assert received == query and peer[1] == local_port
            server.sendto(reply, peer)
            received = client.recv(512)
            assert received[:2] == query[:2] and received[2:12] == bytes.fromhex("81800001000100000000")
            assert received[12:-16] == query[12:] and socket.inet_ntoa(received[-4:]) == "192.0.2.10"
            expect_dns_block(server)
            command(ctl, 0x008a, flow + trial, trial)
            client.send(query)
            wait_apply(ctl, plan, False, 5353, trial, shape=14)
            expect_dns_block(server)
            command(ctl, 0x009c, flow + trial + struct.pack("!I", 100) + guard[4:] + tlv, trial)
            time.sleep(.15)
            client.send(query)
            wait_apply(ctl, plan, False, 5353, trial, shape=14)
            expect_dns_block(server)
            print(f"IPv{family}: DNS-зонд через NFQUEUE, отдельные APPLIED и ответ DNS, изоляция ID/сокета/марки, DEL и истечение")
PY
then
    nft list table inet r2o_endpoint >&2
    if [ "$stun" = 1 ]; then cat /proc/net/nf_conntrack >&2 || true; fi
    cat "$temp/v4.log" "$temp/v6.log" >&2
    exit 1
fi
