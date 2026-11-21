#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
target=${CARGO_TARGET_DIR:-"$root/target"}
datapath=${R2OD_BIN:-"$target/release/r2o-datapath"}
[ -x "$datapath" ] || { echo "соберите r2o-datapath или задайте R2OD_BIN" >&2; exit 2; }
if [ "${1:-}" != --netns ]; then
    exec unshare -Urn sh "$0" --netns
fi

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
add rule inet r2o_endpoint out ip daddr 127.0.0.1 udp dport { 8443, 8543 } counter queue num 65121
add rule inet r2o_endpoint out ip6 daddr ::1 udp dport { 8443, 8543 } counter queue num 65122
NFT
"$datapath" --mode apply --controller-only --mark 19051 --family ipv4 --queue 65121 --control "$temp/v4.sock" >"$temp/v4.log" 2>&1 &
pid4=$!
"$datapath" --mode apply --controller-only --mark 19051 --family ipv6 --queue 65122 --control "$temp/v6.sock" >"$temp/v6.log" 2>&1 &
pid6=$!

if ! python3 - "$temp" "$root/crates/r2k-core/tests/fixtures" <<'PY'
import pathlib
import socket
import struct
import sys
import time

work, fixtures = map(pathlib.Path, sys.argv[1:])
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

def command(stream, opcode, data):
    stream.sendall(struct.pack("!IH", len(data) + 2, opcode) + data)
    while True:
        kind, body = frame(stream)
        if kind == 8 and body[38:40] == opcode.to_bytes(2, "big"):
            assert body[40:42] == b"\x01\x00", (opcode, body.hex())
            return

def wait_apply(stream, plan, want):
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
            assert 8443 in ports, body.hex()
            stream.settimeout(3)
            return
    stream.settimeout(3)
    assert not want, ("событие точного APPLIED не получено", seen)

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
PY
then
    nft list table inet r2o_endpoint >&2
    cat "$temp/v4.log" "$temp/v6.log" >&2
    exit 1
fi
