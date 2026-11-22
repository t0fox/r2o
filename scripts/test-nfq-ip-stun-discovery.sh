#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
target=${CARGO_TARGET_DIR:-"$root/target"}
datapath=${R2OD_BIN:-"$target/release/r2o-datapath"}
controller=${R2OC_BIN:-"$target/release/r2o-controller"}
[ -x "$datapath" ] && [ -x "$controller" ] || { echo "соберите r2o-datapath и r2o-controller" >&2; exit 2; }
if [ "${1:-}" != --netns ]; then
    [ "$(id -u)" = 0 ] || { echo "проверка требует root для conntrack и NFQUEUE" >&2; exit 2; }
    exec unshare -n sh "$0" --netns
fi
[ -r /proc/net/nf_conntrack ] || { echo "нет доступа к /proc/net/nf_conntrack" >&2; exit 2; }

ip link set lo up
ip route add default dev lo
ip -6 route add default dev lo
nft -f - <<'NFT'
add table inet r2o_stun_test
add chain inet r2o_stun_test fragments { type filter hook output priority -450; policy accept; }
add rule inet r2o_stun_test fragments meta mark 19051 ip frag-off & 0x3fff != 0 counter meta mark set 19054
add chain inet r2o_stun_test fragments6 { type filter hook prerouting priority -450; policy accept; }
add rule inet r2o_stun_test fragments6 ip6 daddr ::1 exthdr frag exists counter meta mark set 19054
add chain inet r2o_stun_test out { type filter hook postrouting priority mangle; policy accept; }
add rule inet r2o_stun_test out udp dport 3478 ct state { new, established } counter
add rule inet r2o_stun_test out meta mark { 19051, 19053, 19054 } return
add rule inet r2o_stun_test out ip daddr 127.0.0.1 udp dport 3478 counter queue num 65131
add rule inet r2o_stun_test out ip6 daddr ::1 udp dport 3478 counter queue num 65132
add chain inet r2o_stun_test in { type filter hook input priority 0; policy accept; }
add rule inet r2o_stun_test in udp dport 3478 meta mark 19054 counter accept
add rule inet r2o_stun_test in udp dport 3478 counter drop
add rule inet r2o_stun_test in ip saddr 127.0.0.1 udp sport 3478 counter queue num 65131
add rule inet r2o_stun_test in ip6 saddr ::1 udp sport 3478 counter queue num 65132
NFT

python3 - "$datapath" "$controller" <<'PY'
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

datapath, controller = sys.argv[1:]


def until(predicate, message, deadline=15):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.025)
    raise AssertionError(message)


def mapped_response(request, peer, af):
    ip = socket.inet_pton(af, peer[0])
    encoded = bytes(a ^ b for a, b in zip(ip, request[4:]))
    value = struct.pack("!BBH", 0, 1 if af == socket.AF_INET else 2, peer[1] ^ 0x2112) + encoded
    return (struct.pack("!HH", 0x0101, 4 + len(value)) + request[4:]
            + struct.pack("!HH", 0x20, len(value)) + value)


def bindings(path):
    return [binding for box in json.loads(path.read_text())["boxes"] for binding in box.get("bindings", [])]


for family, af, address, queue in [(4, socket.AF_INET, "127.0.0.1", 65131), (6, socket.AF_INET6, "::1", 65132)]:
    with tempfile.TemporaryDirectory(prefix="r2o-stun-") as directory:
        tmp = pathlib.Path(directory)
        wire = tmp / "r2op.sock"
        catalog = tmp / "catalog.json"
        dp_log, ct_log = (tmp / name for name in ("datapath.log", "controller.log"))
        catalog.write_text('{"boxes":[]}\n')
        processes = []

        def start(command, log):
            with log.open("ab") as output:
                process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            processes.append(process)
            return process

        def start_datapath():
            process = start([datapath, "--mode", "apply", "--controller-only", "--udp-reverse-hook",
                             "--mark", "19051", "--probe-mark", "19052", "--family", f"ipv{family}",
                             "--queue", str(queue), "--control", str(wire)], dp_log)
            until(wire.exists, "не появился контрольный сокет NFQUEUE")
            return process

        def stop(process):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise
            assert process.returncode == 0, process.returncode

        try:
            dp = start_datapath()
            ct = start([controller, "--serve", str(wire), str(catalog), "--discover", "--mark", "19052",
                        "--measure-mark", "19053", "--no-diagnostics"], ct_log)
            with socket.socket(af, socket.SOCK_DGRAM) as server, socket.socket(af, socket.SOCK_DGRAM) as client:
                server.bind((address, 3478))
                server.settimeout(.1)
                client.connect((address, 3478))
                client.settimeout(3)
                stopped = threading.Event()

                def serve():
                    while not stopped.is_set():
                        try:
                            request, peer = server.recvfrom(256)
                        except TimeoutError:
                            continue
                        if len(request) == 20 and request[:8] == b"\0\x01\0\0\x21\x12\xa4\x42":
                            server.sendto(mapped_response(request, peer, af), peer)

                responder = threading.Thread(target=serve, daemon=True)
                responder.start()
                try:
                    until(lambda: "каталог синхронизирован" in ct_log.read_text(), "контроллер не подключился")
                    request = b"\0\x01\0\0\x21\x12\xa4\x42" + bytes(range(12))
                    client.send(request)
                    client.send(request)
                    until(lambda: "зонд подтверждён, жду Binding Response исходного клиента" in ct_log.read_text(),
                          "планировщик не выполнил диагностическую STUN-пробу")
                    assert "сохранён адресный план" not in ct_log.read_text()
                    assert bindings(catalog) == [], bindings(catalog)
                    client.send(request)
                    assert client.recv(256)[8:20] == request[8:20]
                    time.sleep(.25)
                    assert "сохранён адресный план" not in ct_log.read_text(), "сохранён маршрут по старому txid"
                    request = request[:8] + bytes(range(1, 13))
                    client.send(request)
                    assert client.recv(256)[8:20] == request[8:20]
                    until(lambda: "сохранён адресный план" in ct_log.read_text(), "не установлен постоянный STUN endpoint")
                    stop(ct)
                    saved = bindings(catalog)
                    assert len(saved) == 1, saved
                    binding = saved[0]
                    assert (binding["kind"], binding["target"], binding["port"], binding["family"],
                            binding["transport"], binding["shape"], binding["verified_by"]) == ("addr", address, 3478, family, 17, 5, 3), saved
                    assert not json.loads(catalog.read_text()).get("domain_state")

                    stop(dp)
                    dp = start_datapath()
                    subprocess.run([controller, "--apply-catalog", str(wire), str(catalog)], check=True,
                                   capture_output=True, timeout=10)
                    with socket.socket(af, socket.SOCK_DGRAM) as fresh:
                        fresh.connect((address, 3478))
                        fresh.settimeout(3)
                        fresh.send(request)
                        time.sleep(.05)
                        fresh.send(request)
                        assert fresh.recv(256)[8:20] == request[8:20]
                        later = request[:8] + bytes(range(2, 14))
                        fresh.send(later)
                        assert fresh.recv(256)[8:20] == later[8:20]
                finally:
                    stopped.set()
                    responder.join(timeout=1)
            print(f"IPv{family}: подозрение, прямой таймаут, диагностический и клиентский Binding, сохранение и восстановление endpoint")
        except BaseException:
            for log in (dp_log, ct_log):
                if log.exists():
                    print(log.read_text(), file=sys.stderr)
            subprocess.run(["nft", "list", "table", "inet", "r2o_stun_test"], check=False)
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
PY
