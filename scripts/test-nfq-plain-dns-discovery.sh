#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
target=${CARGO_TARGET_DIR:-"$root/target"}
datapath=${R2OD_BIN:-"$target/release/r2o-datapath"}
controller=${R2OC_BIN:-"$target/release/r2o-controller"}
[ -x "$datapath" ] && [ -x "$controller" ] || { echo "соберите r2o-datapath и r2o-controller" >&2; exit 2; }
if [ "${1:-}" != --netns ]; then
    [ "$(id -u)" = 0 ] || { echo "проверка требует root для conntrack и NFQUEUE" >&2; exit 2; }
    exec unshare -n sh "$0" --netns "$@"
fi
shift

backend=${1:-nft}
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM
ip link set lo up
ip addr add 192.0.2.53/32 dev lo
ip -6 addr add 2001:db8::53/128 dev lo nodad
ip route add default dev lo
ip -6 route add default dev lo
export R2O_DIR="$tmp" R2O_RUN_DIR="$tmp/run" R2O_CONFIG="$tmp/config"
export DNS_DISCOVERY_ENDPOINTS='192.0.2.53:53 [2001:db8::53]:53 192.0.2.53:5300 [2001:db8::53]:5301 192.0.2.53:5302 tcp://192.0.2.53:53 tcp://[2001:db8::53]:53'
cat > "$R2O_CONFIG" <<EOF
FW_BACKEND=$backend
QUEUE_NUM=65141
QUEUE_NUM6=65142
MARK=19051
PROBE_MARK=19052
MEASURE_MARK=19053
DNS_PORTS=53,853,5300,5301,5302
R2O_PPE_DEOFFLOAD=0
EOF
if [ "$backend" = iptables ]; then
    # Имитируем обновление обычных исключений upstream после установки правил.
    mkdir "$tmp/bin"
    cat > "$tmp/bin/ndmc" <<'NDMC'
#!/bin/sh
printf 'dns_server = 192.0.2.53\ndns_server = 2001:db8::53\n'
NDMC
    chmod 755 "$tmp/bin/ndmc"
    PATH="$tmp/bin:$PATH"
    export PATH
fi
sh "$root/router/r2o-firewall.sh" up
if [ "$backend" = iptables ]; then sh "$root/router/r2o-firewall.sh" dns-ensure; fi
sh "$root/router/r2o-firewall.sh" status
[ -r /proc/net/nf_conntrack ] || { echo "нет доступа к /proc/net/nf_conntrack" >&2; exit 2; }
nft -f - <<'NFT'
add table inet r2o_dns_test
add chain inet r2o_dns_test f4 { type filter hook output priority -450; policy accept; }
add rule inet r2o_dns_test f4 meta mark 19051 ip frag-off & 0x3fff != 0 meta mark set 19054
add chain inet r2o_dns_test f6 { type filter hook prerouting priority -450; policy accept; }
add rule inet r2o_dns_test f6 ip6 daddr 2001:db8::53 exthdr frag exists meta mark set 19054
add chain inet r2o_dns_test miss { type filter hook postrouting priority -151; policy accept; }
add rule inet r2o_dns_test miss meta mark 19052 udp dport 5302 meta mark set 19053
add chain inet r2o_dns_test in { type filter hook input priority 0; policy accept; }
add rule inet r2o_dns_test in udp dport { 53, 5301 } meta mark != 19054 counter drop
add rule inet r2o_dns_test in meta nfproto ipv4 tcp dport 53 tcp flags & (syn | rst | fin) == 0 meta length > 60 meta mark != 19051 counter drop
add rule inet r2o_dns_test in meta nfproto ipv6 tcp dport 53 tcp flags & (syn | rst | fin) == 0 meta length > 80 meta mark != 19051 counter drop
NFT

python3 - "$datapath" "$controller" "$tmp" <<'PY'
import collections
import json
import os
import pathlib
import selectors
import socket
import subprocess
import sys
import time

datapath, controller, directory = sys.argv[1:]
tmp = pathlib.Path(directory)
logs = []
processes = []
listeners = []


def start(command, name):
    log = tmp / name
    logs.append(log)
    with log.open("wb") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
    processes.append(process)
    return process, log


def wait_until(predicate, message):
    end = time.monotonic() + 5
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.025)
    raise AssertionError(message)


def stop(process):
    if process.poll() is None:
        process.terminate()
    assert process.wait(8) == 0


def start_datapaths():
    result = []
    for family, queue in [(4, 65141), (6, 65142)]:
        wire = tmp / f"v{family}.sock"
        wire.unlink(missing_ok=True)
        process, _ = start([datapath, "--mode", "apply", "--controller-only", "--udp-reverse-hook",
                            "--family", f"ipv{family}", "--queue", str(queue), "--control", str(wire),
                            "--mark", "19051", "--probe-mark", "19052"], f"datapath{family}.log")
        wait_until(wire.exists, f"нет сокета IPv{family}")
        result.append(process)
    return result


def response_for(query):
    return (query[:2] + bytes.fromhex("81800001000100000000") + query[12:]
            + bytes.fromhex("c00c000100010000003c0004c000020a"))

def serve_dns_tcp(loop, stream, data, silence):
    if data is None:
        connection, _ = stream.accept()
        connection.settimeout(2)
        loop.register(connection, selectors.EVENT_READ, bytearray())
        return
    chunk = stream.recv(512)
    if not chunk:
        loop.unregister(stream)
        stream.close()
        return
    data.extend(chunk)
    if len(data) < 31:
        return
    assert len(data) == 31 and data[:2] == b"\0\x1d"
    assert data[4:] == bytes.fromhex("01000001000000000000076578616d706c6503636f6d0000010001")
    if silence:
        return
    reply = response_for(data[2:])
    try:
        stream.sendall(len(reply).to_bytes(2, "big"))
        time.sleep(.01)
        stream.sendall(reply)
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        loop.unregister(stream)
        stream.close()


def run_until_log(loop, process, log, expected, requests, stale=()):
    deadline = time.monotonic() + 33
    while time.monotonic() < deadline:
        assert process.poll() is None
        if all(line in log.read_text() for line in expected):
            return
        for key, _ in loop.select(.1):
            server, port = key.fileobj, key.data
            if server.type == socket.SOCK_STREAM:
                serve_dns_tcp(loop, server, port, (server.family, 6) in stale)
                continue
            query, peer = server.recvfrom(512)
            assert query[2:] == bytes.fromhex("01000001000000000000076578616d706c6503636f6d0000010001")
            requests[(server.family, port)] += 1
            if (port == 5302 and requests[(server.family, port)] <= 3
                    or port == 53 and (server.family, 17) in stale):
                continue
            response = response_for(query)
            if port == 5301:
                response = response[:13] + b"f" + response[14:]
            else:
                server.sendto(bytes([query[0] ^ 1]) + response[1:], peer)
            server.sendto(response, peer)
    raise AssertionError(requests)


try:
    with selectors.DefaultSelector() as loop:
        for address, ports, family in [
            ("192.0.2.53", (53, 5300, 5302), socket.AF_INET),
            ("2001:db8::53", (53, 5301), socket.AF_INET6),
        ]:
            for port in ports:
                server = socket.socket(family, socket.SOCK_DGRAM)
                listeners.append(server)
                server.bind((address, port))
                loop.register(server, selectors.EVENT_READ, port)
            listener = socket.socket(family, socket.SOCK_STREAM)
            listeners.append(listener)
            listener.bind((address, 53))
            listener.listen()
            loop.register(listener, selectors.EVENT_READ)

        datapaths = start_datapaths()
        catalog = tmp / "catalog.json"
        catalog.write_text('{"boxes":[]}\n')
        serve = [controller, "--serve-both", "--serve4", str(tmp / "v4.sock"),
             "--serve6", str(tmp / "v6.sock"), str(catalog), "--discover", "--mark", "19052",
             "--measure-mark", "19053", "--live4", str(tmp / "live4.json"),
             "--live6", str(tmp / "live6.json")]
        process, log = start(serve, "controller.log")
        expected = (
            "DNS/UDP 192.0.2.53:53: точный APPLIED и корректный DNS-ответ",
            "DNS/UDP [2001:db8::53]:53: точный APPLIED и корректный DNS-ответ",
            "DNS/UDP 192.0.2.53:5300: прямой запрос получил корректный ответ",
            "DNS/UDP [2001:db8::53]:5301: получен некорректный DNS-ответ",
            "DNS/UDP 192.0.2.53:5302: получен DNS-ответ, исполнение плана не подтверждено",
            "DNS/TCP 192.0.2.53:53: точный APPLIED и корректный DNS-ответ",
            "DNS/TCP [2001:db8::53]:53: точный APPLIED и корректный DNS-ответ",
        )
        requests = collections.Counter()
        run_until_log(loop, process, log, expected, requests)
        assert requests[(socket.AF_INET, 53)] == requests[(socket.AF_INET6, 53)] == 1, requests
        for line in expected:
            print(line)

        def catalog_bindings():
            return [b for box in json.loads(catalog.read_text())["boxes"] for b in box["bindings"]]

        wait_until(lambda: len(catalog_bindings()) == 4, "DNS-привязки не попали в каталог")
        stored = json.loads(catalog.read_text())
        saved = catalog_bindings()
        assert {(b["kind"], b["target"], b["port"], b["transport"], b["shape"], b["dns_query_bytes"])
                for b in saved} == {("addr", a, 53, transport, shape, length)
                                    for a in ("192.0.2.53", "2001:db8::53")
                                    for transport, shape, length in ((17, 14, 29), (6, 15, 31))}
        assert not stored.get("domain_state")

        query = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
        wrong_length = query[:12] + b"\x08a" + query[13:]
        for server in (server for server in listeners if server.getsockname()[1] == 53):
            server.settimeout(3)
            if server.type == socket.SOCK_STREAM:
                for request in (wrong_length, query):
                    wire = len(request).to_bytes(2, "big") + request
                    with socket.socket(server.family, socket.SOCK_STREAM) as client:
                        client.settimeout(3)
                        client.connect(server.getsockname())
                        with server.accept()[0] as peer:
                            client.sendall(wire)
                            if request == wrong_length:
                                peer.settimeout(.2)
                                try:
                                    peer.recv(1)
                                except TimeoutError:
                                    continue
                                raise AssertionError("неизмеренная длина TCP-запроса прошла блокировку")
                            peer.settimeout(3)
                            with peer.makefile("rb") as incoming:
                                assert incoming.read(len(wire)) == wire
                            reply = response_for(request)
                            frame = len(reply).to_bytes(2, "big") + reply
                            peer.sendall(frame)
                            with client.makefile("rb") as incoming:
                                assert incoming.read(len(frame)) == frame
                print(f"{server.getsockname()[0]}: обычный DNS/TCP прошёл только с измеренной длиной")
                continue
            with socket.socket(server.family, socket.SOCK_DGRAM) as client:
                client.settimeout(3)
                client.connect(server.getsockname())
                client.send(wrong_length)
                assert not loop.select(.2), "неизмеренная длина запроса прошла блокировку"
                for first in [0x12, 0x13]:
                    request = bytes([first]) + query[1:]
                    client.send(request)
                    received, peer = server.recvfrom(512)
                    assert received == request, "план применился к другому запросу"
                    server.sendto(response_for(request), peer)
                    assert client.recv(512) == response_for(request)
            print(f"{server.getsockname()[0]}: адресный план работает для обычного сокета и двух запросов одного потока")

        stop(process)
        for dp in datapaths:
            stop(dp)
        start_datapaths()
        targets = ("192.0.2.53:53", "[2001:db8::53]:53")
        os.environ["DNS_DISCOVERY_ENDPOINTS"] = " ".join([*targets, *(f"tcp://{t}" for t in targets)])
        process, log = start(serve, "restart.log")
        expected = [f"DNS/{transport} {target}: адресный план восстановлен из каталога"
                    for transport in ("UDP", "TCP") for target in targets] + [
            "DNS/UDP 192.0.2.53:53: повторно подтверждены адресный план и DNS-ответ",
            "DNS/TCP [2001:db8::53]:53: повторно подтверждены адресный план и DNS-ответ",
            "DNS/UDP [2001:db8::53]:53: постоянный план снят",
            "DNS/UDP [2001:db8::53]:53: два таймаута под сохранённым планом",
            "DNS/TCP 192.0.2.53:53: постоянный план снят",
            "DNS/TCP 192.0.2.53:53: два таймаута под сохранённым планом",
        ]
        run_until_log(loop, process, log, expected, requests,
                      stale={(socket.AF_INET6, 17), (socket.AF_INET, 6)})

        def rechecks():
            return {(b["target"], b["transport"]) for b in catalog_bindings() if b.get("recheck_since")}

        wait_until(lambda: rechecks() == {("2001:db8::53", 17), ("192.0.2.53", 6)},
                   "в журнале ожидался отзыв только DNS/UDP IPv6 и DNS/TCP IPv4")
        print("DNS/UDP и DNS/TCP: независимое восстановление и отзыв после двух таймаутов")

        run_until_log(loop, process, log, (
            "DNS/UDP [2001:db8::53]:53: подтверждённый адресный план сохранён",
            "DNS/TCP 192.0.2.53:53: подтверждённый адресный план сохранён",
        ), requests)
        wait_until(lambda: not rechecks(), "отозванные планы не сохранились")
        print("DNS/UDP IPv6 и DNS/TCP IPv4: отозванные планы снова сохранены после свежей проверки")

        stop(process)
        for transport in ("udp", "tcp"):
            subprocess.run(["nft", "insert", "rule", "inet", "r2o_dns_test", "in",
                            "ip", "daddr", "192.0.2.53", transport, "dport", "53", "accept"], check=True)
        os.environ["DNS_DISCOVERY_ENDPOINTS"] = "192.0.2.53:53 tcp://192.0.2.53:53"
        process, log = start(serve, "direct.log")
        run_until_log(loop, process, log, [f"DNS/{transport} 192.0.2.53:53: {outcome}"
                                          for transport in ("UDP", "TCP")
                                          for outcome in ("адресный план восстановлен из каталога",
                                                          "прямой запрос получил корректный ответ",
                                                          "постоянный план снят")], requests)
        wait_until(lambda: rechecks() == {("192.0.2.53", 17), ("192.0.2.53", 6)},
                   "прямой путь не снял оба IPv4-плана")
        print("DNS/UDP и DNS/TCP IPv4: оба плана отозваны после восстановления прямого пути")
except BaseException:
    for log in logs:
        print(log.read_text(), file=sys.stderr)
    subprocess.run(["nft", "list", "ruleset"], check=False, stdout=sys.stderr)
    raise
finally:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    for server in listeners:
        server.close()
PY
