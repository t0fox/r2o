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
export DNS_DISCOVERY_ENDPOINTS='192.0.2.53:53 [2001:db8::53]:53 192.0.2.53:5300 [2001:db8::53]:5301 192.0.2.53:5302'
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


def run_until_log(loop, process, log, expected, requests, stale_v6=False):
    deadline = time.monotonic() + 33
    while time.monotonic() < deadline:
        assert process.poll() is None
        if all(line in log.read_text() for line in expected):
            return
        for key, _ in loop.select(.1):
            server, port = key.fileobj, key.data
            query, peer = server.recvfrom(512)
            assert query[2:] == bytes.fromhex("01000001000000000000076578616d706c6503636f6d0000010001")
            requests[(server.family, port)] += 1
            if (port == 5302 and requests[(server.family, port)] <= 3
                    or stale_v6 and server.family == socket.AF_INET6 and port == 53):
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
        )
        requests = collections.Counter()
        run_until_log(loop, process, log, expected, requests)
        assert requests[(socket.AF_INET, 53)] == requests[(socket.AF_INET6, 53)] == 1, requests
        for line in expected:
            print(line)

        def catalog_bindings():
            return [b for box in json.loads(catalog.read_text())["boxes"] for b in box["bindings"]]

        wait_until(lambda: len(catalog_bindings()) == 2, "DNS-привязки не попали в каталог")
        stored = json.loads(catalog.read_text())
        saved = catalog_bindings()
        assert {(b["kind"], b["target"], b["port"], b["transport"], b["shape"], b["dns_query_bytes"])
                for b in saved} == {("addr", a, 53, 17, 14, 29) for a in ("192.0.2.53", "2001:db8::53")}
        assert not stored.get("domain_state")

        query = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
        wrong_length = query[:12] + b"\x08a" + query[13:]
        for server in (server for server in listeners if server.getsockname()[1] == 53):
            server.settimeout(3)
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
        os.environ["DNS_DISCOVERY_ENDPOINTS"] = "192.0.2.53:53 [2001:db8::53]:53"
        process, log = start(serve, "restart.log")
        expected = (
            "DNS/UDP 192.0.2.53:53: адресный план восстановлен из каталога",
            "DNS/UDP [2001:db8::53]:53: адресный план восстановлен из каталога",
            "DNS/UDP 192.0.2.53:53: повторно подтверждены адресный план и DNS-ответ",
            "DNS/UDP [2001:db8::53]:53: постоянный план снят",
            "DNS/UDP [2001:db8::53]:53: два таймаута под сохранённым планом",
        )
        run_until_log(loop, process, log, expected, requests, stale_v6=True)
        wait_until(lambda: any(b["target"] == "2001:db8::53" and b.get("recheck_since")
                               for b in catalog_bindings()), "отзыв IPv6 не попал в каталог")
        bindings = {b["target"]: b for b in catalog_bindings()}
        assert bindings["2001:db8::53"]["recheck_since"]
        assert not bindings["192.0.2.53"].get("recheck_since")
        print("DNS/UDP: восстановление IPv4/IPv6, подтверждение IPv4 и отзыв IPv6 после двух таймаутов")

        run_until_log(loop, process, log, (
            "DNS/UDP [2001:db8::53]:53: подтверждённый адресный план сохранён",
        ), requests)
        assert all(not b.get("recheck_since") for b in catalog_bindings())
        print("DNS/UDP IPv6: отозванный план снова сохранён после свежей проверки")

        stop(process)
        subprocess.run(["nft", "insert", "rule", "inet", "r2o_dns_test", "in",
                        "ip", "daddr", "192.0.2.53", "udp", "dport", "53", "accept"], check=True)
        os.environ["DNS_DISCOVERY_ENDPOINTS"] = "192.0.2.53:53"
        process, log = start(serve, "direct.log")
        run_until_log(loop, process, log, (
            "DNS/UDP 192.0.2.53:53: адресный план восстановлен из каталога",
            "DNS/UDP 192.0.2.53:53: прямой запрос получил корректный ответ",
            "DNS/UDP 192.0.2.53:53: постоянный план снят",
        ), requests)
        assert any(b["target"] == "192.0.2.53" and b.get("recheck_since") for b in catalog_bindings())
        print("DNS/UDP IPv4: сохранённый план отозван после восстановления прямого пути")
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
