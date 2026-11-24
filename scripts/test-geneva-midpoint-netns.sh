#!/usr/bin/env bash
# Сравнение планов на своём TLS-сервере в двух изолированных netns.
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ] || { [ "$#" -eq 3 ] && [ "$3" != --discovery ] && [ "$3" != --lan-discovery ]; }; then
  echo "Использование: sudo bash $0 /путь/r2o-datapath /путь/r2o-controller [--discovery|--lan-discovery]" >&2
  exit 2
fi
unshare -n bash -s -- "$@" <<'NETNS'
set -eu
dp=$1
controller=$2
discovery=${3:-}
measure=${R2O_DISCOVERY_MEASURE:-}
if [ -n "$measure" ] && [ "$discovery" != --lan-discovery ]; then
  echo 'Замер подбора требует --lan-discovery' >&2
  exit 2
fi
namespace_lifetime=110
if [ -n "$measure" ]; then
  namespace_lifetime=300
fi
lab=$(mktemp -d "${TMPDIR:-/tmp}/geneva-netns.XXXXXX")
echo "$lab"
daemon=
server=
watcher=
lan=
unshare -n sleep "$namespace_lifetime" &
peer=$!
cleanup() {
  for pid in "$watcher" "$daemon" "$server" "$peer" "$lan"; do
     if test -n "$pid"; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
}
trap cleanup EXIT
sleep .1
ip link set lo up
ip link add veth0 type veth peer name veth1
ip link set veth1 netns "$peer"
ip link set veth0 up
ip addr add 198.51.100.1/30 dev veth0
# Датапат сверяет интерфейс с маршрутом по умолчанию внутри netns.
ip route add default dev veth0
nsenter -t "$peer" -n ip link set lo up
nsenter -t "$peer" -n ip link set veth1 up
nsenter -t "$peer" -n ip addr add 198.51.100.2/30 dev veth1
if [ "$discovery" = --lan-discovery ]; then
  unshare -n sleep "$namespace_lifetime" &
  lan=$!
  sleep .1
  ip link add rlan type veth peer name client
  ip link set client netns "$lan"
  ip addr add 203.0.113.1/30 dev rlan
  ip link set rlan up
  nsenter -t "$lan" -n ip link set lo up
  nsenter -t "$lan" -n ip link set client up
  nsenter -t "$lan" -n ip addr add 203.0.113.2/30 dev client
  nsenter -t "$lan" -n ip route add default via 203.0.113.1
  nsenter -t "$peer" -n ip route add 203.0.113.0/30 via 198.51.100.1
  sysctl -qw net.ipv4.ip_forward=1
  nsenter -t "$lan" -n sysctl -qw net.ipv4.tcp_timestamps=0
  export R2O_DIR="$lab" R2O_RUN_DIR="$lab/run" R2O_PLATFORM=openwrt FW_BACKEND=nft
  export QUEUE_NUM=52692 IPV6_ENABLED=0 PORTS=443 R2O_PLATFORM_RUNTIME=1
  export R2O_SOFTWARE_PATH_ENDPOINTS='' DNS_DISCOVERY_ENDPOINTS=''
fi
if [ -n "$measure" ]; then
  nsenter -t "$peer" -n ip addr add 198.51.100.6/32 dev veth1
  ip route add 198.51.100.6/32 dev veth0
fi
if [ -n "$discovery" ]; then
  # В этой проверке фильтр читает первый байт данных после TCP-заголовка без опций.
  sysctl -qw net.ipv4.tcp_timestamps=0
  nsenter -t "$peer" -n sysctl -qw net.ipv4.tcp_timestamps=0
fi
openssl req -x509 -newkey rsa:2048 -keyout "$lab/key.pem" -out "$lab/cert.pem" -subj /CN=a.example.com \
  -addext subjectAltName=DNS:a.example.com,DNS:b.example.net -days 1 -noenc >"$lab/key.log" 2>&1
cat >"$lab/peer.py" <<'PY'
import socket
import ssl
import sys
import threading

root = sys.argv[1]
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
context.load_cert_chain(f"{root}/cert.pem", f"{root}/key.pem")
def serve(peer):
    with peer:
        peer.settimeout(2)
        try:
            with context.wrap_socket(peer, server_side=True) as tls:
                if not tls.recv(4096).startswith(b"GET "):
                    return
                body = b"verified LAN/WAN response\n"
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                            str(len(body)).encode() + b"\r\n\r\n" + body)
                tls.unwrap().close()
        except (TimeoutError, OSError):
            pass
with socket.create_server(("0.0.0.0", 443)) as listener:
    while True:
        peer, _ = listener.accept()
        threading.Thread(target=serve, args=(peer,), daemon=True).start()
PY
nsenter -t "$peer" -n python3 "$lab/peer.py" "$lab" >"$lab/server.log" 2>&1 &
server=$!
sleep .3
client() {
  local args=()
  local host=${2:-a.example.com}
  if [ -n "$lan" ]; then args=(nsenter -t "$lan" -n); fi
  printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$host" |
    "${args[@]}" timeout 3s openssl s_client -connect "${3:-198.51.100.2}:443" -servername "$host" -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups X25519 -alpn h2 -no_ticket -CAfile "$lab/cert.pem" -verify_hostname "$host" -verify_return_error -brief -ign_eof >"$lab/$1.log" 2>&1
}
verified() {
  grep -q 'Verification: OK' "$lab/$1.log" &&
    grep -q 'HTTP/1.1 200 OK' "$lab/$1.log" &&
    grep -Fxq 'verified LAN/WAN response' "$lab/$1.log"
}
client clear
verified clear
python3 - "$lab" <<'PY'
import pathlib, struct, sys
root = pathlib.Path(sys.argv[1])
def write(name, tag, records):
    records = [(0x0001, bytes([tag]) * 16), (0x0002, b"\x06\x01")] + records
    (root / name).write_bytes(b"R2OP" + struct.pack("!HHHH",1,15 if name == "midpoint.plan" else 5,0,len(records)) +
        b"".join(struct.pack("!HH", key, len(value)) + value for key, value in records))
write("chunk.plan", 0xb1, [(0x0109,b"\x01"),(0x010a,b""),(0x0108,struct.pack("!I",1400))] +
    [(0x0100,struct.pack("!Hh",0,pos)) for pos in range(178,1600,178)])
write("midpoint.plan", 0xc1, [(0x0112,b"\x00\x18"),(0x0100,struct.pack("!Hh",3,0))])
PY
nsenter -t "$peer" -n nft 'add table inet r2o_lab'
nsenter -t "$peer" -n nft 'add chain inet r2o_lab input { type filter hook input priority 0; policy accept; }'
if [ -n "$discovery" ]; then
  nsenter -t "$peer" -n nft 'add chain inet r2o_lab output { type filter hook output priority 0; policy accept; }'
  nsenter -t "$peer" -n nft add rule inet r2o_lab output tcp sport 443 @th,160,8 22 counter ct mark set 1
  nsenter -t "$peer" -n nft add rule inet r2o_lab input tcp dport 443 ct mark 0 ip length '>=' 122 counter drop
else
  nsenter -t "$peer" -n nft add rule inet r2o_lab input tcp dport 443 ip length '>=' 175 counter drop
fi
if [ -z "$lan" ]; then
  nft 'add table inet r2o_lab'
  nft 'add chain inet r2o_lab output { type filter hook output priority 0; policy accept; }'
  nft 'add rule inet r2o_lab output ct state { new, established } counter'
  nft add rule inet r2o_lab output tcp dport 443 meta mark != 45 queue num 52692 bypass
  nft 'add chain inet r2o_lab input { type filter hook input priority 0; policy accept; }'
  nft add rule inet r2o_lab input tcp sport 443 queue num 52692 bypass
fi
client blocked || true
if grep -q 'CONNECTION ESTABLISHED' "$lab/blocked.log"; then echo 'Контрольная блокировка не сработала'; exit 1; fi
if [ -n "$discovery" ]; then
  "$dp" --mode apply --queue 52692 --family ipv4 --mark 45 --probe-mark 46 --controller-only --control "$lab/dp.sock" >"$lab/datapath.log" 2>&1 &
  daemon=$!
  sleep .3
  if [ -n "$lan" ]; then
    "$dp" --platform up
    "$dp" --platform status
  fi
  "$controller" --serve "$lab/dp.sock" "$lab/catalog.json" --discover --mark 46 --measure-mark 46 --live "$lab/discovery.json" --no-diagnostics >"$lab/controller.log" 2>&1 &
  watcher=$!
  sleep 1
  if [ -n "$measure" ]; then
    source "$measure"
    measure_root=$lab
    measure_log=$lab/controller.log
    request() { client "$@"; }
    application() { verified "$@"; }
    measure_discovery cold a.example.com 198.51.100.2 || { tail -60 "$measure_log" "$lab/datapath.log"; exit 1; }
    measure_discovery warm b.example.net 198.51.100.6 || { tail -60 "$measure_log" "$lab/datapath.log"; exit 1; }
    "$dp" --platform down
    exit 0
  fi
  discovery_started=$SECONDS
  client trigger || true
  # Контроллер пишет подтверждения в файл с интервалом 60 секунд.
  for ((attempt = 0; attempt < 40; attempt++)); do
    [ ! -s "$lab/catalog.json" ] || break
    kill -0 "$daemon" "$watcher"
    sleep 2
  done
  python3 - "$lab/catalog.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    catalog = json.load(source)
for box in catalog["boxes"]:
    for plan in box["plans"]:
        if not plan["enabled"] or not all(line in plan["text"].splitlines() for line in (
            "r2o-plan 1 15", "input tcp-flags PA", "split hello_middle +0", "order forward"
        )):
            continue
        if any(b["target"] == "a.example.com" and b["plan_id"] == plan["id"]
               and b["enabled"] and b["level"] == 3 for b in box["bindings"]):
            print(f"Discovery: подтверждённый план {plan['id']} сохранён")
            sys.exit(0)
sys.exit("В каталоге нет подтверждённого плана Geneva")
PY
  client recovered
  verified recovered
  echo 'После сохранения плана HTTPS прошёл'
  if [ -n "$lan" ]; then
    printf 'LAN_TLS_DISCOVERY_PASS elapsed_seconds=%s\n' "$((SECONDS - discovery_started))"
    kill "$watcher" "$daemon"
    wait "$watcher" || true
    wait "$daemon" || true
    watcher=
    daemon=
    repeat_started=$SECONDS
    "$dp" --mode apply --queue 52692 --family ipv4 --mark 45 --probe-mark 46 --controller-only --control "$lab/dp.sock" >"$lab/datapath-repeat.log" 2>&1 &
    daemon=$!
    for ((attempt = 0; attempt < 30; attempt++)); do
        "$dp" --platform status >/dev/null 2>&1 && [ -S "$lab/dp.sock" ] && break
        sleep .1
    done
    "$dp" --platform status
    "$controller" --serve "$lab/dp.sock" "$lab/catalog.json" --discover --mark 46 --measure-mark 46 --live "$lab/discovery-repeat.json" --no-diagnostics >"$lab/controller-repeat.log" 2>&1 &
    watcher=$!
    for ((attempt = 0; attempt < 5; attempt++)); do
        client repeat || true
        verified repeat && break
        kill -0 "$daemon" "$watcher"
        sleep 1
    done
    verified repeat
    printf 'LAN_TLS_REUSE_PASS elapsed_seconds=%s\n' "$((SECONDS - repeat_started))"
    "$dp" --platform down
  fi
  exit
fi
for plan in chunk midpoint; do
  "$dp" --mode apply --queue 52692 --family ipv4 --mark 45 --controller-only --control "$lab/$plan.sock" >"$lab/$plan-datapath.log" 2>&1 &
  daemon=$!
  sleep .3
  kill -0 "$daemon"
  "$controller" --set-name "$lab/$plan.sock" a.example.com ipv4 legacy "$lab/$plan.plan"
  "$controller" --watch "$lab/$plan.sock" >"$lab/$plan-watch.log" 2>&1 &
  watcher=$!
  sleep .1
  successes=0
  for attempt in 1 2 3 4 5; do
    client "$plan-$attempt" || true
    if verified "$plan-$attempt"; then
      successes=$((successes + 1))
    fi
  done
  kill "$watcher"; wait "$watcher" || true; watcher=
  kill "$daemon"; wait "$daemon" || true; daemon=
  applied=$(sed -nE 's/.*план применён ([^ ]+) .*план_ID=\[c1(, c1){15}\].*/\1/p' \
    "$lab/$plan-watch.log" | sort -u | wc -l)
  echo "$plan: $successes/5 HTTPS, APPLIED для Geneva в $applied потоках"
  if [ "$plan" = midpoint ]; then
    test "$successes" = 5
    test "$applied" = 5
  else
    test "$successes" = 0
    test "$applied" = 0
  fi
done
NETNS
