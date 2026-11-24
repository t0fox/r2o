#!/opt/bin/sh
# Повтор того же контролируемого TLS-сценария через штатный iptables backend.
set -eu
PATH=/opt/bin:/opt/sbin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH
LAB=${LAB:-/opt/lab}
export LAB
if [ "${1:-}" != isolated ]; then
    for module in xt_u32 xt_connmark xt_length; do
        grep -q "^$module " /proc/modules || /opt/bin/busybox insmod "$LAB/tls/$module.ko"
    done
    export OPENSSL_CONF=/dev/null LD_LIBRARY_PATH="/opt/lib:$LAB/tls/opt/lib"
    # В 4.9 этот параметр общий для гостя и виден только из исходного netns.
    timestamps=$(cat /proc/sys/net/ipv4/tcp_timestamps)
    trap 'printf "%s\n" "$timestamps" >/proc/sys/net/ipv4/tcp_timestamps' EXIT
    printf '0\n' >/proc/sys/net/ipv4/tcp_timestamps
    /opt/bin/busybox-bootstrap unshare -n /opt/bin/sh "$0" isolated
    exit
fi
ip() { /opt/bin/ip "$@"; }
origin() { /opt/bin/ip netns exec tlstestwan "$@"; }
client() { /opt/bin/ip netns exec tlstestlan "$@"; }
openssl=$LAB/tls/opt/bin/openssl
root=/tmp/r2o-keenetic-tls.$$
mkdir -p "$root/run" /var/run/netns
chmod 700 "$root"
export R2O_DIR=$root R2O_RUN_DIR=$root/run R2O_PLATFORM=keenetic FW_BACKEND=iptables QUEUE_NUM=52692
export IPV6_ENABLED=0 PORTS=443 R2O_PLATFORM_RUNTIME=1 R2O_SOFTWARE_PATH_ENDPOINTS='' DNS_DISCOVERY_ENDPOINTS=''
dp=$LAB/bundle/builds/r2o-datapath-linux-mipsel
controller=${dp%/*}/r2o-controller-linux-mipsel
[ -x "$dp" ] && [ -x "$controller" ]
server=''
daemon=''
watcher=''
cleanup() {
    for pid in "$watcher" "$daemon" "$server"; do
        [ -z "$pid" ] || { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
    done
    ip netns del tlstestlan 2>/dev/null || true
    ip netns del tlstestwan 2>/dev/null || true
}
trap cleanup EXIT
ip link set lo up
ip netns add tlstestlan
ip netns add tlstestwan
ip link add rlan type veth peer name lanp
ip link add rwan type veth peer name wanp
ip link set lanp netns tlstestlan
ip link set wanp netns tlstestwan
ip addr add 203.0.113.1/30 dev rlan
ip addr add 198.51.100.1/30 dev rwan
ip link set rlan up
ip link set rwan up
ip route add default dev rwan
origin /opt/bin/ip addr add 198.51.100.2/30 dev wanp
if [ -r "$LAB/tls/measure-discovery.sh" ]; then
    origin /opt/bin/ip addr add 198.51.100.6/32 dev wanp
    ip route add 198.51.100.6/32 dev rwan
fi
origin /opt/bin/ip link set wanp up
origin /opt/bin/ip route add 203.0.113.0/30 via 198.51.100.1
client /opt/bin/ip addr add 203.0.113.2/30 dev lanp
client /opt/bin/ip link set lanp up
client /opt/bin/ip route add default via 203.0.113.1
sysctl -qw net.ipv4.ip_forward=1
cp "$LAB/tls/cert.pem" "$LAB/tls/key.pem" "$root/"
tar -xzf "$LAB/tls/python-fixture.tar.gz" -C "$root"
cd "$root"
PYTHONHOME="$root/opt" LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$root/opt/lib" \
    /opt/bin/ip netns exec tlstestwan "$root/opt/bin/python3" "$root/peer.py" "$root" \
        </dev/null >server.log 2>&1 &
server=$!
attempt=0
until origin /opt/bin/awk '$2 ~ /:01BB$/ && $4 == "0A" {ready=1} END {exit !ready}' /proc/net/tcp; do
    attempt=$((attempt+1))
    if [ "$attempt" -ge 25 ] || ! kill -0 "$server"; then
        cat server.log
        exit 1
    fi
    sleep 1
done
request() {
    request_host=${2:-a.example.com}
    printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$request_host" |
        client /opt/bin/busybox-bootstrap timeout 6 "$openssl" s_client -connect "${3:-198.51.100.2}:443" \
        -servername "$request_host" -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -groups X25519 \
        -alpn h2 -no_ticket -CAfile cert.pem -verify_hostname "$request_host" -verify_return_error \
        -brief -ign_eof >"$1.log" 2>&1
}
application() {
    grep -q 'Verification: OK' "$1.log" && grep -q 'HTTP/1.1 200 OK' "$1.log" &&
        grep -Fxq 'verified LAN/WAN response' "$1.log"
}
request clear || true
application clear || { cat clear.log server.log; exit 1; }
origin /opt/sbin/iptables -t mangle -A OUTPUT -p tcp --sport 443 \
    -m u32 --u32 '0>>22&0x3c@20>>24=22' -j CONNMARK --set-mark 1
origin /opt/sbin/iptables -A INPUT -p tcp --dport 443 -m connmark --mark 0 \
    -m length --length 122:65535 -j DROP
request blocked || true
if grep -q 'CONNECTION ESTABLISHED' blocked.log; then echo 'Контрольная блокировка не сработала'; exit 1; fi
launch() {
    "$dp" --mode apply --queue 52692 --family ipv4 --mark 45 --probe-mark 46 --controller-only \
        --control "$root/dp.sock" </dev/null >datapath.log 2>&1 &
    daemon=$!
    sleep 1
    "$dp" --platform up
    "$controller" --serve "$root/dp.sock" "$root/catalog.json" --discover --mark 46 --measure-mark 46 \
        --live "$root/live.json" --no-diagnostics </dev/null >controller.log 2>&1 &
    watcher=$!
    sleep 1
}
stop() {
    "$dp" --platform down
    kill "$watcher" "$daemon"
    wait "$watcher" || true
    wait "$daemon" || true
    watcher=''
    daemon=''
}
uptime_s() { cut -d. -f1 /proc/uptime; }
launch
if [ -r "$LAB/tls/measure-discovery.sh" ]; then
    . "$LAB/tls/measure-discovery.sh"
    measure_discovery cold a.example.com 198.51.100.2 "$root" "$root/controller.log" "$watcher" "$daemon" || { tail -60 controller.log datapath.log; exit 1; }
    measure_discovery warm b.example.net 198.51.100.6 "$root" "$root/controller.log" "$watcher" "$daemon" || { tail -60 controller.log datapath.log; exit 1; }
    echo KEENETIC_DISCOVERY_MEASURE_PASS
    stop
    exit 0
fi
started=$(uptime_s)
request trigger || true
attempt=0
until [ -s catalog.json ]; do
    kill -0 "$watcher" "$daemon"
    attempt=$((attempt+1))
    [ "$attempt" -lt 48 ] || { tail -40 controller.log datapath.log; exit 1; }
    sleep 2
done
grep -q 'a.example.com' catalog.json
request discovered || true
application discovered || { cat discovered.log; tail -40 controller.log; exit 1; }
echo "KEENETIC_TLS_DISCOVERY_PASS elapsed_s=$(($(uptime_s)-started))"
stop
started=$(uptime_s)
launch
request repeated || true
application repeated || { cat repeated.log; exit 1; }
echo "KEENETIC_TLS_REUSE_PASS elapsed_s=$(($(uptime_s)-started))"
stop
