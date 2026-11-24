#!/opt/bin/sh
set -eu
LAB=${LAB:-/opt/lab}
PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
WAN4=198.18.0.2
WAN6=2001:db8:77:2::2
if [ -x /opt/bin/ip ]; then IP=/opt/bin/ip; else IP=$(command -v ip); fi
ip() { "$IP" "$@"; }
fixture() {
    family=$1
    subnet=$2
    ip "$family" addr add "$subnet:1::1/64" dev rlan nodad
    ip "$family" addr add "$subnet:2::1/64" dev rwan nodad
    ip netns exec r2olan "$IP" "$family" addr add "$subnet:1::2/64" dev client nodad
    ip netns exec r2owan "$IP" "$family" addr add "$subnet:2::2/64" dev origin nodad
    ip netns exec r2olan "$IP" "$family" route add default via "$subnet:1::1"
    ip netns exec r2owan "$IP" "$family" route add default via "$subnet:2::1"
}
start() {
    mkdir -p /var/run/netns
    ip link set lo up
    ip netns add r2olan
    ip netns add r2owan
    ip link add rlan type veth peer name client
    ip link add rwan type veth peer name origin
    ip link set client netns r2olan
    ip link set origin netns r2owan
    ip addr add 192.168.77.1/24 dev rlan
    ip addr add 198.18.0.1/24 dev rwan
    ip link set rlan up
    ip link set rwan up
    ip netns exec r2olan "$IP" link set client up
    ip netns exec r2owan "$IP" link set origin up
    ip netns exec r2olan "$IP" addr add 192.168.77.2/24 dev client
    ip netns exec r2owan "$IP" addr add 198.18.0.2/24 dev origin
    ip netns exec r2olan "$IP" route add default via 192.168.77.1
    ip netns exec r2owan "$IP" route add default via 198.18.0.1
    for guest_device in lo rlan rwan; do
        printf '0\n' >"/proc/sys/net/ipv6/conf/$guest_device/accept_dad"
    done
    fixture -6 2001:db8:77
    echo 1 >/proc/sys/net/ipv4/ip_forward
    echo 1 >/proc/sys/net/ipv6/conf/all/forwarding
    for address in "$WAN4" "$WAN6"; do
        "$IP" netns exec r2owan "$LAB/probe" server "$address" </dev/null >>/tmp/r2o-lab-origin.log 2>&1 &
    done
}
client() {
    for address in "$WAN4" "$WAN6"; do
        ip netns exec r2olan "$LAB/probe" client "$address"
    done
}
case "${1:-}" in
    start) start ;;
    client) client ;;
    *) exit 2 ;;
esac
