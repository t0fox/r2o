#!/opt/bin/sh
# Политики KN-1913 с тестовыми адресами. Сеть изолирована от хоста.
set -eu
PATH=/opt/bin:/opt/sbin:/bin:/sbin:/usr/bin:/usr/sbin
export PATH
LAB=${LAB:-/opt/lab}
export LAB
if [ "${1:-}" != isolated ]; then
    exec /opt/bin/busybox-bootstrap unshare -n /opt/bin/sh "$0" isolated
fi

root=/tmp/r2o-rpdb.$$
export R2O_DIR=$root R2O_RUN_DIR=$root/run R2O_META_STATE_DIR=$root
export R2O_PLATFORM=keenetic R2O_PLATFORM_RUNTIME=1 FW_BACKEND=iptables
export IPV6_ENABLED=1 PORTS=443 QUEUE_NUM=52692 QUEUE_NUM6=52693 MEASURE_MARK=47
dp=${R2O_RPDB_DATAPATH:-$LAB/bundle/builds/r2o-datapath-linux-mipsel}
probe=$LAB/probe
mkdir -p "$root/run" "$root/diagnostics" /var/run/netns
chmod 700 "$root" "$root/diagnostics"
touch "$root/diagnostics/enabled"
chmod 600 "$root/diagnostics/enabled"
child=''
cleanup() {
    status=$?
    if [ "$status" -ne 0 ] && [ -r "$root/dp.log" ]; then
        cat "$root/dp.log"
    fi
    for pid in $child; do kill "$pid" 2>/dev/null || true; done
    for pid in $child; do wait "$pid" 2>/dev/null || true; done
    ip netns del rpdb-lan 2>/dev/null || true
    ip netns del rpdb-wan 2>/dev/null || true
}
trap cleanup EXIT

ip link set lo up
ip netns add rpdb-lan
ip netns add rpdb-wan
for side in lan wan; do
    ip link add "r$side" type veth peer name "p$side"
    ip link set "p$side" netns "rpdb-$side"
    ip link set "r$side" up
    ip -n "rpdb-$side" link set "p$side" up
done
ip link add rvpn type veth peer name pvpn
ip link set pvpn up
ip link set rvpn up
ip addr add 203.0.113.1/29 dev rlan
ip addr add 198.51.100.1/29 dev rwan
ip -6 addr add 2001:db8:1::1/64 dev rlan nodad
ip -6 addr add 2001:db8:2::1/64 dev rwan nodad
ip -n rpdb-lan addr add 203.0.113.2/29 dev plan
ip -n rpdb-lan -6 addr add 2001:db8:1::2/64 dev plan nodad
ip -n rpdb-lan route add default via 203.0.113.1
ip -n rpdb-lan -6 route add default via 2001:db8:1::1
ip -n rpdb-wan addr add 198.51.100.2/29 dev pwan
ip -n rpdb-wan addr add 198.51.100.3/29 dev pwan
ip -n rpdb-wan addr add 192.0.2.4/32 dev pwan
ip -n rpdb-wan -6 addr add 2001:db8:2::2/64 dev pwan nodad
ip -n rpdb-wan -6 addr add 2001:db8:2::3/64 dev pwan nodad
ip -n rpdb-wan -6 addr add 2001:db8:3::4/128 dev pwan nodad
ip -n rpdb-wan route add default via 198.51.100.1
ip -n rpdb-wan -6 route add default via 2001:db8:2::1
ip route add default via 198.51.100.2
ip -6 route add default via 2001:db8:2::2
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1

for v in -4 -6; do
    ip "$v" rule add pref 9 fwmark 0x3001 lookup 301
    ip "$v" rule add pref 1150 fwmark 0xffffaaa lookup 4096
    ip "$v" rule add pref 1151 fwmark 0xffffaaa blackhole
    ip "$v" route add default dev rvpn table 301
done
ip -4 rule add pref 10 fwmark 0xffffa00 lookup main
for pair in '100 0xffffaab 4098' '102 0xffffaac 4099'; do
    set -- $pair
    ip rule add pref "$1" fwmark "$2" lookup "$3"
    ip rule add pref "$(($1 + 1))" fwmark "$2" blackhole
done
ip route add default via 198.51.100.2 table 16385
ip rule add pref 2152 from 198.51.100.1 lookup 16385
ip rule add pref 2160 from 10.9.9.3 lookup 16389
ip rule add pref 2162 from 172.16.0.3 lookup 16390
ip -6 route add default via 2001:db8:2::2 table 16385
ip -6 rule add pref 2152 oif rwan lookup 16385
ip -6 rule add pref 2166 from 2001:db8:2::1 lookup 16385

ip netns exec rpdb-wan "$probe" server 192.0.2.4 &
child="$child $!"
ip netns exec rpdb-wan "$probe" server 2001:db8:3::4 &
child="$child $!"
"$dp" --both --mode apply --controller-only --queue4 52692 --queue6 52693 \
    --control4 "$root/c4" --control6 "$root/c6" --mark 45 --probe-mark 46 >"$root/dp.log" 2>&1 &
child="$child $!"
sleep 2
"$dp" --platform up

snapshot() {
    for family in 4 6; do
        sample=$root/$1.$family.json
        cp "$root/run/datapath-health.$family.json" "$sample"
        printf '%s IPv%s %s\n' "$1" "$family" "$(cat "$sample")"
        previously=0
        if [ -n "${previous:-}" ]; then
            previously=$(counter "$root/$previous.$family.json" packets)
        fi
        [ "$(counter "$sample" packets)" -gt "$previously" ]
        for metric in checks_started pending_packets unavailable_packets different_packets equivalent_packets rpdb_observe_only_packets; do
            [ "$(counter "$sample" "$metric")" -eq 0 ]
        done
        [ "$(counter "$sample" receive_errors)" -eq 0 ]
        [ "$(counter "$sample" verdict_failures)" -eq 0 ]
    done
    previous=$1
}
counter() {
    sed -n "s/.*\"$2\":\([0-9][0-9]*\).*/\1/p" "$1"
}
traffic() {
    ip netns exec rpdb-lan "$probe" client 192.0.2.4
    ip netns exec rpdb-lan "$probe" client 2001:db8:3::4
}
run_case() {
    # Даём существующему worker обработать уведомления о смене маршрутов.
    sleep 2
    traffic
    sleep 1
    traffic
    sleep 6
    snapshot "$1"
}
run_case equivalent
# Немаркированное соединение самого роутера тоже проходит через NFQUEUE.
for address in 192.0.2.4 2001:db8:3::4; do
    "$probe" client "$address"
    sleep 1
    "$probe" client "$address"
done
sleep 6
snapshot router_local
ip rule add pref 8 fwmark 46 lookup 301
ip -6 rule add pref 8 fwmark 46 lookup 301
run_case vpn
ip rule del pref 8
ip -6 rule del pref 8
ip route add default via 198.51.100.3 table 4096
ip -6 route add default via 2001:db8:2::3 table 4096
ip rule add pref 8 fwmark 47 lookup 4096
ip -6 rule add pref 8 fwmark 47 lookup 4096
run_case second_gateway
ip rule del pref 8
ip -6 rule del pref 8
ip rule add pref 8 from 198.51.100.1 fwmark 46 lookup 4096
ip -6 rule add pref 8 from 2001:db8:1::2 fwmark 45 lookup 4096
run_case source_selected
ip rule del pref 8
ip -6 rule del pref 8
ip route add unreachable default table 302
ip -6 route add unreachable default table 302
ip rule add pref 8 fwmark 45 lookup 302
ip -6 rule add pref 8 fwmark 45 lookup 302
run_case unreachable
ip rule del pref 8
ip -6 rule del pref 8
# Only the unmarked reference path is unreachable. The marked raw socket
# still uses the test WAN. The route gate must use that same WAN.
ip rule add pref 8 fwmark 0/0xffffffff lookup 302
ip -6 rule add pref 8 fwmark 0/0xffffffff lookup 302
for dev in rlan rwan; do
    ip rule add pref 7 iif "$dev" lookup main
    ip -6 rule add pref 7 iif "$dev" lookup main
done
run_case raw_mark_egress
for family in 4 6; do
    baseline=$(counter "$root/source_selected.$family.json" other_egress_packets)
    before=$(counter "$root/unreachable.$family.json" other_egress_packets)
    after=$(counter "$root/raw_mark_egress.$family.json" other_egress_packets)
    [ "$before" -gt "$baseline" ]
    [ "$before" = "$after" ]
done
for dev in rlan rwan; do
    ip rule del pref 7 iif "$dev" lookup main
    ip -6 rule del pref 7 iif "$dev" lookup main
done
ip rule del pref 8
ip -6 rule del pref 8
ip rule add pref 7 iif rvpn lookup 301
ip -6 rule add pref 7 iif rvpn lookup 301
run_case unknown_context
ip rule del pref 7
ip -6 rule del pref 7
run_case restored
"$dp" --platform down
cat "$root/dp.log"
echo KEENETIC_EFFECTIVE_RPDB_PASS
