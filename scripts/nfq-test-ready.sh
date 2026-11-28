# Shared setup for the live NFQUEUE tests. Run the probe in the queue's netns.
r2o_wait_nfq() (
    ns=$1
    pid=$2
    queue=$3
    control=$4
    log=$5
    case "${6:-4}" in
        4) family=ip; address=127.0.0.1 ;;
        6) family=ip6; address=::1 ;;
        *) exit 2 ;;
    esac
    ip netns exec "$ns" nft add table "$family" r2o_ready
    ip netns exec "$ns" nft add chain "$family" r2o_ready output \
        '{ type filter hook output priority -5; policy accept; }'
    # No bypass: a matching datagram must receive a verdict from the datapath.
    ip netns exec "$ns" nft add rule "$family" r2o_ready output \
        "$family" daddr "$address" udp dport 46991 counter queue num "$queue"

    if ! ip netns exec "$ns" python3 - "$pid" "$control" "$address" >"$log" 2>&1 <<'PY'
import os
import socket
import stat
import sys
import time

pid, control, address = int(sys.argv[1]), sys.argv[2], sys.argv[3]
deadline = time.monotonic() + 5
# A delayed verdict still proves this run's queue path. Reusing the random
# challenge keeps a slow runner from perpetually reading the previous reply.
challenge = os.urandom(16)
with socket.socket(socket.AF_INET6 if address == '::1' else socket.AF_INET, socket.SOCK_DGRAM) as probe:
    probe.bind((address, 46991))
    probe.settimeout(0.1)
    while time.monotonic() < deadline:
        os.kill(pid, 0)
        if not os.path.exists(control) or not stat.S_ISSOCK(os.stat(control).st_mode):
            time.sleep(0.05)
            continue
        probe.sendto(challenge, probe.getsockname())
        try:
            if probe.recv(16) == challenge:
                print('NFQUEUE: probe traversed a queue rule without bypass and received a verdict')
                break
        except socket.timeout:
            pass
    else:
        sys.exit('NFQUEUE: no verdict on readiness traffic within 5 seconds')
PY
    then
        ip netns exec "$ns" nft list table "$family" r2o_ready >>"$log" 2>&1
        ip netns exec "$ns" sh -c '
            path=/proc/net/netfilter/nfnetlink_queue
            if [ -r "$path" ]; then cat "$path"; else echo "$path unavailable"; fi
        ' >>"$log" 2>&1
        cat "$log" >&2
        exit 1
    fi

    ip netns exec "$ns" nft delete table "$family" r2o_ready
)
