#!/usr/bin/env bash
set -euo pipefail

r2o_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
r2o_workspace_parent=$(dirname "$(dirname "$(dirname "$r2o_root")")")
r2o_donor_datapath=${R2O_DONOR_DATAPATH:-$r2o_workspace_parent/d2o/datapath}
r2o_tmp=$(mktemp -d)
trap 'rm -rf "$r2o_tmp"' EXIT HUP INT TERM

if [ ! -d "$r2o_donor_datapath" ]; then
    printf 'Каталог C-эталона не найден: %s\n' "$r2o_donor_datapath" >&2
    exit 2
fi

make -C "$r2o_donor_datapath" test-quic-session CC=clang-18

cat >"$r2o_tmp/quic_stun_watch.c" <<EOF
#define main r2o_donor_quic_test_main
#include "$r2o_donor_datapath/test_quic_session.c"
#undef main

static int r2o_check_control_flow(uint16_t client_port) {
    const uint64_t second = 1000000000ull;
    d2k_session *session = stall_flow(client_port, 8);
    if (!session) return 1;
    ct_write(client_port, 12, 14, 1);
    ct_queries = 0;
    d2k_session_sweep(session, 3 * second);
    int failed = ct_queries != 1 || d2k_session_suspects(session) != 0;
    printf("C control: queries=%u suspects=%zu\n", ct_queries,
           d2k_session_suspects(session));
    d2k_session_free(session);
    return failed;
}

static int r2o_check_marked_flow(uint16_t client_port, int discovery) {
    const uint64_t second = 1000000000ull;
    d2k_session *session = stall_flow(client_port, 8);
    uint8_t payload[74] = {0}, packet[1300], reverse[1300], buffer[4096];
    d2k_result result;
    if (!session) return 1;
    if (discovery) {
        payload[1] = 1;
        payload[3] = 70;
        payload[4] = 1;
        payload[5] = 2;
        payload[6] = 3;
        payload[7] = 4;
    } else {
        payload[1] = 1;
        payload[4] = 0x21;
        payload[5] = 0x12;
        payload[6] = 0xa4;
        payload[7] = 0x42;
    }
    size_t length = discovery
        ? build_udp_pkt(packet, client_port, 443, payload, sizeof payload)
        : build_udp_pkt(packet, client_port, 443, payload, 20);
    d2k_session_packet(session, packet, length, 1500000000ull,
                       buffer, sizeof buffer, &result);
    const uint8_t reply_payload[1] = {0x40};
    length = build_udp_rev_pkt(reverse, client_port, reply_payload,
                               sizeof reply_payload);
    d2k_session_packet(session, reverse, length, 1700000000ull,
                       buffer, sizeof buffer, &result);
    ct_write(client_port, 12, 14, 1);
    ct_queries = 0;
    d2k_session_sweep(session, 3 * second);
    int failed = ct_queries != 0 || d2k_session_suspects(session) != 0;
    printf("C %s: queries=%u suspects=%zu\n",
           discovery ? "Discord Discovery" : "STUN", ct_queries,
           d2k_session_suspects(session));
    d2k_session_free(session);
    return failed;
}

int main(void) {
    int failed = r2o_check_control_flow(50430);
    failed |= r2o_check_marked_flow(50431, 0);
    failed |= r2o_check_marked_flow(50432, 1);
    return failed ? 1 : 0;
}
EOF

r2o_link_objects=(
    "$r2o_donor_datapath/session.o"
    "$r2o_donor_datapath/http80.o"
    "$r2o_donor_datapath/hold.o"
    "$r2o_donor_datapath/capture.o"
    "$r2o_donor_datapath/nat.o"
    "$r2o_donor_datapath/ctq.o"
    "$r2o_donor_datapath/nl.o"
    "$r2o_donor_datapath/track.o"
    "$r2o_donor_datapath/tls.o"
    "$r2o_donor_datapath/wire.o"
    "$r2o_donor_datapath/wire_udp.o"
    "$r2o_donor_datapath/journal.o"
    "$r2o_donor_datapath/plans.o"
    "$r2o_donor_datapath/plan_parse.o"
    "$r2o_donor_datapath/plan_apply.o"
    "$r2o_donor_datapath/core_quic.o"
    "$r2o_donor_datapath/core_quicwire.o"
    "$r2o_donor_datapath/core_quicsnap.o"
    "$r2o_donor_datapath/core_crypto.o"
    "$r2o_donor_datapath/core_ipfrag.o"
    "$r2o_donor_datapath/core_httpup_logic.o"
    "$r2o_donor_datapath/core_quichello.o"
    "$r2o_donor_datapath/core_hello.o"
    "$r2o_donor_datapath/core_tls13core.o"
    "$r2o_donor_datapath/core_x25519.o"
)

clang-18 -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$r2o_donor_datapath/include" \
    -I"$r2o_donor_datapath/../core/include" \
    -DD2K_RELEASE_ID='"diff"' \
    "$r2o_tmp/quic_stun_watch.c" "${r2o_link_objects[@]}" \
    -o "$r2o_tmp/quic_stun_watch"

"$r2o_tmp/quic_stun_watch"

cd "$r2o_root"
cargo +1.98.0 test -p r2o-datapath --lib \
    quic_зависание_исключает_stun_и_discord_discovery_из_одного_потока \
    --locked --offline -- --nocapture

printf 'ПРОЙДЕНО: C и Rust исключают STUN и Discord Discovery из QUIC conntrack-stall.\n'
