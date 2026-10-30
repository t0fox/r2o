#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "test_nat_stub.h"
#include "d2k_session.h"

static size_t udp_packet(uint8_t *out, uint16_t sport, uint16_t dport,
                         const uint8_t *payload, size_t payload_len) {
    size_t total = 28 + payload_len;
    memset(out, 0, total);
    out[0] = 0x45;
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[8] = 64;
    out[9] = 17;
    memcpy(out + 12, "\xc0\xa8\x01\x43", 4);
    memcpy(out + 16, "\x01\x02\x03\x04", 4);
    out[20] = (uint8_t)(sport >> 8);
    out[21] = (uint8_t)sport;
    out[22] = (uint8_t)(dport >> 8);
    out[23] = (uint8_t)dport;
    out[24] = (uint8_t)((payload_len + 8) >> 8);
    out[25] = (uint8_t)(payload_len + 8);
    if (payload_len) {
        memcpy(out + 28, payload, payload_len);
    }
    return total;
}

static void discovery(uint8_t payload[74], uint32_t ssrc) {
    memset(payload, 0, 74);
    payload[1] = 1;
    payload[3] = 70;
    payload[4] = (uint8_t)(ssrc >> 24);
    payload[5] = (uint8_t)(ssrc >> 16);
    payload[6] = (uint8_t)(ssrc >> 8);
    payload[7] = (uint8_t)ssrc;
}

static void send_packet(d2k_session *session, uint8_t *packet, size_t n,
                        uint64_t now_ns) {
    uint8_t output[2048];
    d2k_result result;
    d2k_session_set_hook(session, D2K_HOOK_POSTROUTING);
    d2k_session_packet(session, packet, n, now_ns, output, sizeof output, &result);
}

int main(void) {
    D2K_TEST_NAT_NO_TABLE();
    d2k_session *session = d2k_session_new(64, 32);
    if (!session) {
        return 2;
    }
    d2k_session_set_udp_reverse_hook(session, 1);

    uint8_t packet[128], payload[74];
    discovery(payload, 1);
    size_t n = udp_packet(packet, 50000, 50004, payload, sizeof payload);
    send_packet(session, packet, n, 1000000000ull);
    n = udp_packet(packet, 50000, 50004, (const uint8_t *)"media", 5);
    send_packet(session, packet, n, 1100000000ull);
    size_t first = d2k_session_sweep(session, 3100000001ull);

    discovery(payload, 2);
    n = udp_packet(packet, 50000, 50004, payload, sizeof payload);
    send_packet(session, packet, n, 4000000000ull);
    n = udp_packet(packet, 50000, 50004, (const uint8_t *)"media", 5);
    send_packet(session, packet, n, 4100000000ull);
    size_t reconnect = d2k_session_sweep(session, 6100000001ull);

    printf("first=%zu reconnect=%zu suspects=%llu\n", first, reconnect,
           (unsigned long long)d2k_session_suspects(session));
    d2k_session_free(session);
    return 0;
}
