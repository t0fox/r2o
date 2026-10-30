#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "test_nat_stub.h"
#include "d2k_session.h"

static size_t udp_packet_at(uint8_t *out, const uint8_t source[4],
                            const uint8_t destination[4], uint16_t sport,
                            uint16_t dport, const uint8_t *payload,
                            size_t payload_len) {
    size_t total = 28 + payload_len;
    memset(out, 0, total);
    out[0] = 0x45;
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[8] = 64;
    out[9] = 17;
    memcpy(out + 12, source, 4);
    memcpy(out + 16, destination, 4);
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

static size_t udp_packet(uint8_t *out, uint16_t sport, uint16_t dport,
                         const uint8_t *payload, size_t payload_len) {
    static const uint8_t client[4] = {192, 168, 1, 67};
    static const uint8_t server[4] = {1, 2, 3, 4};
    return udp_packet_at(out, client, server, sport, dport, payload, payload_len);
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

static void rtp(uint8_t payload[16], uint32_t ssrc, uint16_t sequence) {
    memset(payload, 0, 16);
    payload[0] = 0x80;
    payload[1] = 0x78;
    payload[2] = (uint8_t)(sequence >> 8);
    payload[3] = (uint8_t)sequence;
    payload[8] = (uint8_t)(ssrc >> 24);
    payload[9] = (uint8_t)(ssrc >> 16);
    payload[10] = (uint8_t)(ssrc >> 8);
    payload[11] = (uint8_t)ssrc;
}

static void send_packet(d2k_session *session, uint8_t *packet, size_t n,
                        uint64_t now_ns, uint8_t hook) {
    uint8_t output[2048];
    d2k_result result;
    d2k_session_set_hook(session, hook);
    d2k_session_packet(session, packet, n, now_ns, output, sizeof output, &result);
}

int main(void) {
    D2K_TEST_NAT_NO_TABLE();
    d2k_session *session = d2k_session_new(64, 32);
    if (!session) {
        return 2;
    }
    d2k_session_set_udp_reverse_hook(session, 1);

    uint8_t packet[128], payload[74], media[16];
    discovery(payload, 1);
    size_t n = udp_packet(packet, 50000, 50004, payload, sizeof payload);
    send_packet(session, packet, n, 1000000000ull, D2K_HOOK_POSTROUTING);
    n = udp_packet(packet, 50000, 50004, (const uint8_t *)"media", 5);
    send_packet(session, packet, n, 1100000000ull, D2K_HOOK_POSTROUTING);
    size_t first = d2k_session_sweep(session, 3100000001ull);

    discovery(payload, 2);
    n = udp_packet(packet, 50000, 50004, payload, sizeof payload);
    send_packet(session, packet, n, 4000000000ull, D2K_HOOK_POSTROUTING);
    n = udp_packet(packet, 50000, 50004, (const uint8_t *)"media", 5);
    send_packet(session, packet, n, 4100000000ull, D2K_HOOK_POSTROUTING);
    size_t reconnect = d2k_session_sweep(session, 6100000001ull);

    printf("ssrc_reconnect first=%zu reconnect=%zu suspects=%llu\n", first, reconnect,
           (unsigned long long)d2k_session_suspects(session));

    static const uint8_t client[4] = {192, 168, 1, 67};
    static const uint8_t new_server[4] = {1, 2, 3, 5};
    discovery(payload, 3);
    n = udp_packet_at(packet, client, new_server, 50000, 50005,
                      payload, sizeof payload);
    send_packet(session, packet, n, 7000000000ull, D2K_HOOK_POSTROUTING);
    n = udp_packet_at(packet, client, new_server, 50000, 50005,
                      (const uint8_t *)"media", 5);
    send_packet(session, packet, n, 7100000000ull, D2K_HOOK_POSTROUTING);
    size_t endpoint_change = d2k_session_sweep(session, 9100000001ull);
    printf("endpoint_change=%zu\n", endpoint_change);
    d2k_session_free(session);

    session = d2k_session_new(64, 32);
    if (!session) {
        return 2;
    }
    d2k_session_set_udp_reverse_hook(session, 1);
    discovery(payload, 4);
    n = udp_packet(packet, 50000, 50004, payload, sizeof payload);
    send_packet(session, packet, n, 1000000000ull, D2K_HOOK_POSTROUTING);
    size_t long_events = 0;
    uint64_t last_packet_ns = 1000000000ull;
    for (uint64_t interval = 1; interval <= 20; interval++) {
        uint64_t now_ns = 1000000000ull + interval * 30000000000ull;
        rtp(media, 4, (uint16_t)interval);
        n = udp_packet(packet, 50000, 50004, media, sizeof media);
        send_packet(session, packet, n, now_ns, D2K_HOOK_POSTROUTING);
        rtp(media, 5, (uint16_t)interval);
        n = udp_packet_at(packet, (const uint8_t[]){1, 2, 3, 4}, client,
                          50004, 50000, media, sizeof media);
        send_packet(session, packet, n, now_ns + 1000000ull, D2K_HOOK_FORWARD);
        last_packet_ns = now_ns + 1000000ull;
        long_events += d2k_session_sweep(session, now_ns + 2000000ull);
        if (d2k_session_expire(session, now_ns + 2000000ull,
                               120000000000ull) != 0) {
            fprintf(stderr, "long RTC flow expired while packets were active\n");
            return 1;
        }
    }
    size_t before_idle = d2k_session_expire(session,
        last_packet_ns + 119000000000ull, 120000000000ull);
    size_t at_idle = d2k_session_expire(session,
        last_packet_ns + 120000000000ull, 120000000000ull);
    if (long_events != 0 || before_idle != 0 || at_idle != 1 ||
        d2k_session_flows_udp(session) != 0) {
        fprintf(stderr, "long RTC lifecycle events=%zu before=%zu at=%zu flows=%zu\n",
                long_events, before_idle, at_idle, d2k_session_flows_udp(session));
        return 1;
    }
    printf("long_session=active600 events=%zu expire=%zu\n", long_events, at_idle);
    d2k_session_free(session);
    return 0;
}
