/* C-оракул: ранние гейты d2k_session_hold_candidate (session.c:2794-2924). */
#include <stdio.h>
#include <string.h>

#include "d2k_session.h"

static uint8_t packet_buffer[2048];

static size_t tcp_packet(uint8_t *o, uint8_t flags, uint32_t sequence,
                         uint32_t acknowledgment, const uint8_t *payload,
                         size_t payload_len) {
    size_t total = 40 + payload_len;
    memset(o, 0, total);
    o[0] = 0x45;
    o[2] = (uint8_t)(total >> 8);
    o[3] = (uint8_t)total;
    o[8] = 64;
    o[9] = 6;
    o[12] = 192; o[13] = 0; o[14] = 2; o[15] = 10;
    o[16] = 198; o[17] = 51; o[18] = 100; o[19] = 20;
    o[20] = 0xC3; o[21] = 0x50; /* 50000 */
    o[22] = 0x01; o[23] = 0xBB; /* 443 */
    o[24] = (uint8_t)(sequence >> 24);
    o[25] = (uint8_t)(sequence >> 16);
    o[26] = (uint8_t)(sequence >> 8);
    o[27] = (uint8_t)sequence;
    o[28] = (uint8_t)(acknowledgment >> 24);
    o[29] = (uint8_t)(acknowledgment >> 16);
    o[30] = (uint8_t)(acknowledgment >> 8);
    o[31] = (uint8_t)acknowledgment;
    o[32] = 0x50;
    o[33] = flags;
    if (payload_len) memcpy(o + 40, payload, payload_len);
    return total;
}

static void feed_syn(d2k_session *session) {
    uint8_t result_buffer[512];
    d2k_result result;
    memset(&result, 0, sizeof result);
    size_t length = tcp_packet(packet_buffer, 0x02, 1000, 3000, NULL, 0);
    (void)d2k_session_packet(session, packet_buffer, length, 1000,
                             result_buffer, sizeof result_buffer, &result);
}

static d2k_session *fresh(int with_syn) {
    d2k_session *session = d2k_session_new(64, 32);
    d2k_session_set_hook(session, D2K_HOOK_POSTROUTING);
    if (with_syn) feed_syn(session);
    return session;
}

static void print_case(const char *name, int with_syn, uint8_t flags,
                       uint32_t sequence, const uint8_t *payload,
                       size_t payload_len) {
    d2k_session *session = fresh(with_syn);
    size_t length = tcp_packet(packet_buffer, flags, sequence, 3000,
                               payload, payload_len);
    printf("%s candidate=%d\n", name,
           d2k_session_hold_candidate(session, packet_buffer, length));
    d2k_session_free(session);
}

int main(void) {
    static const uint8_t tls_head[] = {22, 3, 3, 0, 16, 1, 0, 0, 12};
    static const uint8_t complete[] = {22, 3, 3, 0, 1, 0};
    static const uint8_t get[] = "GET / HTTP/1.1\r\nHost: h\r\n\r\n";

    print_case("A no_syn", 0, 0x18, 1001, tls_head, sizeof tls_head);
    print_case("B no_ack", 1, 0x08, 1001, tls_head, sizeof tls_head);
    print_case("C fin", 1, 0x11, 1001, tls_head, sizeof tls_head);
    print_case("D empty", 1, 0x18, 1001, NULL, 0);
    print_case("E far_tail", 1, 0x18, 1001 + 16384, tls_head, sizeof tls_head);
    print_case("F not_tls", 1, 0x18, 1001, get, sizeof get - 1);
    print_case("G complete", 1, 0x18, 1001, complete, sizeof complete);
    return 0;
}
