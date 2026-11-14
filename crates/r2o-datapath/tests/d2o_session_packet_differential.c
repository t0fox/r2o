/* C-оракул: изолированные ветви d2k_session_packet (session.c). */
#include <stdio.h>
#include <string.h>

#include "d2k_session.h"

static uint8_t buffer[2048];

static size_t ipv4_tcp(uint8_t *o, uint8_t flags, uint32_t sequence,
                       uint16_t source_port, uint16_t destination_port,
                       uint16_t fragment) {
    size_t total = 40;
    memset(o, 0, total);
    o[0] = 0x45;
    o[2] = 0;
    o[3] = (uint8_t)total;
    o[6] = (uint8_t)(fragment >> 8);
    o[7] = (uint8_t)fragment;
    o[8] = 64;
    o[9] = 6;
    o[12] = 192; o[13] = 0; o[14] = 2; o[15] = 10;
    o[16] = 198; o[17] = 51; o[18] = 100; o[19] = 20;
    o[20] = (uint8_t)(source_port >> 8);
    o[21] = (uint8_t)source_port;
    o[22] = (uint8_t)(destination_port >> 8);
    o[23] = (uint8_t)destination_port;
    o[24] = (uint8_t)(sequence >> 24);
    o[25] = (uint8_t)(sequence >> 16);
    o[26] = (uint8_t)(sequence >> 8);
    o[27] = (uint8_t)sequence;
    o[32] = 0x50;
    o[33] = flags;
    return total;
}

static size_t ipv6_tcp(uint8_t *o, uint8_t flags, uint32_t sequence) {
    size_t total = 60;
    memset(o, 0, total);
    o[0] = 0x60;
    o[4] = 0;
    o[5] = 20;
    o[6] = 6;
    o[7] = 64;
    o[8] = 0x20; o[9] = 0x01; o[10] = 0x0d; o[11] = 0xb8;
    o[23] = 0x01;
    o[24] = 0x20; o[25] = 0x01; o[26] = 0x0d; o[27] = 0xb8;
    o[39] = 0x02;
    o[40] = 0xC3; o[41] = 0x51;
    o[42] = 0x01; o[43] = 0xBB;
    o[44] = (uint8_t)(sequence >> 24);
    o[45] = (uint8_t)(sequence >> 16);
    o[46] = (uint8_t)(sequence >> 8);
    o[47] = (uint8_t)sequence;
    o[52] = 0x50;
    o[53] = flags;
    return total;
}

static void feed(d2k_session *session, const uint8_t *packet, size_t length,
                 uint32_t *anchor) {
    uint8_t result_buffer[512];
    d2k_result result;
    memset(&result, 0, sizeof result);
    (void)d2k_session_packet(session, packet, length, 1000,
                             result_buffer, sizeof result_buffer, &result);
    *anchor = 0;
    (void)d2k_session_stream_anchor(session, packet, length, anchor);
}

static void print_case(const char *name, d2k_session *session, uint32_t anchor) {
    printf("%s flows=%zu refusals=%llu anchor=%u\n", name,
           d2k_session_flows_tcp(session),
           (unsigned long long)d2k_session_refusals_tcp(session), anchor);
}

int main(void) {
    d2k_session *session = d2k_session_new(64, 0);
    size_t length;
    uint32_t anchor;

    length = 10;
    memset(buffer, 0, length);
    feed(session, buffer, length, &anchor);
    print_case("A invalid", session, anchor);

    length = ipv4_tcp(buffer, 0x02, 1000, 50000, 443, 0);
    feed(session, buffer, length, &anchor);
    print_case("B syn", session, anchor);

    length = ipv4_tcp(buffer, 0x02, 2000, 50000, 443, 0);
    feed(session, buffer, length, &anchor);
    print_case("C syn-repeat", session, anchor);

    length = ipv4_tcp(buffer, 0x18, 3000, 50001, 443, 0);
    feed(session, buffer, length, &anchor);
    print_case("D data-new", session, anchor);

    length = ipv6_tcp(buffer, 0x02, 4000);
    feed(session, buffer, length, &anchor);
    print_case("E ipv6-syn", session, anchor);

    length = ipv4_tcp(buffer, 0x02, 5000, 50002, 443, 1);
    feed(session, buffer, length, &anchor);
    print_case("F fragment", session, anchor);

    length = ipv4_tcp(buffer, 0x02, 6000, 50003, 443, 0);
    buffer[32] = 0x40; /* thl=4 — короче 20 */
    feed(session, buffer, length, &anchor);
    print_case("G bad-thl", session, anchor);

    length = ipv4_tcp(buffer, 0x12, 7000, 50004, 443, 0);
    feed(session, buffer, length, &anchor);
    print_case("H syn-ack", session, anchor);

    length = ipv4_tcp(buffer, 0x18, 3001, 50000, 443, 0);
    feed(session, buffer, length, &anchor);
    print_case("I data-existing", session, anchor);

    d2k_session_free(session);
    return 0;
}
