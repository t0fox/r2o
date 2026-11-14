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


static void wr16be(uint8_t *o, unsigned v) {
    o[0] = (uint8_t)(v >> 8);
    o[1] = (uint8_t)v;
}

static size_t put_tlv(uint8_t *o, size_t off, uint16_t kind,
                      const uint8_t *value, size_t length) {
    wr16be(o + off, kind);
    wr16be(o + off + 2, (unsigned)length);
    memcpy(o + off + 4, value, length);
    return off + 4 + length;
}

static size_t fake_plan_bytes(uint8_t *o) {
    static const uint8_t transport[] = {6, 1};
    static const uint8_t fake[] = {0, 1, 'F', 'A', 'K', 'E'};
    static const uint8_t params[] = {0, 1, 0, 0, 1, 0, 0, 0, 0, 0};
    memcpy(o, "D2KP", 4);
    wr16be(o + 4, 1);
    wr16be(o + 6, 0);
    wr16be(o + 8, 0);
    wr16be(o + 10, 3);
    size_t off = 12;
    off = put_tlv(o, off, 0x0002, transport, sizeof transport);
    off = put_tlv(o, off, 0x0010, fake, sizeof fake);
    off = put_tlv(o, off, 0x0101, params, sizeof params);
    return off;
}

static const uint8_t CLIENT_HELLO[] = {
    0x16, 0x03, 0x03, 0, 47, 1, 0, 0, 43, 0x03, 0x03,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 2, 0x13, 1, 1, 0, 0, 0
};

static size_t packet_with_payload(uint8_t *o, uint8_t flags, uint32_t sequence,
                                  const uint8_t *payload, size_t payload_len) {
    size_t total = 40 + payload_len;
    memset(o, 0, total);
    o[0] = 0x45;
    o[2] = (uint8_t)(total >> 8);
    o[3] = (uint8_t)total;
    o[8] = 64;
    o[9] = 6;
    o[12] = 192; o[13] = 0; o[14] = 2; o[15] = 10;
    o[16] = 198; o[17] = 51; o[18] = 100; o[19] = 20;
    o[20] = 0xC3; o[21] = 0x50;
    o[22] = 0x01; o[23] = 0xBB;
    o[24] = (uint8_t)(sequence >> 24);
    o[25] = (uint8_t)(sequence >> 16);
    o[26] = (uint8_t)(sequence >> 8);
    o[27] = (uint8_t)sequence;
    o[28] = 0; o[29] = 0; o[30] = 0x03; o[31] = 0x84;
    o[32] = 0x50;
    o[33] = flags;
    memcpy(o + 40, payload, payload_len);
    return total;
}

static void plan_case(const char *name, d2k_session *session, const uint8_t *packet,
                      size_t length) {
    static uint8_t out[4096];
    d2k_result result;
    memset(&result, 0, sizeof result);
    (void)d2k_session_packet(session, packet, length, 2000, out, sizeof out, &result);
    printf("%s applied=%d verdict=%d n=%zu lens=", name, result.applied ? 1 : 0,
           (int)result.verdict, result.n_out);
    for (size_t i = 0; i < result.n_out; i++) {
        printf("%s%zu", i ? "," : "", result.out[i].len);
    }
    printf("\n");
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

    d2k_session *planned = d2k_session_new(64, 0);
    uint8_t plan_buffer[256];
    d2k_plan *plan = NULL;
    char error[200];
    size_t plan_length = fake_plan_bytes(plan_buffer);
    if (plan_length && d2k_plan_load(plan_buffer, plan_length, &plan, error, sizeof error) == 0) {
        d2k_session_set_plan(planned, plan);
        length = packet_with_payload(buffer, 0x02, 1000, NULL, 0);
        plan_case("J plan-syn", planned, buffer, length);
        length = packet_with_payload(buffer, 0x18, 1001, CLIENT_HELLO,
                                     sizeof CLIENT_HELLO);
        plan_case("K plan-hello", planned, buffer, length);
        d2k_session_free(planned);
    } else {
        printf("J plan-syn load-error=%s\n", error);
        printf("K plan-hello load-error=%s\n", error);
        d2k_session_free(planned);
    }
    return 0;
}
