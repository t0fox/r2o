/* C-оракул: d2k_session_observe_tcp (session.c:2628-2631) — наблюдение без
 * применения плана. Печатаются публичные счётчики после каждого пакета. */
#include <stdio.h>
#include <string.h>

#include "d2k_session.h"

static uint8_t buffer[2048];

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

static size_t tcp_packet(uint8_t *o, uint8_t flags, uint32_t sequence,
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
    if (payload_len) memcpy(o + 40, payload, payload_len);
    return total;
}

static size_t udp_packet(uint8_t *o) {
    size_t total = 28;
    memset(o, 0, total);
    o[0] = 0x45;
    o[2] = 0; o[3] = (uint8_t)total;
    o[8] = 64;
    o[9] = 17;
    o[12] = 192; o[13] = 0; o[14] = 2; o[15] = 10;
    o[16] = 198; o[17] = 51; o[18] = 100; o[19] = 20;
    o[20] = 0xC3; o[21] = 0x50;
    o[22] = 0x01; o[23] = 0xBB;
    o[24] = 0; o[25] = 8;
    return total;
}

static void run(const char *name, d2k_session *session, const uint8_t *packet,
                size_t length) {
    uint32_t anchor = 0;
    (void)d2k_session_observe_tcp(session, packet, length, 1000);
    (void)d2k_session_stream_anchor(session, packet, length, &anchor);
    printf("%s flows=%zu hello_flows=%llu applied=%llu done=%llu anchor=%u\n",
           name, d2k_session_flows_tcp(session),
           (unsigned long long)d2k_session_tcp_hello_flows(session),
           (unsigned long long)d2k_session_applied(session),
           (unsigned long long)d2k_session_done(session), anchor);
}

int main(void) {
    d2k_session *session = d2k_session_new(64, 0);
    uint8_t plan_buffer[256];
    d2k_plan *plan = NULL;
    char error[200];
    size_t plan_length = fake_plan_bytes(plan_buffer);
    if (d2k_plan_load(plan_buffer, plan_length, &plan, error, sizeof error) == 0) {
        d2k_session_set_plan(session, plan);
    }

    size_t length = 10;
    memset(buffer, 0, length);
    run("A invalid", session, buffer, length);

    length = tcp_packet(buffer, 0x02, 1000, NULL, 0);
    run("B syn", session, buffer, length);

    length = tcp_packet(buffer, 0x18, 1001, CLIENT_HELLO, sizeof CLIENT_HELLO);
    run("C hello", session, buffer, length);

    size_t udp_length = udp_packet(buffer);
    run("D udp", session, buffer, udp_length);

    d2k_session_free(session);
    return 0;
}
