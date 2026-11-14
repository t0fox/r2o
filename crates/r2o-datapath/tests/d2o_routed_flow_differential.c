/* C-оракул: routed_flow (datapath/session.c:1593-1626) через
 * d2k_session_packet с меткой маршрутизатора. */
#include <stdio.h>
#include <string.h>

#include "d2k_session.h"

static uint8_t buffer[2048];

static void w16be(uint8_t *o, unsigned v) {
    o[0] = (uint8_t)(v >> 8);
    o[1] = (uint8_t)v;
}

static size_t tcp_packet(uint8_t *o, const uint8_t *src, const uint8_t *dst,
                         uint16_t sport, uint16_t dport, uint8_t flags,
                         uint32_t sequence, const uint8_t *payload,
                         size_t payload_len) {
    size_t total = 40 + payload_len;
    memset(o, 0, total);
    o[0] = 0x45;
    w16be(o + 2, (unsigned)total);
    o[8] = 64;
    o[9] = 6;
    memcpy(o + 12, src, 4);
    memcpy(o + 16, dst, 4);
    w16be(o + 20, sport);
    w16be(o + 22, dport);
    o[24] = (uint8_t)(sequence >> 24);
    o[25] = (uint8_t)(sequence >> 16);
    o[26] = (uint8_t)(sequence >> 8);
    o[27] = (uint8_t)sequence;
    o[32] = 0x50;
    o[33] = flags;
    if (payload_len) memcpy(o + 40, payload, payload_len);
    return total;
}

static size_t udp_packet(uint8_t *o, const uint8_t *src, const uint8_t *dst,
                         uint16_t sport, uint16_t dport, const uint8_t *payload,
                         size_t payload_len) {
    size_t total = 28 + payload_len;
    memset(o, 0, total);
    o[0] = 0x45;
    w16be(o + 2, (unsigned)total);
    o[8] = 64;
    o[9] = 17;
    memcpy(o + 12, src, 4);
    memcpy(o + 16, dst, 4);
    w16be(o + 20, sport);
    w16be(o + 22, dport);
    w16be(o + 24, (unsigned)(8 + payload_len));
    if (payload_len) memcpy(o + 28, payload, payload_len);
    return total;
}

static void run_ex(const char *name, d2k_session *session, const uint8_t *packet,
                   size_t length, uint64_t now, int compare_skip) {
    uint8_t result[4096];
    d2k_result r;
    memset(&r, 0, sizeof r);
    (void)d2k_session_packet(session, packet, length, now, result, sizeof result, &r);
    if (compare_skip) {
        printf("%s skip=%d first=%d mark=%u\n", name,
               r.skipped && r.skipped[0] ? 1 : 0, r.routed_first, r.routed_mark);
    } else {
        /* Пропуск ставит обычный путь (нет плана), не routed_flow. */
        printf("%s skip=- first=%d mark=%u\n", name, r.routed_first, r.routed_mark);
    }
}

static void run(const char *name, d2k_session *session, const uint8_t *packet,
                size_t length, uint64_t now) {
    run_ex(name, session, packet, length, now, 1);
}

int main(void) {
    static const uint8_t client[4] = {192, 0, 2, 10};
    static const uint8_t server[4] = {198, 51, 100, 20};
    d2k_session *s = d2k_session_new(64, 0);
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);

    size_t syn = tcp_packet(buffer, client, server, 40000, 443, 0x02, 1000,
                            NULL, 0);
    d2k_session_set_route_mark(s, 77);
    run("A mark-syn", s, buffer, syn, 1000);
    d2k_session_set_route_mark(s, 0);
    {
        size_t data = tcp_packet(buffer, client, server, 40000, 443, 0x18, 1001,
                                 (const uint8_t *)"x", 1);
        run("B follow", s, buffer, data, 2000);
    }
    size_t again = tcp_packet(buffer, client, server, 40000, 443, 0x02, 2000,
                              NULL, 0);
    run_ex("C new-syn", s, buffer, again, 3000, 0);
    d2k_session_set_route_mark(s, 77);
    run("K mark-after-new-syn", s, buffer, again, 3500);
    d2k_session_set_route_mark(s, 0);
    size_t other = tcp_packet(buffer, client, server, 40001, 443, 0x02, 3000,
                              NULL, 0);
    run_ex("D unknown", s, buffer, other, 4000, 0);
    d2k_session_set_route_mark(s, 77);
    run("L mark-unknown", s, buffer, other, 4500);
    d2k_session_set_route_mark(s, 0);
    size_t udp = udp_packet(buffer, client, server, 50000, 443,
                            (const uint8_t *)"q", 1);
    d2k_session_set_route_mark(s, 77);
    run("E mark-udp", s, buffer, udp, 5000);
    d2k_session_set_route_mark(s, 0);
    {
        size_t reverse = udp_packet(buffer, server, client, 443, 50000,
                                    (const uint8_t *)"r", 1);
        run("F udp-reverse", s, buffer, reverse, 6000);
    }
    d2k_session_set_route_mark(s, 77);
    run("J udp-again", s, buffer, udp, 7000);
    d2k_session_free(s);
    return 0;
}
