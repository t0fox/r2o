/* C-оракул: TCP-ветка «плана для этой цели нет» в session_packet.
 *
 * Сессия без планов, первый ClientHello с SNI: C пишет PLAN_REFUSED с
 * code NONE и текстом причины, а `d2k_session_client_shape` отдаёт
 * наблюдённую форму (LEGACY_NO_TS при пустых TCP-опциях). Повтор hello и
 * данные отказа не повторяют; новый поток даёт второй отказ.
 */
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
                         uint32_t sequence, uint32_t acknowledgment,
                         const uint8_t *payload, size_t payload_len) {
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
    o[28] = (uint8_t)(acknowledgment >> 24);
    o[29] = (uint8_t)(acknowledgment >> 16);
    o[30] = (uint8_t)(acknowledgment >> 8);
    o[31] = (uint8_t)acknowledgment;
    o[32] = 0x50;
    o[33] = flags;
    if (payload_len) memcpy(o + 40, payload, payload_len);
    return total;
}

/* ClientHello с SNI, без supported_versions и без TCP-опций. */
static size_t client_hello(uint8_t *o, size_t cap) {
    static const uint8_t host[] = "example.test";
    uint8_t extensions[512];
    size_t n = 0;
    size_t list_len = 1 + 2 + sizeof host - 1;
    size_t ext_len = 2 + list_len;
    extensions[n++] = 0; extensions[n++] = 0;
    w16be(extensions + n, (unsigned)ext_len); n += 2;
    w16be(extensions + n, (unsigned)list_len); n += 2;
    extensions[n++] = 0;
    w16be(extensions + n, (unsigned)(sizeof host - 1)); n += 2;
    memcpy(extensions + n, host, sizeof host - 1); n += sizeof host - 1;

    uint8_t body[512];
    size_t b = 0;
    body[b++] = 0x03; body[b++] = 0x03;
    for (int i = 0; i < 32; i++) body[b++] = 0;
    body[b++] = 0;
    body[b++] = 0; body[b++] = 2; body[b++] = 0x13; body[b++] = 1;
    body[b++] = 1; body[b++] = 0;
    w16be(body + b, (unsigned)n); b += 2;
    memcpy(body + b, extensions, n); b += n;

    uint8_t handshake[512];
    handshake[0] = 1;
    handshake[1] = (uint8_t)(b >> 16);
    handshake[2] = (uint8_t)(b >> 8);
    handshake[3] = (uint8_t)b;
    memcpy(handshake + 4, body, b);
    size_t handshake_len = 4 + b;

    if (handshake_len + 5 > cap) return 0;
    o[0] = 0x16; o[1] = 0x03; o[2] = 0x03;
    w16be(o + 3, (unsigned)handshake_len);
    memcpy(o + 5, handshake, handshake_len);
    return 5 + handshake_len;
}

static void send_packet(d2k_session *s, size_t length, uint64_t now) {
    uint8_t result[4096];
    d2k_result r;
    memset(&r, 0, sizeof r);
    (void)d2k_session_packet(s, buffer, length, now, result, sizeof result, &r);
}

static void print_hex(const uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
}

static size_t refused_count(const d2k_journal *j, const d2k_jrn_entry **last) {
    size_t count = 0;
    *last = NULL;
    for (size_t i = 0; i < d2k_journal_count(j); i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e->kind == D2K_JRN_PLAN_REFUSED) {
            count++;
            *last = e;
        }
    }
    return count;
}

static void report(const char *name, d2k_session *s, size_t before) {
    const d2k_journal *j = d2k_session_journal(s);
    const d2k_jrn_entry *e = NULL;
    size_t after = refused_count(j, &e);
    printf("%s refusals=%zu", name, after);
    if (after > before && e) {
        printf(" code=%u plan=", e->code);
        print_hex(e->plan_id, D2K_PLAN_ID_LEN);
        printf(" trial=");
        print_hex(e->trial_id, D2K_TRIAL_ID_LEN);
        printf(" note=%s shape=%u", e->note ? e->note : "-",
               d2k_session_client_shape(s, &e->key));
    }
    printf(" new=%d\n", after > before ? 1 : 0);
}

static void handshake(d2k_session *s, const uint8_t *src, const uint8_t *dst,
                      uint16_t sport, uint32_t syn_seq, uint32_t server_seq,
                      const uint8_t *hello, size_t hello_len, uint64_t now) {
    size_t length = tcp_packet(buffer, src, dst, sport, 443, 0x02, syn_seq, 0,
                               NULL, 0);
    send_packet(s, length, now);
    length = tcp_packet(buffer, dst, src, 443, sport, 0x12, server_seq,
                        syn_seq + 1, NULL, 0);
    send_packet(s, length, now + 50000000ull);
    length = tcp_packet(buffer, src, dst, sport, 443, 0x18, syn_seq + 1,
                        server_seq, hello, hello_len);
    send_packet(s, length, now + 100000000ull);
}

int main(void) {
    static const uint8_t client[4] = {192, 0, 2, 10};
    static const uint8_t server[4] = {198, 51, 100, 20};
    uint8_t hello[512];
    size_t hello_len = client_hello(hello, sizeof hello);
    d2k_session *s = d2k_session_new(64, 16);
    if (!s) return 2;
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);

    handshake(s, client, server, 41000, 700, 900, hello, hello_len, 1000);
    report("T1 first", s, 0);

    size_t length = tcp_packet(buffer, client, server, 41000, 443, 0x18, 701,
                               900, hello, hello_len);
    send_packet(s, length, 150001000ull);
    report("T2 repeat", s, 1);

    length = tcp_packet(buffer, client, server, 41000, 443, 0x18, 702, 900,
                        (const uint8_t *)"x", 1);
    send_packet(s, length, 160001000ull);
    report("T3 data", s, 1);

    handshake(s, client, server, 41001, 1700, 1900, hello, hello_len,
              200001000ull);
    report("T4 new-flow", s, 1);

    d2k_session_free(s);
    return 0;
}
