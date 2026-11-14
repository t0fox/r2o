/* C-оракул: ct_tcp_flow (datapath/session.c:3279-3328) через
 * d2k_session_sweep с подставным ct_query.
 *
 * Печатается told, накопленные подозрения и последняя SUSPECT-запись:
 * est (num), server_hello, planned.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_session.h"
#include "d2k_ctq.h"

static uint8_t buffer[2048];
static d2k_ct_info script[64];
static size_t script_len;
static size_t script_pos;

static int fake_query(void *ctx, const d2k_ct_tuple *tuple, d2k_ct_info *out) {
    (void)ctx;
    (void)tuple;
    memset(out, 0, sizeof *out);
    if (script_pos >= script_len) {
        return -1;
    }
    *out = script[script_pos++];
    return 0;
}

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

/* Тот же ClientHello с SNI, что в Rust-тесте. */
static size_t client_hello(uint8_t *o, size_t cap) {
    static const uint8_t host[] = "example.test";
    uint8_t record[512];
    size_t n = 0;
    /* extensions: server_name */
    size_t list_len = 1 + 2 + sizeof host - 1;
    size_t ext_len = 2 + list_len;
    record[n++] = 0; record[n++] = 0;
    w16be(record + n, (unsigned)ext_len); n += 2;
    w16be(record + n, (unsigned)list_len); n += 2;
    record[n++] = 0;
    w16be(record + n, (unsigned)(sizeof host - 1)); n += 2;
    memcpy(record + n, host, sizeof host - 1); n += sizeof host - 1;
    (void)ext_len;

    uint8_t body[512];
    size_t b = 0;
    body[b++] = 0x03; body[b++] = 0x03;
    for (int i = 0; i < 32; i++) body[b++] = 0;
    body[b++] = 0; /* session id */
    body[b++] = 0; body[b++] = 2; body[b++] = 0x13; body[b++] = 1;
    body[b++] = 1; body[b++] = 0;
    w16be(body + b, (unsigned)n); b += 2;
    memcpy(body + b, record, n); b += n;

    uint8_t hs[512];
    hs[0] = 1;
    hs[1] = (uint8_t)(b >> 16); hs[2] = (uint8_t)(b >> 8); hs[3] = (uint8_t)b;
    memcpy(hs + 4, body, b);
    size_t hs_len = 4 + b;

    if (hs_len + 5 > cap) return 0;
    o[0] = 0x16; o[1] = 0x03; o[2] = 0x03;
    w16be(o + 3, (unsigned)hs_len);
    memcpy(o + 5, hs, hs_len);
    return 5 + hs_len;
}

static size_t server_hello(uint8_t *o, size_t cap) {
    if (cap < 47) return 0;
    size_t n = 0;
    o[n++] = 0x16; o[n++] = 0x03; o[n++] = 0x03;
    w16be(o + n, 42); n += 2;
    o[n++] = 2;
    o[n++] = 0; o[n++] = 0; o[n++] = 38;
    o[n++] = 0x03; o[n++] = 0x03;
    for (int i = 0; i < 32; i++) o[n++] = 0;
    o[n++] = 0;
    o[n++] = 0x13; o[n++] = 1;
    o[n++] = 0;
    return n;
}

static void step(const char *name, d2k_session *s, uint64_t now) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t before = d2k_journal_count(j);
    size_t told = d2k_session_sweep(s, now);
    size_t after = d2k_journal_count(j);
    printf("%s told=%zu suspicions=%llu", name, told,
           (unsigned long long)d2k_session_suspects(s));
    if (after > before) {
        const d2k_jrn_entry *e = d2k_journal_at(j, after - 1);
        printf(" est=%u server_hello=%d planned=%d\n", e->num,
               e->d_server_hello, e->d_planned);
    } else {
        printf(" est=0 server_hello=- planned=-\n");
    }
}

static d2k_session *flow_session(void) {
    static const uint8_t client[4] = {192, 0, 2, 10};
    static const uint8_t server[4] = {198, 51, 100, 20};
    d2k_session *s = d2k_session_new(64, 64);
    if (!s) return NULL;
    uint8_t result[4096];
    d2k_result r;
    uint8_t hello[512];
    size_t hello_len = client_hello(hello, sizeof hello);
    size_t length = tcp_packet(buffer, client, server, 40000, 443, 0x02, 700, 0,
                               NULL, 0);
    (void)d2k_session_packet(s, buffer, length, 1000, result, sizeof result, &r);
    length = tcp_packet(buffer, server, client, 443, 40000, 0x12, 900, 701,
                        NULL, 0);
    (void)d2k_session_packet(s, buffer, length, 50001000ull, result,
                             sizeof result, &r);
    length = tcp_packet(buffer, client, server, 40000, 443, 0x18, 701, 900,
                        hello, hello_len);
    (void)d2k_session_packet(s, buffer, length, 100001000ull, result,
                             sizeof result, &r);
    {
        uint8_t sh[64];
        size_t sh_len = server_hello(sh, sizeof sh);
        length = tcp_packet(buffer, server, client, 443, 40000, 0x18, 900, 701,
                            sh, sh_len);
    }
    (void)d2k_session_packet(s, buffer, length, 200001000ull, result,
                             sizeof result, &r);
    script_len = 0;
    script_pos = 0;
    d2k_session_set_ct_query(s, fake_query, NULL);
    return s;
}

static void push(uint64_t orig, uint64_t reply, uint8_t state, uint8_t known) {
    d2k_ct_info *info = &script[script_len++];
    memset(info, 0, sizeof *info);
    info->orig_pkts = orig;
    info->reply_pkts = reply;
    info->tcp_state = state;
    info->tcp_state_known = known;
}

static void setup_line(const char *name, d2k_session *s) {
    printf("%s hellos=%llu with_sni=%llu hello_flows=%llu\n", name,
           (unsigned long long)d2k_session_hellos(s),
           (unsigned long long)d2k_session_with_sni(s),
           (unsigned long long)d2k_session_tcp_hello_flows(s));
}

int main(void) {
    const uint64_t ns = 1000000000ull;
    const uint64_t base = 2000000000ull;

    /* A: состояния нет — молчание. */
    d2k_session *s = flow_session();
    setup_line("H setup", s);
    push(10, 25, 0, 0);
    step("A state-unknown", s, base);
    d2k_session_free(s);

    /* B: SYN_SENT — watch_off. */
    s = flow_session();
    push(10, 25, 1, 1);
    step("B syn-sent", s, base);
    push(13, 25, 3, 1);
    step("B2 after-off", s, base + 3 * ns);
    d2k_session_free(s);

    /* C: установленное соединение, оценка 25, RTO 2 с. */
    s = flow_session();
    push(10, 25, 3, 1); /* baseline */
    step("C baseline", s, base);
    push(11, 25, 3, 1); /* orig +1 — мало */
    step("C orig-1", s, base + 2 * ns);
    push(13, 25, 3, 1); /* +3, но прошло 1.9 с */
    step("C rto-1", s, base + 1900000000ull);
    push(16, 25, 3, 1); /* +6, прошло 2.1 с — событие */
    step("C event", s, base + 2100000000ull);
    push(19, 25, 3, 1); /* уже suspected */
    step("C repeat", s, base + 3 * ns);
    d2k_session_free(s);

    /* D: оценка выше полосы (25+25) — watch_off. */
    s = flow_session();
    push(10, 100, 3, 1);
    step("D over-band", s, base);
    push(13, 100, 3, 1);
    step("D after-off", s, base + 3 * ns);
    d2k_session_free(s);

    /* E: ответ не вырос — unseen=0. */
    s = flow_session();
    push(10, 1, 3, 1);
    step("E baseline", s, base);
    push(13, 1, 3, 1);
    step("E unseen-0", s, base + 3 * ns);
    d2k_session_free(s);

    /* F: бюджет 60 — оценка 62 в полосе. */
    s = flow_session();
    {
        static const uint16_t budgets[] = {25, 60};
        (void)d2k_session_set_stall_budgets(s, budgets, 2);
    }
    push(10, 62, 3, 1);
    step("F baseline", s, base);
    push(13, 62, 3, 1);
    step("F rto", s, base + 1 * ns);
    push(16, 62, 3, 1);
    step("F event", s, base + 3 * ns);
    d2k_session_free(s);

    /* G: orig меньше метки — молчание. */
    s = flow_session();
    push(10, 25, 3, 1);
    step("G baseline", s, base);
    push(9, 25, 3, 1);
    step("G orig-less", s, base + 3 * ns);
    push(12, 25, 3, 1); /* +2 от метки 10 */
    step("G orig-2", s, base + 4 * ns);
    d2k_session_free(s);
    return 0;
}
