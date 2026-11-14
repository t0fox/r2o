/* C-оракул: ветви handle_udp — STUN voice, QUIC Initial, серверное
 * направление, отказ таблицы потоков. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_ctl.h"
#include "d2k_ctlsrv.h"
#include "d2k_http80.h"
#include "d2k_session.h"

static uint8_t buffer[2048];

static void w16be(uint8_t *o, unsigned v) {
    o[0] = (uint8_t)(v >> 8);
    o[1] = (uint8_t)v;
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

static void stun_request(uint8_t *o) {
    memset(o, 0, 20);
    o[0] = 0; o[1] = 1; /* Binding request */
    o[4] = 0x21; o[5] = 0x12; o[6] = 0xA4; o[7] = 0x42;
    for (int i = 8; i < 20; i++) o[i] = (uint8_t)(0x40 + i);
}

static void stun_response(uint8_t *o) {
    stun_request(o);
    o[0] = 1; o[1] = 1; /* Binding success response */
}

static void print(const char *name, const d2k_session *session) {
    printf("%s flows=%zu refusals=%llu hellos=%llu with_sni=%llu exchanges=%llu\n",
           name, d2k_session_flows_udp(session),
           (unsigned long long)d2k_session_refusals_udp(session),
           (unsigned long long)d2k_session_hellos(session),
           (unsigned long long)d2k_session_with_sni(session),
           (unsigned long long)d2k_session_exchanges(session));
}


/* --- планы: установка через control и сверка применения ------------------ */

static unsigned long long fnv1a(const uint8_t *p, size_t n) {
    unsigned long long h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

static size_t put_tlv(uint8_t *o, size_t off, uint16_t kind, const uint8_t *v, size_t n) {
    w16be(o + off, kind);
    w16be(o + off + 2, (unsigned)n);
    memcpy(o + off + 4, v, n);
    return off + 4 + n;
}

static size_t plan_header(uint8_t *o, uint16_t minexec, uint16_t records, uint8_t idbyte) {
    static const uint8_t id[16] = {0x51,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t ids[16];
    memcpy(ids, id, 16);
    ids[0] = idbyte;
    memcpy(o, "D2KP", 4);
    o[4] = 0; o[5] = 1;
    o[6] = (uint8_t)(minexec >> 8); o[7] = (uint8_t)minexec;
    o[8] = 0; o[9] = 0;
    o[10] = (uint8_t)(records >> 8); o[11] = (uint8_t)records;
    return put_tlv(o, 12, 0x0001, ids, 16);
}

static size_t quic_qsplit_plan(uint8_t *o) {
    static const uint8_t transport[2] = {17, 2};
    static const uint8_t one[1] = {1};
    size_t off = plan_header(o, 10, 3, 0x51);
    off = put_tlv(o, off, 0x0002, transport, 2);
    off = put_tlv(o, off, 0x010f, one, 1);
    return off;
}

static size_t quic_fake_plan(uint8_t *o, unsigned fakes) {
    static const uint8_t transport[2] = {17, 2};
    static const uint8_t payload[4] = {0, 1, 'F', 'Q'};
    static const uint8_t fake[10] = {0, 1, 0, 0, 1, 0, 0, 0, 0, 0};
    size_t off = plan_header(o, 0, (uint16_t)(3 + fakes), 0x52);
    off = put_tlv(o, off, 0x0002, transport, 2);
    off = put_tlv(o, off, 0x0010, payload, sizeof payload);
    for (unsigned i = 0; i < fakes; i++) off = put_tlv(o, off, 0x0101, fake, sizeof fake);
    return off;
}

/* План с фальшивкой и обычным разрезом payload: для UDP C отвергает
 * несколько payload-посылок целиком (`session.c:1372-1386`). */
static size_t quic_split_fake_plan(uint8_t *o) {
    static const uint8_t transport[2] = {17, 2};
    static const uint8_t payload[4] = {0, 1, 'F', 'Q'};
    static const uint8_t fake[10] = {0, 1, 0, 0, 1, 0, 0, 0, 0, 0};
    static const uint8_t split[4] = {0, 0, 0, 16};
    size_t off = plan_header(o, 0, 5, 0x54);
    off = put_tlv(o, off, 0x0002, transport, 2);
    off = put_tlv(o, off, 0x0010, payload, sizeof payload);
    off = put_tlv(o, off, 0x0100, split, sizeof split);
    off = put_tlv(o, off, 0x0101, fake, sizeof fake);
    return off;
}

/* quicdeny: единственное содержание плана — снять QUIC-поток имени. */
static size_t quic_deny_plan(uint8_t *o) {
    static const uint8_t transport[2] = {17, 2};
    static const uint8_t deny[1] = {1};
    size_t off = plan_header(o, 11, 3, 0x55);
    off = put_tlv(o, off, 0x0002, transport, 2);
    return put_tlv(o, off, 0x0110, deny, 1);
}

/* План TCP, поставленный общим для UDP-пакета: C `plan_fits_transport`
 * отказывает до исполнения. */
static size_t tcp_global_plan(uint8_t *o) {
    static const uint8_t transport[2] = {6, 1};
    size_t off = plan_header(o, 0, 2, 0x56);
    return put_tlv(o, off, 0x0002, transport, 2);
}

static size_t voice_fake_plan(uint8_t *o) {
    static const uint8_t transport[2] = {17, 3};
    static const uint8_t payload[7] = {0, 1, 'V', 'O', 'I', 'C', 'E'};
    static const uint8_t fake[10] = {0, 1, 0, 0, 1, 0, 0, 0, 0, 0};
    size_t off = plan_header(o, 0, 4, 0x53);
    off = put_tlv(o, off, 0x0002, transport, 2);
    off = put_tlv(o, off, 0x0010, payload, sizeof payload);
    off = put_tlv(o, off, 0x0101, fake, sizeof fake);
    return off;
}

static void install_name(d2k_ctlsrv *cx, const char *host, uint8_t shape,
                         const uint8_t *plan, size_t plan_len) {
    uint8_t cmd[1024];
    size_t n = 0;
    size_t host_len = strlen(host);
    cmd[n++] = (uint8_t)host_len;
    memcpy(cmd + n, host, host_len); n += host_len;
    cmd[n++] = shape;
    cmd[n++] = 4;
    memcpy(cmd + n, plan, plan_len); n += plan_len;
    d2k_ctlsrv_command(cx, D2K_CMD_SET_NAME, cmd, n);
}

static void install_addr(d2k_ctlsrv *cx, const uint8_t address[4], uint8_t shape,
                         const uint8_t *plan, size_t plan_len) {
    uint8_t cmd[1024];
    size_t n = 0;
    cmd[n++] = 4;
    memset(cmd + n, 0, 16); n += 16;
    memcpy(cmd + 1, address, 4);
    cmd[n++] = shape;
    memcpy(cmd + n, plan, plan_len); n += plan_len;
    d2k_ctlsrv_command(cx, D2K_CMD_SET_ADDR, cmd, n);
}

static d2k_session *plan_session(d2k_ctlsrv *cx) {
    d2k_session *s = d2k_session_new(64, 0);
    memset(cx, 0, sizeof *cx);
    cx->sess = s;
    cx->now_ns = 1000;
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    return s;
}

static void plan_case_ex(const char *name, d2k_session *s, const uint8_t *packet,
                         size_t length, uint8_t *result_buffer, size_t result_cap,
                         int compare_skip) {
    d2k_result r;
    memset(&r, 0, sizeof r);
    (void)d2k_session_packet(s, packet, length, 1000, result_buffer, result_cap, &r);
    printf("%s applied=%d n=%zu lens=", name, r.applied ? 1 : 0, r.n_out);
    for (size_t i = 0; i < r.n_out; i++) {
        printf("%s%zu", i ? "," : "", r.out[i].len);
    }
    printf(" hash=");
    for (size_t i = 0; i < r.n_out; i++) {
        printf("%s%016llx", i ? "," : "",
               fnv1a(result_buffer + r.out[i].off, r.out[i].len));
    }
    printf(" phash=");
    for (size_t i = 0; i < r.n_out; i++) {
        size_t off = r.out[i].off;
        size_t len = r.out[i].len;
        printf("%s%016llx", i ? "," : "",
               len > 28 ? fnv1a(result_buffer + off + 28, len - 28) : 0ull);
    }
    if (compare_skip) {
        printf(" skip=%d\n", r.skipped && r.skipped[0] ? 1 : 0);
    } else {
        printf(" skip=-\n");
    }
}

static void plan_case(const char *name, d2k_session *s, const uint8_t *packet,
                      size_t length, uint8_t *result_buffer, size_t result_cap) {
    plan_case_ex(name, s, packet, length, result_buffer, result_cap, 1);
}

/* C `handle_udp`: после quicdeny снимается каждая клиентская датаграмма
 * потока, не только Initial. Печатаем вердикты обоих пакетов. */
static void qdeny_flow_case(const char *name, const uint8_t *plan_bytes,
                            size_t plan_len, const uint8_t *first,
                            size_t first_len, const uint8_t *second,
                            size_t second_len) {
    d2k_plan *plan = NULL;
    char error[200];
    if (d2k_plan_load(plan_bytes, plan_len, &plan, error, sizeof error) != 0) {
        printf("%s load-error=%s\n", name, error);
        return;
    }
    d2k_session *s = d2k_session_new(64, 0);
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    d2k_session_set_plan(s, plan);
    uint8_t out[4096];
    d2k_result r;
    memset(&r, 0, sizeof r);
    (void)d2k_session_packet(s, first, first_len, 1000, out, sizeof out, &r);
    int first_verdict = r.verdict;
    size_t first_n = r.n_out;
    memset(&r, 0, sizeof r);
    (void)d2k_session_packet(s, second, second_len, 2000, out, sizeof out, &r);
    printf("%s verdict=%d/%d n=%zu/%zu\n", name, first_verdict, r.verdict,
           first_n, r.n_out);
    d2k_session_free(s);
}

/* План ставится общим (`d2k_session_set_plan`), как файл `--plan` в d2kd:
 * control-проверка формы QUIC здесь не участвует. */
static void global_plan_case(const char *name, const uint8_t *plan_bytes,
                             size_t plan_len, const uint8_t *packet,
                             size_t length, uint8_t *result_buffer,
                             size_t result_cap) {
    d2k_plan *plan = NULL;
    char error[200];
    if (d2k_plan_load(plan_bytes, plan_len, &plan, error, sizeof error) != 0) {
        printf("%s load-error=%s\n", name, error);
        return;
    }
    d2k_session *s = d2k_session_new(64, 0);
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    d2k_session_set_plan(s, plan);
    plan_case(name, s, packet, length, result_buffer, result_cap);
    d2k_session_free(s);
}

static void print_short(const char *name, const d2k_session *session) {
    printf("%s flows=%zu refusals=%llu exchanges=%llu\n", name,
           d2k_session_flows_udp(session),
           (unsigned long long)d2k_session_refusals_udp(session),
           (unsigned long long)d2k_session_exchanges(session));
}

static void silence_case(const char *name, const uint8_t *payload,
                          size_t payload_len, int with_repeat, int with_response,
                          int final_repeat, uint64_t sweep_at) {
    static const uint8_t client[4] = {192, 0, 2, 10};
    static const uint8_t server[4] = {198, 51, 100, 20};
    uint8_t packet[2048];
    uint8_t result[4096];
    d2k_session *s = d2k_session_new(64, 0);
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    size_t length = udp_packet(packet, client, server, 50005, 443, payload,
                               payload_len);
    (void)d2k_session_packet(s, packet, length, 1000, result, sizeof result,
                             &(d2k_result){0});
    if (with_repeat) {
        (void)d2k_session_packet(s, packet, length, 1800, result, sizeof result,
                                 &(d2k_result){0});
    }
    if (with_response) {
        d2k_session_set_hook(s, D2K_HOOK_INPUT);
        length = udp_packet(packet, server, client, 443, 50005,
                            (const uint8_t *)"resp", 4);
        (void)d2k_session_packet(s, packet, length, 1900, result, sizeof result,
                                 &(d2k_result){0});
    }
    if (final_repeat) {
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        length = udp_packet(packet, client, server, 50005, 443, payload,
                            payload_len);
        (void)d2k_session_packet(s, packet, length, 2000, result, sizeof result,
                                 &(d2k_result){0});
    }
    d2k_session_set_udp_reverse_hook(s, 1);
    size_t told = d2k_session_sweep(s, sweep_at);
    printf("%s flows=%zu hellos=%llu suspects=%zu\n", name,
           d2k_session_flows_udp(s),
           (unsigned long long)d2k_session_hellos(s), told);
    d2k_session_free(s);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 3;
    uint8_t initial[2048];
    size_t initial_len = fread(initial, 1, sizeof initial, file);
    fclose(file);
    file = fopen(argv[2], "rb");
    if (!file) return 3;
    uint8_t unnamed[2048];
    size_t unnamed_len = fread(unnamed, 1, sizeof unnamed, file);
    fclose(file);

    static const uint8_t client[4] = {192, 0, 2, 10};
    static const uint8_t server[4] = {198, 51, 100, 20};
    uint8_t payload[32];
    uint8_t result_buffer[4096];
    size_t length;
    uint8_t response[32];

    /* QUIC Initial из клиента, ответ сервера, обратный Initial. */
    d2k_session *quic = d2k_session_new(64, 0);
    d2k_session_set_hook(quic, D2K_HOOK_POSTROUTING);
    length = udp_packet(buffer, client, server, 50001, 443, initial, initial_len);
    (void)d2k_session_packet(quic, buffer, length, 1000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    print("Q1", quic);
    d2k_session_set_hook(quic, D2K_HOOK_INPUT);
    length = udp_packet(buffer, server, client, 443, 50001, (const uint8_t *)"resp", 4);
    (void)d2k_session_packet(quic, buffer, length, 2000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    print("Q2", quic);
    (void)d2k_session_packet(quic, buffer, length, 3000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    print("Q3", quic);
    length = udp_packet(buffer, server, client, 443, 50002, initial, initial_len);
    (void)d2k_session_packet(quic, buffer, length, 4000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    print("Q4", quic);
    d2k_session_free(quic);

    /* STUN voice: запрос на медиапорт Дискорда, затем два ответа. */
    d2k_session *voice = d2k_session_new(64, 0);
    d2k_session_set_hook(voice, D2K_HOOK_POSTROUTING);
    stun_request(payload);
    length = udp_packet(buffer, client, server, 50000, 50010, payload, 20);
    (void)d2k_session_packet(voice, buffer, length, 1000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    d2k_session_set_hook(voice, D2K_HOOK_INPUT);
    stun_response(response);
    length = udp_packet(buffer, server, client, 50010, 50000, response, 20);
    (void)d2k_session_packet(voice, buffer, length, 2000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    print_short("V1", voice);
    (void)d2k_session_packet(voice, buffer, length, 3000, result_buffer, sizeof result_buffer, &(d2k_result){0});
    print_short("V2", voice);
    d2k_session_free(voice);

    /* V3: направление доказано другим пакетом, STUN приходит на FORWARD.
     * C берёт сторону из fl->dir_known, а не только из крючка. */
    d2k_session *forward_voice = d2k_session_new(64, 0);
    d2k_session_set_hook(forward_voice, D2K_HOOK_POSTROUTING);
    length = udp_packet(buffer, client, server, 50011, 50010, initial, initial_len);
    (void)d2k_session_packet(forward_voice, buffer, length, 1000,
                             result_buffer, sizeof result_buffer, &(d2k_result){0});
    d2k_session_set_hook(forward_voice, D2K_HOOK_FORWARD);
    stun_request(payload);
    length = udp_packet(buffer, client, server, 50011, 50010, payload, 20);
    (void)d2k_session_packet(forward_voice, buffer, length, 2000,
                             result_buffer, sizeof result_buffer, &(d2k_result){0});
    stun_response(response);
    length = udp_packet(buffer, server, client, 50010, 50011, response, 20);
    (void)d2k_session_packet(forward_voice, buffer, length, 3000,
                             result_buffer, sizeof result_buffer, &(d2k_result){0});
    print_short("V3", forward_voice);
    d2k_session_free(forward_voice);


    /* Отказ таблицы: 60 корректных UDP-потоков при 64 слотах (порог 3/4). */
    d2k_session *refusal = d2k_session_new(64, 0);
    d2k_session_set_hook(refusal, D2K_HOOK_POSTROUTING);
    for (unsigned i = 0; i < 60; i++) {
        length = udp_packet(buffer, client, server, (uint16_t)(20000 + i),
                            50010, (const uint8_t *)"x", 1);
        (void)d2k_session_packet(refusal, buffer, length, 1000 + i,
                                 result_buffer, sizeof result_buffer, &(d2k_result){0});
    }
    print_short("R1", refusal);
    d2k_session_free(refusal);

    /* Initial без имени: saw_initial, повтор PTO, затем sweep без ответа. */
    d2k_session *silent = d2k_session_new(64, 0);
    d2k_session_set_hook(silent, D2K_HOOK_POSTROUTING);
    length = udp_packet(buffer, client, server, 50003, 443, unnamed, unnamed_len);
    (void)d2k_session_packet(silent, buffer, length, 1000,
                             result_buffer, sizeof result_buffer, &(d2k_result){0});
    (void)d2k_session_packet(silent, buffer, length, 1800,
                             result_buffer, sizeof result_buffer, &(d2k_result){0});
    d2k_session_set_udp_reverse_hook(silent, 1);
    size_t told = d2k_session_sweep(silent, 1000ull + 2000000000ull + 1ull);
    printf("S1 flows=%zu hellos=%llu suspects=%zu\n",
           d2k_session_flows_udp(silent),
           (unsigned long long)d2k_session_hellos(silent), told);
    d2k_session_free(silent);

    /* Ответ после последнего PTO: sweep молчит. */
    d2k_session *answered = d2k_session_new(64, 0);
    d2k_session_set_hook(answered, D2K_HOOK_POSTROUTING);
    length = udp_packet(buffer, client, server, 50004, 443, unnamed, unnamed_len);
    (void)d2k_session_packet(answered, buffer, length, 1000,
                             result_buffer, sizeof result_buffer, &(d2k_result){0});
    (void)d2k_session_packet(answered, buffer, length, 1800,
                             result_buffer, sizeof result_buffer, &(d2k_result){0});
    d2k_session_set_hook(answered, D2K_HOOK_INPUT);
    length = udp_packet(buffer, server, client, 443, 50004, (const uint8_t *)"resp", 4);
    (void)d2k_session_packet(answered, buffer, length, 1900,
                             result_buffer, sizeof result_buffer, &(d2k_result){0});
    d2k_session_set_udp_reverse_hook(answered, 1);
    told = d2k_session_sweep(answered, 1000ull + 2000000000ull + 1ull);
    printf("S2 flows=%zu hellos=%llu suspects=%zu\n",
           d2k_session_flows_udp(answered),
           (unsigned long long)d2k_session_hellos(answered), told);
    d2k_session_free(answered);

    /* S3-S8: rev_after_hello/last_fwd и saw_initial для молчания. */
    silence_case("S3 repeat-after-response", initial, initial_len, 1, 1, 1,
                 2000001001ull);
    silence_case("S4 response-only", initial, initial_len, 1, 1, 0,
                 2000001001ull);
    silence_case("S5 no-forward-after-hello", initial, initial_len, 0, 0, 0,
                 2000001001ull);
    silence_case("S6 named-silence", initial, initial_len, 1, 0, 0,
                 2000001001ull);
    silence_case("S7 early-sweep", initial, initial_len, 1, 0, 0,
                 1000001000ull);
    silence_case("S8 unnamed-repeat-after-response", unnamed, unnamed_len, 1, 1,
                 1, 2000001001ull);

    /* --- планы: выбор по имени/адресу/голосу и предел посылок ---------- */
    {
        static const uint8_t server_addr[4] = {198, 51, 100, 20};
        uint8_t plan[4096];
        uint8_t result_buffer[65536];
        d2k_ctlsrv cx;

        /* P1: QUIC имя + qsplit — пересборка CRYPTO. */
        d2k_session *ps = plan_session(&cx);
        size_t plan_len = quic_qsplit_plan(plan);
        install_name(&cx, "example.com", 3, plan, plan_len);
        length = udp_packet(buffer, client, server, 50101, 443, initial, initial_len);
        plan_case("P1 name-quic-qsplit", ps, buffer, length, result_buffer, sizeof result_buffer);
        d2k_session_free(ps);

        /* P2: план на чужое имя — не применяется. */
        ps = plan_session(&cx);
        plan_len = quic_qsplit_plan(plan);
        install_name(&cx, "other.example", 3, plan, plan_len);
        length = udp_packet(buffer, client, server, 50102, 443, initial, initial_len);
        plan_case("P2 other-name", ps, buffer, length, result_buffer,
                  sizeof result_buffer);
        d2k_session_free(ps);

        /* P3: адресный QUIC-план на Initial без имени. */
        ps = plan_session(&cx);
        plan_len = quic_fake_plan(plan, 1);
        install_addr(&cx, server_addr, 3, plan, plan_len);
        length = udp_packet(buffer, client, server, 50103, 443, unnamed, unnamed_len);
        plan_case("P3 addr-quic-fake", ps, buffer, length, result_buffer, sizeof result_buffer);
        d2k_session_free(ps);

        /* P4: именной QUIC fake: фальшивка + собственный оригинал. */
        ps = plan_session(&cx);
        plan_len = quic_fake_plan(plan, 1);
        install_name(&cx, "example.com", 3, plan, plan_len);
        length = udp_packet(buffer, client, server, 50104, 443, initial, initial_len);
        plan_case("P4 name-quic-fake", ps, buffer, length, result_buffer, sizeof result_buffer);
        d2k_session_free(ps);

        /* P5: голос по имени @discord-voice. */
        ps = plan_session(&cx);
        plan_len = voice_fake_plan(plan);
        install_name(&cx, "@discord-voice", 5, plan, plan_len);
        stun_request(payload);
        length = udp_packet(buffer, client, server, 50105, 50010, payload, 20);
        plan_case("P5 voice-name", ps, buffer, length, result_buffer, sizeof result_buffer);
        d2k_session_free(ps);

        /* P6: голос по адресу. */
        ps = plan_session(&cx);
        plan_len = voice_fake_plan(plan);
        install_addr(&cx, server_addr, 5, plan, plan_len);
        stun_request(payload);
        length = udp_packet(buffer, client, server, 50106, 50010, payload, 20);
        plan_case("P6 voice-addr", ps, buffer, length, result_buffer, sizeof result_buffer);
        d2k_session_free(ps);

        /* P7: 25 фальшивок + оригинал = 26 посылок — предел. */
        ps = plan_session(&cx);
        plan_len = quic_fake_plan(plan, 25);
        install_name(&cx, "example.com", 3, plan, plan_len);
        length = udp_packet(buffer, client, server, 50107, 443, initial, initial_len);
        plan_case("P7 quic-25-fakes", ps, buffer, length, result_buffer, sizeof result_buffer);
        d2k_session_free(ps);

        /* P8: 26 фальшивок + оригинал = 27 > предела — отказ целиком. */
        ps = plan_session(&cx);
        plan_len = quic_fake_plan(plan, 26);
        install_name(&cx, "example.com", 3, plan, plan_len);
        length = udp_packet(buffer, client, server, 50108, 443, initial, initial_len);
        plan_case("P8 quic-26-fakes", ps, buffer, length, result_buffer, sizeof result_buffer);
        d2k_session_free(ps);

        /* P9: разрез payload + фальшивка как общий план. Датаграмма
         * атомарна: C не отправляет ни одной посылки и пишет отказ. */
        plan_len = quic_split_fake_plan(plan);
        global_plan_case("P9 quic-split-fake", plan, plan_len, buffer,
                         udp_packet(buffer, client, server, 50109, 443,
                                    initial, initial_len),
                         result_buffer, sizeof result_buffer);

        /* P10: quicdeny снимает и повтор Initial, и обычную клиентскую
         * датаграмму того же потока. */
        plan_len = quic_deny_plan(plan);
        uint8_t first[2048];
        size_t first_len =
            udp_packet(first, client, server, 50110, 443, initial, initial_len);
        uint8_t second[64];
        size_t second_len =
            udp_packet(second, client, server, 50110, 443,
                       (const uint8_t *)"later", 5);
        qdeny_flow_case("P10 qdeny-flow", plan, plan_len, first, first_len,
                        second, second_len);

        /* P11: TCP-план как общий для UDP — отказ по транспорту. */
        plan_len = tcp_global_plan(plan);
        global_plan_case("P11 other-transport", plan, plan_len, buffer,
                         udp_packet(buffer, client, server, 50111, 443,
                                    initial, initial_len),
                         result_buffer, sizeof result_buffer);
    }
    return 0;
}

