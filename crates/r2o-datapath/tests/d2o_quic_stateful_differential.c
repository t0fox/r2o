/* C stateful QUIC handle_udp fixture: plan-applied skip, name/shape/ring,
 * кольцо до qsnap_done, пустое имя, Retry/неполный Initial, разрез payload
 * и защитная судьба HOLD. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_plan.h"

/* Защитная ветка `D2K_ORIG_HOLD` не достижима из сериализованного плана:
 * `d2k_plan_apply` её не возвращает. Чтобы проверить именно production-
 * ветку `handle_udp`, подменяем только сам вызов исполнителя. Остальной
 * `session.c` остаётся настоящим. */
static int g_hold_mode;
static int (*const g_real_plan_apply)(const d2k_plan *, const d2k_flow *,
                                      const d2k_pkt *, d2k_actions *) = d2k_plan_apply;
static int harness_plan_apply(const d2k_plan *, const d2k_flow *,
                              const d2k_pkt *, d2k_actions *);
#define d2k_plan_apply harness_plan_apply
#include "session.c"
#undef d2k_plan_apply

static int harness_plan_apply(const d2k_plan *p, const d2k_flow *f,
                              const d2k_pkt *in, d2k_actions *out) {
    if (!g_hold_mode) {
        return g_real_plan_apply(p, f, in, out);
    }
    memset(out, 0, sizeof *out);
    out->fate = D2K_ORIG_HOLD;
    out->v = calloc(1, sizeof *out->v);
    if (!out->v) {
        return -1;
    }
    out->n = 1;
    out->v[0].kind = D2K_EMIT_PAYLOAD;
    out->v[0].bytes = in->payload;
    out->v[0].len = in->payload_len;
    return 0;
}

static size_t udp_packet(uint8_t *out, const uint8_t *src, const uint8_t *dst,
                         uint16_t sport, uint16_t dport, const uint8_t *payload,
                         size_t payload_len) {
    size_t total = 28 + payload_len;
    memset(out, 0, total);
    out[0] = 0x45;
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[8] = 64;
    out[9] = 17;
    memcpy(out + 12, src, 4);
    memcpy(out + 16, dst, 4);
    out[20] = (uint8_t)(sport >> 8); out[21] = (uint8_t)sport;
    out[22] = (uint8_t)(dport >> 8); out[23] = (uint8_t)dport;
    out[24] = (uint8_t)((8 + payload_len) >> 8);
    out[25] = (uint8_t)(8 + payload_len);
    if (payload_len) memcpy(out + 28, payload, payload_len);
    return total;
}

static size_t plan_header(uint8_t *out, uint16_t records) {
    static const uint8_t id[16] = {0x51,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    memcpy(out, "D2KP", 4);
    out[4]=0; out[5]=1; out[6]=0; out[7]=10; out[8]=0; out[9]=0;
    out[10]=(uint8_t)(records >> 8); out[11]=(uint8_t)records;
    size_t off = 12;
    out[off++] = 0x00; out[off++] = 0x01;
    out[off++] = 0x00; out[off++] = 0x10;
    memcpy(out + off, id, sizeof id); off += sizeof id;
    out[off++] = 0x00; out[off++] = 0x02;
    out[off++] = 0x00; out[off++] = 0x02;
    out[off++] = 17; out[off++] = 2;
    return off;
}

static size_t quic_plan(uint8_t *out) {
    size_t off = plan_header(out, 3);
    out[off++] = 0x01; out[off++] = 0x0f;
    out[off++] = 0x00; out[off++] = 0x01;
    out[off++] = 1;
    return off;
}

static size_t split_plan(uint8_t *out) {
    size_t off = plan_header(out, 3);
    /* REC_SPLIT: якорь PAYLOAD_START, смещение 100 — две payload-посылки. */
    out[off++] = 0x01; out[off++] = 0x00;
    out[off++] = 0x00; out[off++] = 0x04;
    out[off++] = 0x00; out[off++] = 0x00;
    out[off++] = 0x00; out[off++] = 100;
    return off;
}

static void install_plan(d2k_session *s, const char *host, const uint8_t *plan,
                         size_t plan_len) {
    d2k_plan *p = NULL;
    char error[200];
    if (d2k_plan_load(plan, plan_len, &p, error, sizeof error) != 0) {
        printf("plan load-error=%s\n", error);
        return;
    }
    if (d2k_plantab_set_name_family(d2k_session_plans(s),
            (const uint8_t *)host, strlen(host), 1000, p,
            D2K_PLAN_SHAPE_QUIC, 0, 4) != 0) {
        printf("plan install-error\n");
    }
}

static void print_result(const char *name, d2k_session *s, d2k_result *r,
                         const uint8_t *packet, size_t length) {
    uint32_t anchor = 0;
    (void)d2k_session_stream_anchor(s, packet, length, &anchor);
    d2k_key key;
    static const uint8_t src[4] = {192,0,2,10};
    static const uint8_t dst[4] = {198,51,100,20};
    static const uint8_t sport[2] = {0xC3,0x51};
    static const uint8_t dport[2] = {0x01,0xBB};
    (void)d2k_key_make(&key, 17, src, dst, sport, dport);
    d2k_flow *flow = d2k_track_find(s->uflows, &key);
    size_t live = 0;
    for (size_t i = 0; i < s->init_ring_n; i++) {
        if (s->init_ring[i].len != 0) { live++; }
    }
    printf("%s applied=%d skip=%d skipped=\"%s\" n=%zu plan_done=%d sends_left=%u ring=%zu ring_live=%zu qsnap=%d quic_name=\"%s\" shape_miss=%d verdict=%d\n",
           name, r->applied ? 1 : 0,
           r->skipped && r->skipped[0] ? 1 : 0,
           r->skipped ? r->skipped : "",
           r->n_out, flow ? flow->plan_done : 0,
           flow ? flow->sends_left : 0, s->init_ring_n, live,
           flow ? flow->qsnap_done : 0, r->quic_name, r->quic_shape_miss,
           (int)r->verdict);
}

static void ring_line(const char *name, d2k_session *s, int with_name,
                      const char *quic_name) {
    d2k_key key;
    static const uint8_t src[4] = {192,0,2,10};
    static const uint8_t dst[4] = {198,51,100,20};
    static const uint8_t sport[2] = {0xC3,0x51};
    static const uint8_t dport[2] = {0x01,0xBB};
    size_t live = 0;
    (void)d2k_key_make(&key, 17, src, dst, sport, dport);
    d2k_flow *flow = d2k_track_find(s->uflows, &key);
    for (size_t i = 0; i < s->init_ring_n; i++) {
        if (s->init_ring[i].len != 0) { live++; }
    }
    printf("%s ring_live=%zu qsnap=%d plan_done=%d", name, live,
           flow ? flow->qsnap_done : 0, flow ? flow->plan_done : 0);
    if (with_name) {
        printf(" quic_name=\"%s\"", quic_name ? quic_name : "");
    }
    putchar('\n');
}

static void run_flow(const char *name, d2k_session *s, const uint8_t *payload,
                     size_t payload_len, int install) {
    static const uint8_t client[4] = {192,0,2,10};
    static const uint8_t server[4] = {198,51,100,20};
    uint8_t buffer[2048];
    uint8_t out[4096];
    d2k_result result;
    size_t n;
    if (install) {
        uint8_t plan_bytes[256];
        size_t plan_len = quic_plan(plan_bytes);
        install_plan(s, "example.com", plan_bytes, plan_len);
    }
    d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
    n = udp_packet(buffer, client, server, 50001, 443, payload, payload_len);
    memset(&result, 0, sizeof result);
    (void)d2k_session_packet(s, buffer, n, 1000, out, sizeof out, &result);
    char label[64];
    snprintf(label, sizeof label, "%s first", name);
    print_result(label, s, &result, buffer, n);
    memset(&result, 0, sizeof result);
    (void)d2k_session_packet(s, buffer, n, 1800, out, sizeof out, &result);
    snprintf(label, sizeof label, "%s second", name);
    print_result(label, s, &result, buffer, n);
}

static void send_packet(d2k_session *s, const uint8_t *payload,
                        size_t payload_len, uint64_t now, d2k_result *result) {
    static const uint8_t client[4] = {192,0,2,10};
    static const uint8_t server[4] = {198,51,100,20};
    uint8_t buffer[2048];
    uint8_t out[4096];
    size_t n = udp_packet(buffer, client, server, 50001, 443, payload, payload_len);
    memset(result, 0, sizeof *result);
    (void)d2k_session_packet(s, buffer, n, now, out, sizeof out, result);
}

static void send_one(const char *label, d2k_session *s, const uint8_t *payload,
                     size_t payload_len, uint64_t now) {
    static const uint8_t client[4] = {192,0,2,10};
    static const uint8_t server[4] = {198,51,100,20};
    uint8_t buffer[2048];
    d2k_result result;
    size_t n = udp_packet(buffer, client, server, 50001, 443, payload, payload_len);
    send_packet(s, payload, payload_len, now, &result);
    print_result(label, s, &result, buffer, n);
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    uint8_t initial[2048], unnamed[2048], first[2048], second[2048];
    size_t initial_len, unnamed_len, first_len, second_len;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 3;
    initial_len = fread(initial, 1, sizeof initial, f);
    fclose(f);
    f = fopen(argv[2], "rb");
    if (!f) return 3;
    unnamed_len = fread(unnamed, 1, sizeof unnamed, f);
    fclose(f);
    f = fopen(argv[3], "rb");
    if (!f) return 3;
    first_len = fread(first, 1, sizeof first, f);
    fclose(f);
    f = fopen(argv[4], "rb");
    if (!f) return 3;
    second_len = fread(second, 1, sizeof second, f);
    fclose(f);

    d2k_session *planned = d2k_session_new(64, 0);
    run_flow("Q1 planned-named", planned, initial, initial_len, 1);
    d2k_session_free(planned);

    d2k_session *empty = d2k_session_new(64, 0);
    run_flow("Q2 empty-name", empty, unnamed, unnamed_len, 0);
    d2k_session_free(empty);

    d2k_session *named = d2k_session_new(64, 0);
    run_flow("Q3 named-no-plan", named, initial, initial_len, 0);
    d2k_session_free(named);

    /* Q4: кольцо живёт до qsnap_done. C при активном hold не снимает
       снимок на готовности — только на replay головы. */
    {
        static const uint8_t client[4] = {192,0,2,10};
        static const uint8_t server[4] = {198,51,100,20};
        uint8_t pkt[2048], out[4096];
        d2k_result result;
        d2k_key key;
        d2k_session *hold = d2k_session_new(64, 0);
        d2k_session_set_hook(hold, D2K_HOOK_POSTROUTING);
        size_t n = udp_packet(pkt, client, server, 50001, 443, first, first_len);
        if (d2k_session_udp_hold_begin(hold, pkt, n, 1000, &key) != 1) {
            printf("Q4 hold-begin-error\n");
        }
        memset(&result, 0, sizeof result);
        (void)d2k_session_packet(hold, pkt, n, 1000, out, sizeof out, &result);
        ring_line("Q4 hold-prefetch first", hold, 0, NULL);

        n = udp_packet(pkt, client, server, 50001, 443, second, second_len);
        memset(&result, 0, sizeof result);
        (void)d2k_session_packet(hold, pkt, n, 1100, out, sizeof out, &result);
        ring_line("Q4 hold-prefetch second", hold, 0, NULL);

        d2k_session_udp_hold_replay(hold, &key);
        n = udp_packet(pkt, client, server, 50001, 443, first, first_len);
        memset(&result, 0, sizeof result);
        (void)d2k_session_packet(hold, pkt, n, 1200, out, sizeof out, &result);
        ring_line("Q4 hold-replay head", hold, 1, result.quic_name);
        d2k_session_free(hold);
    }

    /* Q5: пустое имя не взводит qsnap_done и не чистит кольцо; следующий
       именованный Initial собирает снимок своего DCID. */
    {
        d2k_result result;
        d2k_session *s = d2k_session_new(64, 0);
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        send_packet(s, unnamed, unnamed_len, 1000, &result);
        ring_line("Q5 empty-name first", s, 0, NULL);
        send_packet(s, unnamed, unnamed_len, 1100, &result);
        ring_line("Q5 empty-name second", s, 0, NULL);
        d2k_session_free(s);
    }

    /* Q6: Retry/неполный Initial не взводит qsnap_done; кольцо не трогается
       не-Initial датаграммой, а именованный Initial нового полёта собирает
       снимок и очищает записи потока. */
    {
        static const uint8_t retry[] = {0xf0,0,0,0,1,8,1,2,3,4,5,6,7,8,0,4,9,9,9,9};
        d2k_result result;
        d2k_session *s = d2k_session_new(64, 0);
        d2k_session_set_hook(s, D2K_HOOK_POSTROUTING);
        send_packet(s, first, first_len, 1000, &result);
        ring_line("Q6 incomplete first", s, 0, NULL);
        send_packet(s, retry, sizeof retry, 1100, &result);
        ring_line("Q6 retry ignored", s, 0, NULL);
        send_packet(s, initial, initial_len, 1200, &result);
        ring_line("Q6 named-after-retry", s, 1, result.quic_name);
        d2k_session_free(s);
    }

    /* Q7: разрез payload на две посылки для UDP — порча, отказ целиком. */
    {
        uint8_t plan_bytes[256];
        size_t plan_len = split_plan(plan_bytes);
        d2k_session *s = d2k_session_new(64, 0);
        install_plan(s, "example.com", plan_bytes, plan_len);
        send_one("Q7 split-payload first", s, initial, initial_len, 1000);
        d2k_session_free(s);
    }

    /* Q8: исполнитель вернул HOLD — оригинал удержать нельзя, отказ без
       единой посылки, вердикт ACCEPT. */
    {
        uint8_t plan_bytes[256];
        size_t plan_len = quic_plan(plan_bytes);
        d2k_session *s = d2k_session_new(64, 0);
        install_plan(s, "example.com", plan_bytes, plan_len);
        g_hold_mode = 1;
        send_one("Q8 hold-fate first", s, initial, initial_len, 1000);
        g_hold_mode = 0;
        d2k_session_free(s);
    }
    return 0;
}
