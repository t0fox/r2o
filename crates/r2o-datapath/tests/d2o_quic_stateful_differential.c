/* C stateful QUIC handle_udp fixture: plan-applied skip, name/shape, ring. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "session.c"

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

static size_t quic_plan(uint8_t *out) {
    static const uint8_t id[16] = {0x51,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    static const uint8_t transport[2] = {17,2};
    static const uint8_t one[1] = {1};
    memcpy(out, "D2KP", 4);
    out[4]=0; out[5]=1; out[6]=0; out[7]=10; out[8]=0; out[9]=0;
    out[10]=0; out[11]=3;
    size_t off = 12;
    const uint8_t *values[] = {id, transport, one};
    const uint16_t kinds[] = {0x0001, 0x0002, 0x010f};
    const size_t lengths[] = {16, 2, 1};
    for (unsigned i = 0; i < 3; i++) {
        out[off++] = (uint8_t)(kinds[i] >> 8); out[off++] = (uint8_t)kinds[i];
        out[off++] = (uint8_t)(lengths[i] >> 8); out[off++] = (uint8_t)lengths[i];
        memcpy(out + off, values[i], lengths[i]); off += lengths[i];
    }
    return off;
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
    printf("%s applied=%d skip=%d skipped=\"%s\" n=%zu plan_done=%d sends_left=%u ring=%zu qsnap=%d quic_name=\"%s\" shape_miss=%d\n",
           name, r->applied ? 1 : 0,
           r->skipped && r->skipped[0] ? 1 : 0,
           r->skipped ? r->skipped : "",
           r->n_out, flow ? flow->plan_done : 0,
           flow ? flow->sends_left : 0, s->init_ring_n,
           flow ? flow->qsnap_done : 0, r->quic_name, r->quic_shape_miss);
}

static void run_flow(const char *name, d2k_session *s, const uint8_t *payload,
                     size_t payload_len, int install_plan) {
    static const uint8_t client[4] = {192,0,2,10};
    static const uint8_t server[4] = {198,51,100,20};
    uint8_t buffer[2048];
    uint8_t out[4096];
    d2k_result result;
    size_t n;
    if (install_plan) {
        d2k_plan *plan = NULL;
        char error[200];
        uint8_t plan_bytes[256];
        size_t plan_len = quic_plan(plan_bytes);
        if (d2k_plan_load(plan_bytes, plan_len, &plan, error, sizeof error) != 0) {
            printf("%s load-error=%s\n", name, error); return;
        }
        const char *host = "example.com";
        if (d2k_plantab_set_name_family(d2k_session_plans(s),
                (const uint8_t *)host, strlen(host), 1000, plan,
                D2K_PLAN_SHAPE_QUIC, 0, 4) != 0) {
            printf("%s install-error\n", name); return;
        }
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

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    uint8_t initial[2048], unnamed[2048];
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 3;
    size_t initial_len = fread(initial, 1, sizeof initial, f);
    fclose(f);
    f = fopen(argv[2], "rb");
    if (!f) return 3;
    size_t unnamed_len = fread(unnamed, 1, sizeof unnamed, f);
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
    return 0;
}
