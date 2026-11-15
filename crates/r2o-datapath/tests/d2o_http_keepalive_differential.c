/* C HTTP keep-alive fixture: production d2k_session + plantab. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "session.c"

static size_t packet(uint8_t *out, uint8_t flags, uint32_t sequence,
                     const uint8_t *payload, size_t length) {
    size_t total = 40 + length;
    memset(out, 0, total);
    out[0] = 0x45;
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[8] = 64;
    out[9] = 6;
    out[12] = 192; out[13] = 0; out[14] = 2; out[15] = 10;
    out[16] = 198; out[17] = 51; out[18] = 100; out[19] = 20;
    out[20] = 0xC3; out[21] = 0x50;
    out[22] = 0x00; out[23] = 80;
    out[24] = (uint8_t)(sequence >> 24);
    out[25] = (uint8_t)(sequence >> 16);
    out[26] = (uint8_t)(sequence >> 8);
    out[27] = (uint8_t)sequence;
    out[32] = 0x50;
    out[33] = flags;
    if (length) memcpy(out + 40, payload, length);
    return total;
}

static size_t http_plan(uint8_t *out) {
    static const uint8_t id[16] = {0x61,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    static const uint8_t transport[2] = {6,4};
    static const uint8_t payload[4] = {0,1,'F','H'};
    static const uint8_t fake[10] = {0,1,0,0,1,0,0,0,0,0};
    memcpy(out, "D2KP", 4);
    out[4]=0; out[5]=1; out[6]=0; out[7]=11; out[8]=0; out[9]=0;
    out[10]=0; out[11]=4;
    size_t off = 12;
    const uint8_t *values[] = {id, transport, payload, fake};
    const uint16_t kinds[] = {0x0001, 0x0002, 0x0010, 0x0101};
    const size_t lengths[] = {16, 2, 4, 10};
    for (unsigned i = 0; i < 4; i++) {
        out[off++] = (uint8_t)(kinds[i] >> 8); out[off++] = (uint8_t)kinds[i];
        out[off++] = (uint8_t)(lengths[i] >> 8); out[off++] = (uint8_t)lengths[i];
        memcpy(out + off, values[i], lengths[i]); off += lengths[i];
    }
    return off;
}

int main(void) {
    static const uint8_t get1[] = "GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n";
    static const uint8_t get2[] = "GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n";
    d2k_session *s = d2k_session_new(64, 0);
    d2k_plan *plan = NULL;
    char error[200];
    uint8_t plan_bytes[256];
    uint8_t buffer[2048];
    uint8_t out[4096];
    d2k_result result;
    size_t plan_len = http_plan(plan_bytes);
    if (d2k_plan_load(plan_bytes, plan_len, &plan, error, sizeof error) != 0) {
        printf("load-error=%s\n", error); return 1;
    }
    const char *host = "example.test";
    if (d2k_plantab_set_name_family(d2k_session_plans(s), (const uint8_t *)host,
            strlen(host), 1000, plan, D2K_PLAN_SHAPE_HTTP, 0, 4) != 0) {
        printf("install-error\n"); return 1;
    }
    d2k_key key;
    static const uint8_t src[4] = {192,0,2,10};
    static const uint8_t dst[4] = {198,51,100,20};
    static const uint8_t sport[2] = {0xC3,0x50};
    static const uint8_t dport[2] = {0x00,0x50};
    (void)d2k_key_make(&key, 6, src, dst, sport, dport);

    size_t n = packet(buffer, 0x02, 1000, NULL, 0);
    (void)d2k_session_packet(s, buffer, n, 1000, out, sizeof out, &result);
    n = packet(buffer, 0x18, 1001, get1, sizeof get1 - 1);
    memset(&result, 0, sizeof result);
    (void)d2k_session_packet(s, buffer, n, 1001, out, sizeof out, &result);
    d2k_flow *flow = d2k_track_find(s->flows, &key);
    printf("first applied=%d n=%zu skip=%d plan_done=%d sends_left=%u\n",
           result.applied ? 1 : 0, result.n_out,
           result.skipped && result.skipped[0] ? 1 : 0,
           flow ? flow->plan_done : 0, flow ? flow->sends_left : 0);
    if (flow) {
        while (flow->sends_left) {
            (void)d2k_session_sent(s, 1002, &key, flow->execution_id);
            flow = d2k_track_find(s->flows, &key);
        }
    }
    n = packet(buffer, 0x18, 1001 + (uint32_t)(sizeof get1 - 1), get2,
               sizeof get2 - 1);
    memset(&result, 0, sizeof result);
    (void)d2k_session_packet(s, buffer, n, 1002, out, sizeof out, &result);
    flow = d2k_track_find(s->flows, &key);
    printf("second applied=%d n=%zu skip=%d plan_done=%d sends_left=%u\n",
           result.applied ? 1 : 0, result.n_out,
           result.skipped && result.skipped[0] ? 1 : 0,
           flow ? flow->plan_done : 0, flow ? flow->sends_left : 0);
    d2k_session_free(s);
    return 0;
}
