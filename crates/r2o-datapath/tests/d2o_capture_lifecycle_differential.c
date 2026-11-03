#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "d2k_capture.h"

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "capture fixture line %d: %s\n", __LINE__, #expression); \
        exit(1); \
    } \
} while (0)

static d2k_key key(uint16_t port) {
    static const uint8_t low_ip[4] = {192, 0, 2, 1};
    static const uint8_t high_ip[4] = {198, 51, 100, 2};
    const uint8_t low_port[2] = {(uint8_t)(port >> 8), (uint8_t)port};
    static const uint8_t high_port[2] = {1, 187};
    d2k_key flow = {0};
    memcpy(&flow.low_ip, low_ip, sizeof low_ip);
    memcpy(&flow.high_ip, high_ip, sizeof high_ip);
    memcpy(&flow.low_port, low_port, sizeof low_port);
    memcpy(&flow.high_port, high_port, sizeof high_port);
    flow.family = 4;
    flow.proto = 6;
    return flow;
}

static void hello(uint8_t bytes[32]) {
    for (size_t i = 0; i < 32; i++) { bytes[i] = (uint8_t)i; }
    bytes[0] = 22;
    bytes[1] = 3;
    bytes[2] = 1;
    bytes[3] = 0;
    bytes[4] = 27;
    bytes[5] = 1;
    bytes[6] = 0;
    bytes[7] = 0;
    bytes[8] = 23;
}

static uint64_t hash_bytes(const uint8_t *bytes, size_t len) {
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < len; i++) {
        hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
    }
    return hash;
}

static int feed(d2k_capture *capture, const d2k_key *flow, uint64_t now,
                uint32_t sequence, uint32_t anchor, int have_anchor,
                const uint8_t *bytes, size_t len,
                const uint8_t **result, size_t *result_len, uint32_t *result_seq) {
    return d2k_capture_feed(capture, flow, 1, now, sequence, anchor, have_anchor,
                            bytes, len, result, result_len, result_seq);
}

static void reordered(void) {
    d2k_capture capture = {0};
    d2k_key flow = key(1234);
    uint8_t bytes[32];
    const uint8_t *result = NULL;
    size_t result_len = 0;
    uint32_t result_seq = 0;
    hello(bytes);

    int first = feed(&capture, &flow, 1, 116, 100, 1, bytes + 16, 16,
                     &result, &result_len, &result_seq);
    int overlap = feed(&capture, &flow, 2, 116, 100, 1, bytes + 16, 8,
                       &result, &result_len, &result_seq);
    int final_segment = feed(&capture, &flow, 3, 100, 100, 1, bytes, 16,
                             &result, &result_len, &result_seq);
    CHECK(first == 0 && overlap == 0 && final_segment == 1);
    CHECK(result && result_seq == 100 && result_len == sizeof bytes);
    CHECK(memcmp(result, bytes, sizeof bytes) == 0);
    CHECK(capture.completed == 1 && capture.rejected == 0 &&
           capture.expired == 0 && capture.full == 0);
    printf("reorder hash=%016" PRIx64 " first=%d overlap=%d final=%d seq=%" PRIu32
           " len=%zu completed=%" PRIu64 " rejected=%" PRIu64
           " expired=%" PRIu64 " full=%" PRIu64 "\n",
           hash_bytes(bytes, sizeof bytes), first, overlap, final_segment,
           result_seq, result_len, capture.completed, capture.rejected,
           capture.expired, capture.full);
}

static void expires_at_absolute_ttl(void) {
    d2k_capture capture = {0};
    d2k_key flow = key(1234);
    uint8_t bytes[32];
    const uint8_t *result = NULL;
    size_t result_len = 0;
    uint32_t result_seq = 0;
    hello(bytes);

    int first = feed(&capture, &flow, 1, 100, 0, 0, bytes, 1,
                     &result, &result_len, &result_seq);
    int retry = feed(&capture, &flow, D2K_CAPTURE_TTL_NS, 100, 0, 0, bytes, 1,
                     &result, &result_len, &result_seq);
    int tail = feed(&capture, &flow, D2K_CAPTURE_TTL_NS + 1, 101, 0, 0,
                    bytes + 1, sizeof bytes - 1, &result, &result_len, &result_seq);
    CHECK(first == 0 && retry == 0 && tail == 0);
    CHECK(capture.completed == 0 && capture.rejected == 0 &&
           capture.expired == 1 && capture.full == 0);
    printf("ttl hash=%016" PRIx64 " first=%d retry=%d tail=%d completed=%" PRIu64
           " rejected=%" PRIu64 " expired=%" PRIu64 " full=%" PRIu64 "\n",
           hash_bytes(bytes, sizeof bytes), first, retry, tail, capture.completed,
           capture.rejected, capture.expired, capture.full);
}

static void refuses_without_evicting_and_reuses_expired_slot(void) {
    d2k_capture capture = {0};
    uint8_t bytes[32];
    const uint8_t *result = NULL;
    size_t result_len = 0;
    uint32_t result_seq = 0;
    hello(bytes);

    for (size_t i = 0; i < D2K_CAPTURE_SLOTS; i++) {
        d2k_key flow = key((uint16_t)(1000 + i));
        CHECK(feed(&capture, &flow, 1, 100, 0, 0, bytes, 1,
                    &result, &result_len, &result_seq) == 0);
    }
    d2k_key refused_flow = key(2000);
    int refused = feed(&capture, &refused_flow, 2, 100, 0, 0, bytes, sizeof bytes,
                      &result, &result_len, &result_seq);
    d2k_key active_flow = key(1000);
    int active = feed(&capture, &active_flow, 3, 101, 0, 0, bytes + 1,
                      sizeof bytes - 1, &result, &result_len, &result_seq);
    CHECK(refused == -2 && active == 1);
    CHECK(result && result_seq == 100 && result_len == sizeof bytes);
    CHECK(memcmp(result, bytes, sizeof bytes) == 0);

    int reused = feed(&capture, &refused_flow, D2K_CAPTURE_TTL_NS + 1, 100,
                      0, 0, bytes, sizeof bytes, &result, &result_len, &result_seq);
    CHECK(reused == 1 && result && result_seq == 100 && result_len == sizeof bytes);
    CHECK(memcmp(result, bytes, sizeof bytes) == 0);
    CHECK(capture.completed == 2 && capture.rejected == 0 &&
           capture.expired == D2K_CAPTURE_SLOTS - 1 && capture.full == 1);
    printf("full hash=%016" PRIx64 " refused=%d active=%d reused=%d completed=%" PRIu64
           " rejected=%" PRIu64 " expired=%" PRIu64 " full=%" PRIu64 "\n",
           hash_bytes(bytes, sizeof bytes), refused, active, reused,
           capture.completed, capture.rejected, capture.expired, capture.full);
}

int main(void) {
    reordered();
    expires_at_absolute_ttl();
    refuses_without_evicting_and_reuses_expired_slot();
    return 0;
}