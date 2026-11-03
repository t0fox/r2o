#define main d2k_test_session_main
#include "test_session.c"
#undef main

static uint64_t hello_hash(const uint8_t *bytes, size_t len) {
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < len; i++) {
        hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
    }
    return hash;
}

static int capture_case(const char *label, int split) {
    d2k_session *session = d2k_session_new(64, 64);
    if (!session) { return 1; }
    uint8_t packet[4096], output[8192], hello[4096];
    d2k_result result;
    d2k_payload_stats stats;
    const uint16_t port = 43040;
    const size_t hello_len = build_hello(hello);
    memset(hello + 11, 0, 32);

    size_t packet_len = build_pkt(packet, port, 0x02, NULL, 0);
    wr32(packet + 24, 1000);
    d2k_session_packet_probe(session, packet, packet_len, 1, output, sizeof output, &result);
    if (split) {
        packet_len = build_pkt(packet, port, 0x18, hello, 5);
        wr32(packet + 24, 1001);
        d2k_session_packet_probe(session, packet, packet_len, 2, output, sizeof output, &result);
        packet_len = build_pkt(packet, port, 0x18, hello + 5, hello_len - 5);
        wr32(packet + 24, 1006);
        d2k_session_packet_probe(session, packet, packet_len, 3, output, sizeof output, &result);
    } else {
        packet_len = build_pkt(packet, port, 0x18, hello, hello_len);
        wr32(packet + 24, 1001);
        d2k_session_packet_probe(session, packet, packet_len, 2, output, sizeof output, &result);
    }

    d2k_session_payload_stats(session, &stats);
    printf("%s hello=%016llx complete=%llu rejected=%llu expired=%llu full=%llu\n",
           label, (unsigned long long)hello_hash(hello, hello_len),
           (unsigned long long)stats.capture_complete,
           (unsigned long long)stats.capture_rejected,
           (unsigned long long)stats.capture_expired,
           (unsigned long long)stats.capture_full);
    const int failed = stats.capture_complete != 1 || stats.capture_rejected != 0 ||
        stats.capture_expired != 0 || stats.capture_full != 0;
    d2k_session_free(session);
    return failed;
}

int main(void) {
    return capture_case("split", 1) | capture_case("single", 0);
}