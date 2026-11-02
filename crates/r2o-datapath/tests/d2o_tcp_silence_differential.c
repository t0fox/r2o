#define main d2o_test_session_main
#include "test_session.c"
#undef main

static int silent_suspect(const d2k_session *session) {
    const d2k_jrn_entry *entry = last_suspect(session);
    return entry && entry->code == D2K_SUSPECT_SILENT;
}

/* Seed through production APIs so fixtures do not depend on test-only helpers. */
static uint64_t d2o_tcp_silence_seed(d2k_session *session, uint16_t port,
                                     const uint8_t *hello, size_t hello_len,
                                     uint64_t rtt_ns, int server_empty_ack) {
    uint8_t pkt[1024], out[4096];
    d2k_result result;
    size_t n = cut_seq(pkt, build_pkt(pkt, port, 0x02, NULL, 0), 999, 0);
    d2k_session_packet(session, pkt, n, 0, out, sizeof out, &result);
    n = cut_seq(pkt, build_rev_pkt(pkt, port, 0x12, NULL, 0), 4999, 1000);
    d2k_session_packet(session, pkt, n, rtt_ns, out, sizeof out, &result);
    uint64_t hello_ns = rtt_ns + 10000000ull;
    n = cut_seq(pkt, build_pkt(pkt, port, 0x18, hello, hello_len), 1000, 5000);
    d2k_session_packet(session, pkt, n, hello_ns, out, sizeof out, &result);
    if (server_empty_ack) {
        n = cut_seq(pkt, build_rev_pkt(pkt, port, 0x10, NULL, 0),
                    5000, 1000 + (uint32_t)hello_len);
        d2k_session_packet(session, pkt, n, hello_ns + 10000000ull,
                           out, sizeof out, &result);
    }
    return hello_ns;
}

int main(void) {
    const uint64_t ms = 1000000ull;
    const uint64_t sec = 1000000000ull;
    uint8_t hello[512], pkt[1024], out[4096];
    const size_t hello_len = build_hello(hello);
    d2k_result result;
    int sweep, duplicate, expiry, expiry_silent;
    int fin_early, fin_late, rst_early, rst_late, retry, retry_silent;
    int isolated;

    d2k_session *session = d2k_session_new(16, 32);
    if (!session) return 1;
    uint64_t hello_ns = d2o_tcp_silence_seed(session, 45101, hello, hello_len, 20 * ms, 1);
    sweep = d2k_session_sweep(session, hello_ns + 1500 * ms) == 1;
    duplicate = d2k_session_sweep(session, hello_ns + 3 * sec) == 0;
    d2k_session_free(session);

    session = d2k_session_new(16, 32);
    if (!session) return 1;
    hello_ns = d2o_tcp_silence_seed(session, 45102, hello, hello_len, 20 * ms, 1);
    expiry = d2k_session_expire(session, hello_ns + 120 * sec + 100 * ms, 120 * sec) == 1;
    expiry_silent = silent_suspect(session);
    d2k_session_free(session);

    const uint8_t close_flags[] = {0x11, 0x14};
    for (size_t i = 0; i < sizeof close_flags; i++) {
        const uint16_t port = (uint16_t)(45110 + i);
        session = d2k_session_new(16, 32);
        if (!session) return 1;
        hello_ns = d2o_tcp_silence_seed(session, port, hello, hello_len, 20 * ms, 1);
        size_t n = cut_seq(pkt, build_pkt(pkt, port, close_flags[i], NULL, 0),
                           1000 + (uint32_t)hello_len, 5000);
        d2k_session_packet(session, pkt, n, hello_ns + 500 * ms, out, sizeof out, &result);
        int early = silent_suspect(session);
        if (d2k_session_suspects(session) != 0) return 1;
        d2k_session_free(session);

        session = d2k_session_new(16, 32);
        if (!session) return 1;
        hello_ns = d2o_tcp_silence_seed(session, (uint16_t)(port + 10), hello, hello_len, 20 * ms, 1);
        n = cut_seq(pkt, build_pkt(pkt, (uint16_t)(port + 10), close_flags[i], NULL, 0),
                    1000 + (uint32_t)hello_len, 5000);
        d2k_session_packet(session, pkt, n, hello_ns + 1500 * ms, out, sizeof out, &result);
        int late = silent_suspect(session);
        d2k_session_free(session);

        if (i == 0) { fin_early = early; fin_late = late; }
        else { rst_early = early; rst_late = late; }
    }

    session = d2k_session_new(16, 32);
    if (!session) return 1;
    hello_ns = d2o_tcp_silence_seed(session, 45130, hello, hello_len, 200 * ms, 0);
    size_t n = cut_seq(pkt, build_pkt(pkt, 45130, 0x18, hello, hello_len), 1000, 5000);
    d2k_session_packet(session, pkt, n, hello_ns + 1100 * ms, out, sizeof out, &result);
    retry = d2k_session_sweep(session, hello_ns + 1200 * ms) == 1;
    retry_silent = silent_suspect(session);
    d2k_session_free(session);

    session = d2k_session_new(16, 32);
    if (!session) return 1;
    n = cut_seq(pkt, build_pkt(pkt, 45140, 0x02, NULL, 0), 999, 0);
    d2k_session_packet(session, pkt, n, 0, out, sizeof out, &result);
    n = cut_seq(pkt, build_rev_pkt(pkt, 45140, 0x12, NULL, 0), 4999, 1000);
    d2k_session_packet(session, pkt, n, 20 * ms, out, sizeof out, &result);
    n = cut_seq(pkt, build_pkt(pkt, 45141, 0x02, NULL, 0), 999, 0);
    d2k_session_packet(session, pkt, n, 30 * ms, out, sizeof out, &result);
    n = cut_seq(pkt, build_pkt(pkt, 45141, 0x18, hello, hello_len), 1000, 5000);
    d2k_session_packet(session, pkt, n, 40 * ms, out, sizeof out, &result);
    d2k_session_expire(session, 120 * sec + 140 * ms, 120 * sec);
    isolated = d2k_session_suspects(session) == 0;
    d2k_session_free(session);

    printf("sweep=%d duplicate=%d expiry=%d expiry_silent=%d "
           "fin_early=%d fin_late=%d rst_early=%d rst_late=%d "
           "retry=%d retry_silent=%d isolated=%d\n",
           sweep, duplicate, expiry, expiry_silent, fin_early, fin_late,
           rst_early, rst_late, retry, retry_silent, isolated);
    return 0;
}
