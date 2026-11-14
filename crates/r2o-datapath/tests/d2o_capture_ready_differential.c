/* C-оракул: d2k_capture_feed (capture.c:22-124) — ранняя сборка TLS. */
#include <stdio.h>
#include <string.h>

#include "d2k_capture.h"

#define HELLO_LEN 20

static uint8_t hello_bytes[HELLO_LEN];

static void make_hello(void) {
    for (size_t i = 0; i < HELLO_LEN; i++) hello_bytes[i] = (uint8_t)i;
    hello_bytes[0] = 22;
    hello_bytes[1] = 3;
    hello_bytes[2] = 1;
    hello_bytes[3] = 0;
    hello_bytes[4] = HELLO_LEN - 5;
    hello_bytes[5] = 1;
    hello_bytes[6] = 0;
    hello_bytes[7] = 0;
    hello_bytes[8] = HELLO_LEN - 9;
}

static d2k_key make_key(void) {
    d2k_key key;
    d2k_addr source, destination;
    memset(&source, 0, sizeof source);
    memset(&destination, 0, sizeof destination);
    source.family = 4;
    destination.family = 4;
    source.bytes[0] = 192; source.bytes[1] = 0; source.bytes[2] = 2; source.bytes[3] = 10;
    destination.bytes[0] = 198; destination.bytes[1] = 51; destination.bytes[2] = 100;
    destination.bytes[3] = 20;
    uint8_t sports[2] = {0xC3, 0x50};
    uint8_t dports[2] = {0x01, 0xBB};
    (void)d2k_key_make_addr(&key, 6, &source, &destination, sports, dports);
    return key;
}

static void print_result(const char *name, int rc, size_t len, uint32_t seq,
                         const d2k_capture *capture) {
    printf("%s rc=%d len=%zu seq=%u rejected=%llu completed=%llu expired=%llu full=%llu\n",
           name, rc, len, seq,
           (unsigned long long)capture->rejected,
           (unsigned long long)capture->completed,
           (unsigned long long)capture->expired,
           (unsigned long long)capture->full);
}

static int feed(d2k_capture *c, const d2k_key *key, uint64_t generation,
                uint64_t now, uint32_t seq, uint32_t anchor, int have_anchor,
                const uint8_t *bytes, size_t len, size_t *out_len, uint32_t *out_seq) {
    const uint8_t *hello = NULL;
    *out_len = 0;
    *out_seq = 0;
    int rc = d2k_capture_feed(c, key, generation, now, seq, anchor, have_anchor,
                              bytes, len, &hello, out_len, out_seq);
    return rc;
}

int main(void) {
    make_hello();
    d2k_key key = make_key();
    size_t len;
    uint32_t seq;
    d2k_capture capture;

    memset(&capture, 0, sizeof capture);
    int rc = feed(&capture, &key, 1, 1000, 1000, 1000, 1, hello_bytes, HELLO_LEN,
                  &len, &seq);
    print_result("A complete", rc, len, seq, &capture);

    memset(&capture, 0, sizeof capture);
    (void)feed(&capture, &key, 1, 1000, 1000, 1000, 1, hello_bytes, 10, &len, &seq);
    rc = feed(&capture, &key, 1, 1001, 1010, 1000, 1, hello_bytes + 10, 10, &len, &seq);
    print_result("B split", rc, len, seq, &capture);

    memset(&capture, 0, sizeof capture);
    (void)feed(&capture, &key, 1, 1000, 1000, 1000, 1, hello_bytes, 10, &len, &seq);
    rc = feed(&capture, &key, 1, 1001, 1010, 1000, 1, hello_bytes + 10, 10, &len, &seq);
    int rc2 = feed(&capture, &key, 1, 1002, 1000, 1000, 1, hello_bytes, HELLO_LEN,
                   &len, &seq);
    print_result("C retransmit", rc2, len, seq, &capture);

    memset(&capture, 0, sizeof capture);
    (void)feed(&capture, &key, 1, 1000, 1000, 1000, 1, hello_bytes, 10, &len, &seq);
    uint8_t conflict[10];
    memcpy(conflict, hello_bytes + 10, 10);
    conflict[0] ^= 0xFF;
    rc = feed(&capture, &key, 1, 1001, 1010, 1000, 1, conflict, 10, &len, &seq);
    print_result("D conflict", rc, len, seq, &capture);

    memset(&capture, 0, sizeof capture);
    rc = feed(&capture, &key, 1, 1000, 1000, 1000, 0, hello_bytes, HELLO_LEN,
              &len, &seq);
    print_result("E no-anchor head", rc, len, seq, &capture);

    memset(&capture, 0, sizeof capture);
    uint8_t not_tls[HELLO_LEN];
    memcpy(not_tls, hello_bytes, HELLO_LEN);
    not_tls[0] = 'G';
    rc = feed(&capture, &key, 1, 1000, 1000, 1000, 0, not_tls, HELLO_LEN,
              &len, &seq);
    print_result("F no-anchor tail", rc, len, seq, &capture);

    memset(&capture, 0, sizeof capture);
    rc = feed(&capture, &key, 1, 1000, 6000, 1000, 1, hello_bytes, HELLO_LEN,
              &len, &seq);
    print_result("G far anchor", rc, len, seq, &capture);

    memset(&capture, 0, sizeof capture);
    (void)feed(&capture, &key, 1, 1000, 1000, 1000, 1, hello_bytes, 10, &len, &seq);
    rc = feed(&capture, &key, 1, 1000 + 5000000000ull, 1010, 1000, 1,
              hello_bytes + 10, 10, &len, &seq);
    print_result("H ttl", rc, len, seq, &capture);

    memset(&capture, 0, sizeof capture);
    (void)feed(&capture, &key, 1, 1000, 1000, 1000, 1, hello_bytes, 10, &len, &seq);
    rc = feed(&capture, &key, 2, 1001, 1000, 1000, 1, hello_bytes, HELLO_LEN,
              &len, &seq);
    print_result("I generation", rc, len, seq, &capture);

    memset(&capture, 0, sizeof capture);
    (void)feed(&capture, &key, 1, 1000, 0xFFFFFFF0, 0xFFFFFFF0, 1,
               hello_bytes, 16, &len, &seq);
    rc = feed(&capture, &key, 1, 1001, 0, 0xFFFFFFF0, 1,
              hello_bytes + 16, 4, &len, &seq);
    print_result("J wrap", rc, len, seq, &capture);

    memset(&capture, 0, sizeof capture);
    (void)feed(&capture, &key, 1, 1000, 1000, 1000, 1, hello_bytes, 10, &len, &seq);
    (void)feed(&capture, &key, 1, 1001, 1010, 1000, 1, conflict, 10, &len, &seq);
    rc = feed(&capture, &key, 1, 1002, 1000, 1000, 1, hello_bytes, HELLO_LEN,
              &len, &seq);
    print_result("K rejected-retry", rc, len, seq, &capture);
    return 0;
}
