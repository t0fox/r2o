/* C-оракул: parse_ip (datapath/icmpguard.c:21-47) — разбор IP-заголовка
 * цитаты ICMP time-exceeded. icmpguard.c включается целиком: parse_ip
 * статическая; неиспользуемые секции выбрасываются --gc-sections. */
#include "icmpguard.c"

#include <stdio.h>

static void put16(uint8_t *p, unsigned value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(0x30 + (i & 0x3f));
}

static size_t v4(uint8_t *p, size_t n, uint8_t ihl, uint16_t frag,
                 uint8_t proto, uint8_t ttl, uint16_t ip_len, uint16_t id) {
    if (n > 64) n = 64;
    fill(p, 64);
    p[0] = (uint8_t)(0x40 | ihl);
    p[1] = 0;
    put16(p + 2, ip_len);
    put16(p + 4, id);
    put16(p + 6, frag);
    p[8] = ttl;
    p[9] = proto;
    p[12] = 10; p[13] = 0; p[14] = 2; p[15] = 1;
    p[16] = 10; p[17] = 0; p[18] = 2; p[19] = 2;
    return n;
}

static size_t v6(uint8_t *p, size_t n, uint8_t proto, uint8_t ttl,
                 uint16_t payload_len) {
    if (n > 64) n = 64;
    fill(p, 64);
    p[0] = 0x60;
    p[4] = (uint8_t)(payload_len >> 8);
    p[5] = (uint8_t)payload_len;
    p[6] = proto;
    p[7] = ttl;
    for (int i = 0; i < 16; i++) {
        p[8 + i] = (uint8_t)(0x20 + i);
        p[24 + i] = (uint8_t)(0x40 + i);
    }
    return n;
}

static void run(const char *name, const uint8_t *p, size_t n) {
    ipq q;
    int ok = parse_ip(p, n, &q);
    printf("%s ok=%d", name, ok);
    if (ok) {
        printf(" fam=%u proto=%u ttl=%u ip_len=%u ip_id=%u src=", q.family,
               q.proto, q.ttl, q.ip_len, q.ip_id);
        size_t address_len = q.family == 4 ? 4 : 16;
        for (size_t i = 0; i < address_len; i++) printf("%02x", q.src[i]);
        printf(" dst=");
        for (size_t i = 0; i < address_len; i++) printf("%02x", q.dst[i]);
        printf(" l4=");
        for (size_t i = 0; i < 8; i++) printf("%02x", q.l4[i]);
    }
    printf("\n");
}

int main(void) {
    uint8_t p[64];
    size_t n;

    n = v4(p, 28, 5, 0, 6, 64, 40, 1);
    run("A v4-tcp", p, n);
    n = v4(p, 28, 5, 0, 17, 63, 40, 2);
    run("B v4-udp", p, n);
    n = v4(p, 19, 5, 0, 6, 64, 40, 1);
    run("C v4-short20", p, n);
    n = v4(p, 28, 4, 0, 6, 64, 40, 1);
    run("D v4-bad-ihl", p, n);
    n = v4(p, 28, 5, 1, 6, 64, 40, 1);
    run("E v4-fragment", p, n);
    n = v4(p, 28, 5, 0, 1, 64, 40, 1);
    run("F v4-icmp-proto", p, n);
    n = v4(p, 27, 5, 0, 6, 64, 40, 1);
    run("G v4-need-l4", p, n);
    n = v4(p, 28, 5, 0x2000, 6, 64, 40, 7);
    run("H v4-mf-first", p, n);
    n = v6(p, 48, 6, 64, 8);
    run("I v6-tcp", p, n);
    n = v6(p, 39, 6, 64, 0);
    run("J v6-short", p, n);
    n = v6(p, 48, 58, 64, 8);
    run("K v6-icmpv6-proto", p, n);
    n = v6(p, 47, 6, 64, 7);
    run("L v6-need-l4", p, n);
    n = v6(p, 48, 17, 1, 8);
    run("M v6-udp-ttl1", p, n);
    n = v4(p, 1, 5, 0, 6, 64, 40, 1);
    run("N one-byte", p, n);
    run("O empty", p, 0);
    return 0;
}
