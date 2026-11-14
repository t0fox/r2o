/* C-оракул: tls_route_segment_cap (datapath/d2kd.c:123-151).
 *
 * d2kd.c включается целиком: функция статическая. Маршрутный MTU подменён
 * заглушкой d2k_raw_route_maxlen_family — проверяется только арифметика
 * предела и отбор пакетов; сам MTU уже покрыт test-route-mtu-differential.sh.
 * main d2kd.c переименован, неиспользуемые секции выбрасываются
 * --gc-sections. */
#define main d2kd_main
#include "d2kd.c"
#undef main

#include <stdio.h>

static size_t g_mtu;

size_t d2k_raw_route_maxlen_family(d2k_raw *r, const uint8_t *dst,
                                   uint8_t family) {
    (void)r;
    (void)dst;
    (void)family;
    return g_mtu;
}

static void put16(uint8_t *p, unsigned value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(0x30 + (i & 0x3f));
}

static size_t v4(uint8_t *p, size_t n, uint8_t ihl, uint8_t proto,
                 uint8_t tcp_doff, uint8_t first, uint8_t second) {
    fill(p, 96);
    p[0] = (uint8_t)(0x40 | ihl);
    put16(p + 2, (unsigned)n);
    p[8] = 64;
    p[9] = proto;
    p[12] = 192; p[13] = 0; p[14] = 2; p[15] = 1;
    p[16] = 198; p[17] = 51; p[18] = 100; p[19] = 2;
    size_t tcp = (size_t)ihl * 4u;
    put16(p + tcp, 40000);
    put16(p + tcp + 2, 443);
    p[tcp + 12] = (uint8_t)(tcp_doff << 4);
    p[tcp + tcp_doff * 4] = first;
    p[tcp + tcp_doff * 4 + 1] = second;
    return n;
}

static size_t v6(uint8_t *p, size_t n, uint8_t next, uint8_t tcp_doff,
                 uint8_t first, uint8_t second) {
    fill(p, 96);
    p[0] = 0x60;
    p[6] = next;
    p[7] = 64;
    for (int i = 0; i < 16; i++) {
        p[8 + i] = (uint8_t)(0x20 + i);
        p[24 + i] = (uint8_t)(0x40 + i);
    }
    p[40 + 12] = (uint8_t)(tcp_doff << 4);
    p[40 + tcp_doff * 4] = first;
    p[40 + tcp_doff * 4 + 1] = second;
    return n;
}

static void run(const char *name, const uint8_t *p, size_t n, size_t mtu) {
    g_mtu = mtu;
    printf("%s cap=%zu\n", name,
           tls_route_segment_cap((d2k_raw *)1, p, n));
}

int main(void) {
    uint8_t p[96];
    run("A v4-tls", p, v4(p, 60, 5, 6, 5, 0x16, 3), 1500);
    run("B v4-ihl6", p, v4(p, 64, 6, 6, 5, 0x16, 3), 1400);
    run("C v4-udp", p, v4(p, 60, 5, 17, 5, 0x16, 3), 1500);
    run("D v4-not-tls", p, v4(p, 60, 5, 6, 5, 0x17, 3), 1500);
    run("E v4-wrong-ver", p, v4(p, 60, 5, 6, 5, 0x16, 2), 1500);
    run("F v4-short-doff", p, v4(p, 60, 5, 6, 4, 0x16, 3), 1500);
    run("G v4-too-short", p, v4(p, 39, 5, 6, 5, 0x16, 3), 1500);
    run("H v4-exact", p, v4(p, 45, 5, 6, 5, 0x16, 3), 1500);
    run("I v4-small-mtu", p, v4(p, 60, 5, 6, 5, 0x16, 3), 40);
    run("J v6-tls", p, v6(p, 70, 6, 5, 0x16, 3), 1280);
    run("K v6-short", p, v6(p, 59, 6, 5, 0x16, 3), 1280);
    run("L v6-not-tcp", p, v6(p, 70, 17, 5, 0x16, 3), 1280);
    run("M v4-tls-2", p, v4(p, 60, 5, 6, 5, 0x16, 3), 1500);
    p[0] = 0x55;
    run("N bad-version", p, 60, 1500);
    return 0;
}
