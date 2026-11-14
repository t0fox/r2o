/* C/Rust differential: d2k_raw_prepare context validation (a378). */
#include <stdio.h>
#include <string.h>

#include "raw.c"

static void wr16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void run(const char *name, const uint8_t *packet, size_t length) {
    d2k_raw raw;
    memset(&raw, 0, sizeof raw);
    raw.fd = -1;
    raw.fd6 = -1;
    raw.fragment_fd = -1;
    raw.maxlen = 1500;
    char error[128];
    int rc = d2k_raw_prepare(&raw, packet, length, error, sizeof error);
    printf("%s rc=%d\n", name, rc < 0 ? -1 : 0);
    if (raw.fd6 >= 0) close(raw.fd6);
    if (raw.fragment_fd >= 0) close(raw.fragment_fd);
}

int main(void) {
    uint8_t udp[36];
    memset(udp, 0, sizeof udp);
    udp[0] = 0x45;
    wr16(udp + 2, sizeof udp);
    wr16(udp + 4, 9);
    udp[8] = 64;
    udp[9] = 17;
    udp[12] = 192; udp[13] = 0; udp[14] = 2; udp[15] = 1;
    udp[16] = 198; udp[17] = 51; udp[18] = 100; udp[19] = 2;
    wr16(udp + 20, 51234);
    wr16(udp + 22, 443);
    wr16(udp + 24, 16);
    run("ipv4_plain", udp, sizeof udp);

    uint8_t bad_version[36];
    memcpy(bad_version, udp, sizeof udp);
    bad_version[0] = 0x75;
    run("ipv4_bad_version", bad_version, sizeof bad_version);

    uint8_t fragment[36];
    memcpy(fragment, udp, sizeof udp);
    wr16(fragment + 6, 0x2000);
    fragment[9] = 6;
    run("fragment_bad_proto", fragment, sizeof fragment);

    memcpy(fragment, udp, sizeof udp);
    wr16(fragment + 6, 0x2000);
    wr16(fragment + 4, 0);
    run("fragment_zero_id", fragment, sizeof fragment);

    memcpy(fragment, udp, sizeof udp);
    wr16(fragment + 6, 0x2000);
    fragment[0] = 0x46;
    run("fragment_ihl6", fragment, sizeof fragment);

    uint8_t ipv6_bad[56];
    memset(ipv6_bad, 0, sizeof ipv6_bad);
    ipv6_bad[0] = 0x60;
    wr16(ipv6_bad + 4, 8);
    ipv6_bad[6] = 17;
    run("ipv6_bad_len", ipv6_bad, sizeof ipv6_bad);
    return 0;
}
