/* C-оракул: d2k_wire_build (datapath/wire.c:109-277) — legacy wire_profile=0.
 *
 * Входной пакет и d2k_conn строятся из одних и тех же полей; Rust получает
 * тот же пакет. Печатаются rc/len/hex. */
#include <stdio.h>
#include <string.h>

#include "d2k_wire.h"

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static size_t input4(uint8_t *packet) {
    size_t total = 40 + 4;
    memset(packet, 0, total);
    packet[0] = 0x45;
    wr16(packet + 2, (uint16_t)total);
    wr16(packet + 4, 0x1234);
    packet[8] = 63;
    packet[9] = 6;
    packet[12] = 192; packet[13] = 0; packet[14] = 2; packet[15] = 10;
    packet[16] = 198; packet[17] = 51; packet[18] = 100; packet[19] = 20;
    wr16(packet + 20, 40000);
    wr16(packet + 22, 443);
    wr32(packet + 24, 1000);
    wr32(packet + 28, 777);
    packet[32] = 5 << 4;
    packet[33] = 0x18;
    wr16(packet + 34, 50240);
    memcpy(packet + 40, "orig", 4);
    return total;
}

static size_t input6(uint8_t *packet) {
    size_t total = 60 + 4;
    memset(packet, 0, total);
    packet[0] = 0x60;
    wr16(packet + 4, 24);
    packet[6] = 6;
    packet[7] = 63;
    packet[8] = 0x20; packet[9] = 0x01; packet[10] = 0x0d; packet[11] = 0xb8;
    packet[23] = 1;
    packet[24] = 0x20; packet[25] = 0x01; packet[26] = 0x0d; packet[27] = 0xb8;
    packet[39] = 2;
    wr16(packet + 40, 40000);
    wr16(packet + 42, 443);
    wr32(packet + 44, 1000);
    wr32(packet + 48, 777);
    packet[52] = 5 << 4;
    packet[53] = 0x18;
    wr16(packet + 54, 50240);
    memcpy(packet + 60, "orig", 4);
    return total;
}

static d2k_conn conn_from(const uint8_t *packet, int family) {
    d2k_conn c;
    memset(&c, 0, sizeof c);
    c.family = (uint8_t)family;
    if (family == 4) {
        memcpy(&c.src_ip, packet + 12, 4);
        memcpy(&c.dst_ip, packet + 16, 4);
        c.ttl = packet[8];
        c.ip_id = rd16(packet + 4);
        memcpy(&c.src_port, packet + 20, 2);
        memcpy(&c.dst_port, packet + 22, 2);
        c.ack = rd32(packet + 28);
        c.window = rd16(packet + 34);
    } else {
        memcpy(c.src_ip6, packet + 8, 16);
        memcpy(c.dst_ip6, packet + 24, 16);
        c.ttl = packet[7];
        memcpy(&c.src_port, packet + 40, 2);
        memcpy(&c.dst_port, packet + 42, 2);
        c.ack = rd32(packet + 48);
        c.window = rd16(packet + 54);
    }
    return c;
}

static void run(const char *name, int family, uint8_t ttl, uint8_t poison,
                int32_t seq_shift, const uint8_t *pre, size_t pre_len,
                uint8_t urgent, uint16_t urgent_ptr, const uint8_t *bytes,
                size_t len, size_t cap) {
    uint8_t packet[128];
    size_t packet_len = family == 6 ? input6(packet) : input4(packet);
    (void)packet_len;
    d2k_conn c = conn_from(packet, family);
    d2k_emit e;
    memset(&e, 0, sizeof e);
    e.kind = D2K_EMIT_PAYLOAD;
    e.seq = 1000;
    e.ttl = ttl;
    e.poison = poison;
    e.seq_shift = seq_shift;
    e.wire_profile = 0;
    e.urgent = urgent;
    e.urgent_ptr = urgent_ptr;
    e.pre = pre;
    e.pre_len = pre_len;
    e.bytes = bytes;
    e.len = len;
    uint8_t out[512];
    size_t rc = d2k_wire_build(&c, &e, out, cap);
    printf("%s len=%zu hex=", name, rc);
    for (size_t i = 0; i < rc; i++) printf("%02x", out[i]);
    printf("\n");
}

int main(void) {
    static const uint8_t payload[] = "hello";
    static const uint8_t pre[] = "ab";
    static const uint8_t body[] = "cd";
    static const uint8_t abcd[] = "abcd";

    run("A ipv4", 4, 0, 0, 0, NULL, 0, 0, 0, payload, sizeof payload - 1, 512);
    run("B shift-prefix", 4, 0, 0, -5, pre, sizeof pre - 1, 0, 0, body,
        sizeof body - 1, 512);
    run("C ttl", 4, 8, 0, 0, NULL, 0, 0, 0, payload, sizeof payload - 1, 512);
    run("D badsum", 4, 0, D2K_POISON_BADSUM, 0, NULL, 0, 0, 0, payload,
        sizeof payload - 1, 512);
    run("E ts-back", 4, 0, D2K_POISON_TCPTS_BACK, 0, NULL, 0, 0, 0, payload,
        sizeof payload - 1, 512);
    run("F ipid-zero", 4, 0, D2K_POISON_IPID_ZERO, 0, NULL, 0, 0, 0, payload,
        sizeof payload - 1, 512);
    run("G urgent", 4, 0, 0, 0, NULL, 0, 1, 2, abcd, sizeof abcd - 1, 512);
    run("H ipv6", 6, 0, 0, 0, NULL, 0, 0, 0, payload, sizeof payload - 1, 512);
    run("I ipv6-shift-ttl", 6, 8, 0, 7, NULL, 0, 0, 0, payload,
        sizeof payload - 1, 512);
    run("J ipv6-ipid-zero", 6, 0, D2K_POISON_IPID_ZERO, 0, NULL, 0, 0, 0,
        payload, sizeof payload - 1, 512);
    run("K urgent-bad", 4, 0, 0, 0, NULL, 0, 1, 9, abcd, sizeof abcd - 1, 512);
    run("L cap-small", 4, 0, 0, 0, NULL, 0, 0, 0, payload, sizeof payload - 1,
        40);
    return 0;
}
