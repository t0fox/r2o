/* C-оракул сборки IPv6-фрагментов без отправки (core/ipfrag.c:91-130).
 *
 * Проверяются fragment header (next=44, id, offset/M), порядок форм 1-4,
 * длины и байты; сокеты и CAP_NET_RAW не нужны. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_ipfrag.h"

static void print_hex(const uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
    printf("\n");
}

int main(void) {
    static const uint8_t src[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t dst[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    uint8_t payload[64];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(i * 7 + 3);
    uint8_t out[1024];
    d2k_ipfrag_span spans[3];

    for (int shape = 1; shape <= 4; shape++) {
        d2k_ipfrag_plan plan;
        if (d2k_ipfrag_shape(shape, &plan) != 0) return 2;
        uint32_t id = 0x12345000u + (uint32_t)shape;
        size_t count = d2k_udpfrag6_build_ex(src, dst, 40000, 443, payload,
                                             sizeof payload, &plan, id, 48,
                                             0x2e, 0x12345, out, sizeof out,
                                             spans);
        printf("shape%d_count %zu\n", shape, count);
        if (!count) return 2;
        int nonzero = 1;
        int same = 1;
        for (size_t i = 0; i < count; i++) {
            printf("shape%d_%zu ", shape, i);
            print_hex(out + spans[i].off, spans[i].len);
            uint32_t got = (uint32_t)out[spans[i].off + 44] << 24 |
                           (uint32_t)out[spans[i].off + 45] << 16 |
                           (uint32_t)out[spans[i].off + 46] << 8 |
                           out[spans[i].off + 47];
            if (got == 0) nonzero = 0;
            if (got != id) same = 0;
        }
        printf("shape%d_ids nonzero=%d same=%d\n", shape, nonzero, same);
    }
    return 0;
}
