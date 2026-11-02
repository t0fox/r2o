#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "d2k_ipfrag.h"
#include "d2k_plan.h"

static int write_set(uint8_t family, uint8_t shape, const uint8_t *output,
                     const d2k_ipfrag_span spans[3], size_t count) {
    if (count > 3) return -1;
    uint8_t record[3] = {family, shape, (uint8_t)count};
    if (fwrite(record, 1, sizeof record, stdout) != sizeof record) return -1;
    for (size_t i = 0; i < count; i++) {
        size_t length = spans[i].len;
        uint8_t encoded_length[2] = {
            (uint8_t)(length >> 8),
            (uint8_t)length
        };
        if (fwrite(encoded_length, 1, sizeof encoded_length, stdout) != sizeof encoded_length ||
            fwrite(output + spans[i].off, 1, length, stdout) != length) return -1;
    }
    return 0;
}

static int emit_ipv4(const uint8_t payload[1200]) {
    const uint8_t src[4] = {192, 0, 2, 1};
    const uint8_t dst[4] = {198, 51, 100, 2};
    uint8_t output[4096];
    for (uint8_t shape = 1; shape <= 4; shape++) {
        d2k_ipfrag_plan plan;
        d2k_ipfrag_span spans[3];
        if (d2k_ipfrag_shape(shape, &plan) != 0) return -1;
        size_t count = d2k_udpfrag_build_ex(
            src, dst, 51234, 443, payload, 1200, &plan, 0x1234, 57, 0xa5,
            output, sizeof output, spans);
        if (!count || write_set(4, shape, output, spans, count) != 0) return -1;
    }
    return 0;
}

static int emit_ipv6(const uint8_t payload[1200]) {
    const uint8_t src[16] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 1};
    const uint8_t dst[16] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 2};
    uint8_t output[4096];
    for (uint8_t shape = 1; shape <= 4; shape++) {
        d2k_ipfrag_plan plan;
        d2k_ipfrag_span spans[3];
        if (d2k_ipfrag_shape(shape, &plan) != 0) return -1;
        size_t count = d2k_udpfrag6_build_ex(
            src, dst, 51234, 443, payload, 1200, &plan, 0x12345678, 57,
            0xab, 0x12345, output, sizeof output, spans);
        if (!count || write_set(6, shape, output, spans, count) != 0) return -1;
    }
    return 0;
}

static int emit_capacity_case(uint8_t family, uint8_t shape, size_t payload_len) {
    static const uint8_t src4[4] = {192, 0, 2, 1};
    static const uint8_t dst4[4] = {198, 51, 100, 2};
    static const uint8_t src6[16] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t dst6[16] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 2};
    uint8_t output[D2K_WIRE_BATCH_MAX * 1600u];
    d2k_ipfrag_span spans[3];
    d2k_ipfrag_plan plan;
    uint8_t *payload = malloc(payload_len);
    if (!payload || d2k_ipfrag_shape(shape, &plan) != 0) {
        free(payload);
        return -1;
    }
    for (size_t i = 0; i < payload_len; i++) payload[i] = (uint8_t)i;

    size_t count = family == 4
        ? d2k_udpfrag_build_ex(src4, dst4, 51234, 443, payload, payload_len,
                               &plan, 0x1234, 57, 0xa5, output, sizeof output, spans)
        : d2k_udpfrag6_build_ex(src6, dst6, 51234, 443, payload, payload_len,
                                &plan, 0x12345678, 57, 0xab, 0x12345,
                                output, sizeof output, spans);
    uint8_t record[6] = {
        0xca, family, shape, (uint8_t)(payload_len >> 8),
        (uint8_t)payload_len, (uint8_t)(count != 0)
    };
    free(payload);
    return fwrite(record, 1, sizeof record, stdout) == sizeof record ? 0 : -1;
}
int main(void) {
    uint8_t payload[1200];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)i;
    if (emit_ipv4(payload) != 0 || emit_ipv6(payload) != 0) return 1;
    const size_t lengths[] = {40000, 41500};
    for (size_t li = 0; li < sizeof lengths / sizeof lengths[0]; li++)
        for (uint8_t family = 4; family <= 6; family += 2)
            for (uint8_t shape = 1; shape <= 4; shape++)
                if (emit_capacity_case(family, shape, lengths[li]) != 0) return 1;
    return fflush(stdout) == 0 ? 0 : 2;
}
