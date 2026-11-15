/* C-оракул инвариантов udp_next_fragment_id (core/udpruntime.c:22-30). */
#include <stdint.h>
#include <stdio.h>

#include "d2k_udpruntime.h"
#include "udpruntime.c"

int main(void) {
    uint32_t ids[32];
    uint32_t bad_step = 0, low16_zero = 0, zero = 0;
    for (unsigned i = 0; i < 32; i++) {
        ids[i] = udp_next_fragment_id();
        if (!ids[i]) zero++;
        if (!(uint16_t)ids[i]) low16_zero++;
        if (i > 0) {
            uint32_t expected1 = ids[i - 1] + 1;
            uint32_t expected2 = ids[i - 1] + 2;
            if (ids[i] != expected1 && ids[i] != expected2) bad_step++;
        }
    }
    unsigned unique = 0;
    for (unsigned i = 0; i < 32; i++) {
        unsigned seen = 0;
        for (unsigned j = 0; j < i; j++) {
            if (ids[i] == ids[j]) { seen = 1; break; }
        }
        if (!seen) unique++;
    }
    printf("calls=32 unique=%u low16_zero=%u bad_step=%u zero=%u\n",
           unique, low16_zero, bad_step, zero);
    return 0;
}
