#include <stdint.h>
#include <stdio.h>

#include "core/include/d2k_link.h"

int main(void) {
    for (int shape = 0; shape <= 15; shape++) {
        printf("%d %u %u", shape,
               (unsigned)d2k_link_shape_tcp_profile((uint8_t)shape),
               (unsigned)d2k_link_shape_tcp_base((uint8_t)shape));
        for (int profile = 0; profile <= 3; profile++) {
            printf(" %u", (unsigned)d2k_link_shape_tcp_context(
                               (uint8_t)shape, (uint8_t)profile));
        }
        printf("\n");
    }
    return 0;
}
