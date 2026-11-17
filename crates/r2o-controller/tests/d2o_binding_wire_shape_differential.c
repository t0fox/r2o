/* C-оракул: production `binding_wire_shape` из core/sched.c. */
#include "sched.c"

#include <stdio.h>
#include <string.h>

int main(void)
{
    for (int shape = 0; shape <= 13; shape++) {
        for (int transport = 0; transport <= 17; transport++) {
            if (transport != 0 && transport != 6 && transport != 17) {
                continue;
            }
            for (int profile = 0; profile <= 2; profile++) {
                d2k_cat_binding bd;
                memset(&bd, 0, sizeof bd);
                bd.shape = (uint8_t)shape;
                bd.transport = (uint8_t)transport;
                bd.tcp_profile = (uint8_t)profile;
                printf("%d,%d,%d,%u\n", shape, transport, profile,
                       (unsigned)binding_wire_shape(&bd));
            }
        }
    }
    return 0;
}
