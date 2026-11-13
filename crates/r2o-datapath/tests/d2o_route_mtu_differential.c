/* C/Rust differential: route_mtu (datapath/raw.c:140-176). */
#include <stdio.h>
#include <string.h>

#include "raw.c"

int main(void) {
    uint8_t v4[4] = {127, 0, 0, 1};
    uint8_t v6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    printf("v4 %zu\n", route_mtu(0, v4, 4));
    printf("v6 %zu\n", route_mtu(0, v6, 6));
    printf("bad %zu\n", route_mtu(0, v4, 5));
    return 0;
}
