#include <stdio.h>

#include "d2k_catalog.h"

int main(void) {
    static const unsigned verified_by[] = {
        D2K_VERBY_STUN,
        D2K_VERBY_VOICE_DISCOVERY,
        D2K_VERBY_PROBE_HANDSHAKE,
    };
    for (size_t i = 0; i < sizeof verified_by / sizeof verified_by[0]; i++) {
        printf("%u=%u\n", verified_by[i],
               verified_by[i] == D2K_VERBY_VOICE_DISCOVERY);
    }
    return 0;
}
