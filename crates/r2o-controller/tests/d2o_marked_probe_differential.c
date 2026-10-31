#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "d2k_meas.h"
#include "test_stand.h"

int main(void) {
    struct stand server = {0};
    uint16_t port = stand_start(&server, 0);
    if (!port) {
        fputs("failed to start D2O TCP fixture\n", stderr);
        return 2;
    }

    uint8_t bytes[64];
    memset(bytes, 0xaa, sizeof bytes);
    memcpy(bytes, d2k_test_sig, sizeof d2k_test_sig);
    d2k_hello hello = {bytes, sizeof bytes, NULL, 0, 0, 0};
    d2k_tally result = d2k_meas("127.0.0.1", port, hello, NULL, 0, 0, 700,
                                0x2d, d2k_accept_serverhello, 1);
    printf("marked=%d accepted=%d\n", result.marked, result.pass == 1);
    return result.pass == 1 ? 0 : 1;
}
