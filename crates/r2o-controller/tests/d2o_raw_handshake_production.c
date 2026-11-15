/* C-оракул production-входа d2k_raw_probe_handshake_as в netns. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "raw.c"

int64_t d2k_now_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

int d2k_detect_stopped(const d2k_detect_stop *cancel)
{
    (void)cancel;
    return 0;
}

void d2k_sleep_ms(int ms) { (void)ms; }

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s FAMILY ADDRESS PORT TIMEOUT_MS\n", argv[0]);
        return 2;
    }
    uint8_t family = (uint8_t)atoi(argv[1]);
    uint8_t address[16] = {0};
    if (inet_pton(family == 6 ? AF_INET6 : AF_INET, argv[2], address) != 1) {
        fprintf(stderr, "bad address: %s\n", argv[2]);
        return 2;
    }
    char err[160] = "";
    int rc = d2k_raw_probe_handshake_as(address, family, (uint16_t)atoi(argv[3]),
                                        atoi(argv[4]), 0, NULL, 1, err, sizeof err);
    printf("%d|%s\n", rc, err);
    return 0;
}
