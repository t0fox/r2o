#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "d2k_nat.h"

int main(int argc, char **argv) {
    if (argc != 8) return 2;
    uint8_t protocol = (uint8_t)atoi(argv[2]);
    uint8_t family = (uint8_t)atoi(argv[3]);
    uint8_t source[16] = {0}, destination[16] = {0}, outside[16] = {0};
    int af = family == 4 ? AF_INET : family == 6 ? AF_INET6 : 0;
    if (!af || inet_pton(af, argv[4], source) != 1 || inet_pton(af, argv[6], destination) != 1) return 2;
    uint16_t source_port = htons((uint16_t)atoi(argv[5]));
    uint16_t destination_port = htons((uint16_t)atoi(argv[7]));
    uint16_t outside_port = 0;
    int result = d2k_nat_outside_family(argv[1], protocol, source, source_port,
        destination, destination_port, family, outside, &outside_port);
    if (result != 0) {
        printf("%d - 0\n", result);
        return 0;
    }
    char address[INET6_ADDRSTRLEN];
    if (!inet_ntop(af, outside, address, sizeof address)) return 2;
    printf("0 %s %u\n", address, (unsigned)ntohs(outside_port));
    return 0;
}
