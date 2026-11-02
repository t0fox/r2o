#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_ctq.h"

int main(int argc, char **argv) {
    if (argc != 7) return 2;

    d2k_ct_tuple tuple = {0};
    tuple.family = (uint8_t)strtoul(argv[1], NULL, 10);
    tuple.proto = (uint8_t)strtoul(argv[2], NULL, 10);
    int address_family = tuple.family == 4 ? AF_INET : tuple.family == 6 ? AF_INET6 : 0;
    if (!address_family || inet_pton(address_family, argv[3], tuple.src) != 1 ||
        inet_pton(address_family, argv[5], tuple.dst) != 1) {
        return 2;
    }

    uint16_t source_port = htons((uint16_t)strtoul(argv[4], NULL, 10));
    uint16_t destination_port = htons((uint16_t)strtoul(argv[6], NULL, 10));
    memcpy(tuple.sport_be, &source_port, sizeof source_port);
    memcpy(tuple.dport_be, &destination_port, sizeof destination_port);

    uint8_t request[128];
    size_t length = d2k_ct_get_req(request, sizeof request, 0x01020304u, &tuple);
    if (length == 0) return 2;
    for (size_t i = 0; i < length; ++i) printf("%02x", request[i]);
    putchar('\n');
    return 0;
}
