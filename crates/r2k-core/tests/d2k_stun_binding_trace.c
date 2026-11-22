#include <stdio.h>
#include "d2k_stun.h"

int main(void) {
    const uint8_t txid[12] = {0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae};
    uint8_t message[2048], ip[16];
    size_t size = fread(message, 1, sizeof message, stdin);
    int family = 0;
    uint16_t port;
    if (ferror(stdin)) return 1;
    if (d2k_stun_parse_response(message, size, txid, ip, &family, &port) != 0)
        family = 0;
    printf("%d\n", family);
    return 0;
}
