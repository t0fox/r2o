#include <arpa/inet.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_ctq.h"

static int decode(int argc, char **argv) {
    if (argc != 4) return 2;

    char *end = NULL;
    unsigned long sequence = strtoul(argv[2], &end, 10);
    if (argv[2][0] == '\0' || *end != '\0' || sequence > UINT32_MAX) return 2;

    const char *hex = argv[3];
    size_t hex_length = strlen(hex);
    if ((hex_length & 1u) != 0 || hex_length / 2 > 4096) return 2;
    uint8_t message[4096];
    size_t message_length = hex_length / 2;
    for (size_t i = 0; i < message_length; ++i) {
        char byte[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        end = NULL;
        unsigned long value = strtoul(byte, &end, 16);
        if (end != byte + 2 || value > UINT8_MAX) return 2;
        message[i] = (uint8_t)value;
    }

    d2k_ct_info info = {0};
    int result = d2k_ct_info_parse(message, message_length, (uint32_t)sequence, &info);
    printf("%d %" PRIu64 " %" PRIu64 " %u %u\n", result, info.orig_pkts,
        info.reply_pkts, (unsigned)info.tcp_state_known, (unsigned)info.tcp_state);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "decode") == 0) return decode(argc, argv);
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
