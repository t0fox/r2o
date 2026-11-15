/* C-оракул voice_discovery `discovery_probe`: реальный connected UDP-сокет,
 * первый из 25 запросов уходит планом с prefix, остальные — прямым send.
 * Trace датаграмм и ответы снимает loopback-приёмник. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "voice_discovery.c"

static const uint8_t prefix[20] = {
    0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42,
    0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
    0x9b, 0x9c, 0x9d, 0x9e,
};

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s host:port wait_ms mark use_prefix\n", argv[0]);
        return 2;
    }
    char *colon = strrchr(argv[1], ':');
    if (!colon) return 2;
    *colon = '\0';
    struct in_addr addr;
    if (inet_pton(AF_INET, argv[1], &addr) != 1) return 2;
    uint16_t port = (uint16_t)strtoul(colon + 1, NULL, 10);
    uint32_t wait_ms = (uint32_t)strtoul(argv[2], NULL, 10);
    uint32_t mark = (uint32_t)strtoul(argv[3], NULL, 10);
    int use_prefix = atoi(argv[4]);

    d2k_discovery_result r = discovery_probe(
        addr.s_addr, port, use_prefix ? prefix : NULL,
        use_prefix ? sizeof prefix : 0, wait_ms, mark);
    printf("probe sent=%u received=%u error=%d marked=%d\n",
           r.sent, r.received, r.error, r.marked);
    return 0;
}
