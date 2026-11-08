/* TG14: C-оракул DNS-wire encode/parse из route_dns.c.
 *
 * Modes:
 *   d2o-doh-wire encode DOMAIN TYPE
 *   d2o-doh-wire parse DIR NAME...
 */
#define _POSIX_C_SOURCE 200809L
#include "route_dns.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *file = fopen(path, "rb");
    if (!file) return -1;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    long length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }
    uint8_t *bytes = malloc((size_t)length);
    if (!bytes) {
        fclose(file);
        return -1;
    }
    size_t used = fread(bytes, 1, (size_t)length, file);
    fclose(file);
    if (used != (size_t)length) {
        free(bytes);
        return -1;
    }
    *out = bytes;
    *out_len = used;
    return 0;
}

static void print_addresses(const tg_listener_destination *addresses,
                            size_t count) {
    for (size_t i = 0; i < count; i++) {
        printf(" ");
        size_t length = addresses[i].family == AF_INET ? 4 : 16;
        for (size_t j = 0; j < length; j++) {
            printf("%02x", addresses[i].address[j]);
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    if (strcmp(argv[1], "encode") == 0 && argc == 4) {
        uint8_t packet[512];
        size_t length = 0;
        uint16_t id = 0;
        int rc = dns_encode_question(argv[2], (uint16_t)strtoul(argv[3], NULL, 10),
                                     packet, &length, &id);
        printf("encode %s ok=%d", argv[2], rc == 0 ? 1 : 0);
        if (rc == 0) {
            packet[0] = 0x12;
            packet[1] = 0x34;
            printf(" hex=");
            for (size_t i = 0; i < length; i++) printf("%02x", packet[i]);
        }
        putchar('\n');
        return 0;
    }
    if (strcmp(argv[1], "parse") == 0 && argc >= 4) {
        const char *dir = argv[2];
        for (int index = 3; index < argc; index++) {
            char path[4096];
            snprintf(path, sizeof path, "%s/%s.bin", dir, argv[index]);
            uint8_t *packet = NULL;
            size_t length = 0;
            if (read_file(path, &packet, &length) != 0) {
                printf("parse %s ok=-1\n", argv[index]);
                continue;
            }
            tg_listener_destination addresses[TG_ROUTE_DNS_ADDRESS_MAX] = {{0}};
            size_t count = 0;
            int rc = tg_route_dns_parse_response(packet, length, 0x1234,
                                                 addresses, &count);
            free(packet);
            printf("parse %s ok=%d count=%zu", argv[index], rc == 0 ? 1 : 0,
                   count);
            if (rc == 0) print_addresses(addresses, count);
            putchar('\n');
        }
        return 0;
    }
    return 2;
}
