#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_verify.h"

int main(int argc, char **argv)
{
    char *end = NULL;
    unsigned long port;
    d2k_ver_result result;

    if (argc != 5) {
        fprintf(stderr, "usage: %s ip port sni tls12|tls13\n", argv[0]);
        return 2;
    }
    port = strtoul(argv[2], &end, 10);
    if (!end || *end != '\0' || port == 0 || port > UINT16_MAX) {
        fprintf(stderr, "invalid port: %s\n", argv[2]);
        return 2;
    }

    if (strcmp(argv[4], "tls12") == 0) {
        result = d2k_verify_probe12_on(-1, argv[1], (uint16_t)port, argv[3], 3000, 0);
    } else if (strcmp(argv[4], "tls13") == 0) {
        result = d2k_verify_probe(argv[1], (uint16_t)port, argv[3], 3000, 0);
    } else {
        fprintf(stderr, "invalid TLS version: %s\n", argv[4]);
        return 2;
    }
    printf("%d\t%d\t%d\t%d\n",
           result.level == D2K_VER_APPLICATION,
           result.name_ok,
           result.status,
           result.body_complete);
    d2k_verify_close(&result);
    return 0;
}
