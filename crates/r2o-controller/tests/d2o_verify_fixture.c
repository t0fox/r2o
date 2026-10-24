#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "d2k_verify.h"

int main(int argc, char **argv)
{
    char *end = NULL;
    unsigned long port;
    d2k_ver_result result;

    if (argc != 4) {
        fprintf(stderr, "usage: %s ip port sni\n", argv[0]);
        return 2;
    }
    port = strtoul(argv[2], &end, 10);
    if (!end || *end != '\0' || port == 0 || port > UINT16_MAX) {
        fprintf(stderr, "invalid port: %s\n", argv[2]);
        return 2;
    }

    result = d2k_verify_probe(argv[1], (uint16_t)port, argv[3], 3000, 0);
    printf("%d\t%d\t%d\t%d\n",
           result.level == D2K_VER_APPLICATION,
           result.name_ok,
           result.status,
           result.body_complete);
    d2k_verify_close(&result);
    return 0;
}
