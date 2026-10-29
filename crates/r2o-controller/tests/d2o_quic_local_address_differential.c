#define _POSIX_C_SOURCE 200112L

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "d2k_net4.h"

static int is_local_address(const char *text, int *is_local) {
    if (strchr(text, ':')) {
        struct in6_addr address;
        if (inet_pton(AF_INET6, text, &address) != 1) return -1;
        *is_local = d2k_ip6_private(address.s6_addr);
        return 0;
    }

    struct in_addr address;
    if (inet_pton(AF_INET, text, &address) != 1) return -1;
    *is_local = d2k_ip4_private(address.s_addr);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *fixture = fopen(argv[1], "r");
    if (!fixture) return 2;

    char line[256];
    unsigned line_number = 0;
    int failed = 0;
    while (fgets(line, sizeof(line), fixture)) {
        char name[64], address[128], expected_text[8];
        line_number++;
        if (sscanf(line, "%63[^\t]\t%127[^\t]\t%7s", name, address,
                   expected_text) != 3) {
            fprintf(stderr, "invalid fixture line %u\n", line_number);
            failed = 1;
            break;
        }

        const int expected = strcmp(expected_text, "true") == 0;
        int actual = 0;
        if ((!expected && strcmp(expected_text, "false") != 0) ||
            is_local_address(address, &actual) != 0) {
            fprintf(stderr, "invalid address fixture line %u\n", line_number);
            failed = 1;
            break;
        }
        if (actual != expected) {
            fprintf(stderr, "%s: C policy returned %d, expected %d\n",
                    name, actual, expected);
            failed = 1;
            break;
        }
        printf("%s=%d\n", name, actual);
    }

    if (ferror(fixture)) failed = 1;
    fclose(fixture);
    return failed;
}
