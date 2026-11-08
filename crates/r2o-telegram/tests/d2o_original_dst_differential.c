/* TG15: C-оракул разбора SO_ORIGINAL_DST (tg_listener_decode_original_dst_any). */
#define _POSIX_C_SOURCE 200809L
#include "tg_listener.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static void print_destination(const char *name, int rc,
                              const tg_listener_destination *destination) {
    printf("%s ok=%d", name, rc == 0 ? 1 : 0);
    if (rc == 0) {
        size_t length = destination->family == AF_INET ? 4 : 16;
        printf(" family=%d port=%u addr=", (int)destination->family,
               destination->port);
        for (size_t i = 0; i < length; i++) {
            printf("%02x", destination->address[i]);
        }
    }
    putchar('\n');
}

static void run_v4(const char *name, uint16_t family, uint16_t port,
                   const char *address, size_t length) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = family;
    addr.sin_port = htons(port);
    if (address) inet_pton(AF_INET, address, &addr.sin_addr);
    tg_listener_destination destination;
    int rc = tg_listener_decode_original_dst_any((const uint8_t *)&addr,
                                                 length, &destination);
    print_destination(name, rc, &destination);
}

static void run_v6(const char *name, uint16_t family, uint16_t port,
                   const char *address, size_t length) {
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof addr);
    addr.sin6_family = family;
    addr.sin6_port = htons(port);
    addr.sin6_flowinfo = 0x1234;
    addr.sin6_scope_id = 5;
    if (address) inet_pton(AF_INET6, address, &addr.sin6_addr);
    tg_listener_destination destination;
    int rc = tg_listener_decode_original_dst_any((const uint8_t *)&addr,
                                                 length, &destination);
    print_destination(name, rc, &destination);
}

int main(void) {
    run_v4("v4-valid", AF_INET, 443, "149.154.167.51", sizeof(struct sockaddr_in));
    run_v4("v4-port0", AF_INET, 0, "149.154.167.51", sizeof(struct sockaddr_in));
    run_v4("v4-family-wrong", AF_INET6, 443, "149.154.167.51", sizeof(struct sockaddr_in));
    run_v4("v4-short", AF_INET, 443, "149.154.167.51", sizeof(struct sockaddr_in) - 1);
    run_v4("v4-extra", AF_INET, 443, "149.154.167.51", sizeof(struct sockaddr_in) + 4);
    run_v4("v4-zero-address", AF_INET, 443, "0.0.0.0", sizeof(struct sockaddr_in));

    run_v6("v6-valid", AF_INET6, 443, "2001:67c:4e8:f002::a", sizeof(struct sockaddr_in6));
    run_v6("v6-port0", AF_INET6, 0, "2001:67c:4e8:f002::a", sizeof(struct sockaddr_in6));
    run_v6("v6-family-wrong", AF_INET, 443, "2001:67c:4e8:f002::a", sizeof(struct sockaddr_in6));
    run_v6("v6-short", AF_INET6, 443, "2001:67c:4e8:f002::a", sizeof(struct sockaddr_in6) - 1);
    run_v6("v6-extra", AF_INET6, 443, "2001:67c:4e8:f002::a", sizeof(struct sockaddr_in6) + 4);
    run_v6("v6-mapped", AF_INET6, 443, "::ffff:149.154.167.51", sizeof(struct sockaddr_in6));

    uint8_t unknown[16] = {1, 0};
    tg_listener_destination destination;
    int rc = tg_listener_decode_original_dst_any(unknown, sizeof unknown, &destination);
    print_destination("unknown-family", rc, &destination);
    rc = tg_listener_decode_original_dst_any(unknown, 1, &destination);
    print_destination("too-short", rc, &destination);
    rc = tg_listener_decode_original_dst_any(NULL, 16, &destination);
    print_destination("null-buffer", rc, &destination);
    return 0;
}
