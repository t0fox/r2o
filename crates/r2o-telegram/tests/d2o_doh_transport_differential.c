/* TG14: C-оракул DoH `doh_lookup` из production route_dns.c.
 *
 * Использование: d2o-doh-client CA_PEM DOMAIN
 * Печатает ту же строку, что Rust example tg14_doh_client.
 */
#define _POSIX_C_SOURCE 200809L
#include "route_dns.c"

#include <stdio.h>
#include <string.h>

static void print_addresses(const tg_listener_destination *addresses,
                            size_t count) {
    for (size_t i = 0; i < count; i++) {
        printf(" ");
        size_t length = addresses[i].family == AF_INET ? 4 : 16;
        for (size_t j = 0; j < length; j++)
            printf("%02x", addresses[i].address[j]);
    }
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    SSL_CTX *context = tg_tls_client_context(argv[1]);
    if (!context) {
        printf("ok=0\n");
        return 0;
    }
    tg_route_dns cache;
    memset(&cache, 0, sizeof cache);
    cache.tls_context = context;
    tg_listener_destination addresses[TG_ROUTE_DNS_ADDRESS_MAX] = {{0}};
    size_t count = 0;
    int rc = doh_lookup(&cache, argv[2], addresses, &count);
    if (rc != 0 || !count) {
        printf("ok=0\n");
    } else {
        printf("ok=1 count=%zu", count);
        print_addresses(addresses, count);
        putchar('\n');
    }
    SSL_CTX_free(context);
    return 0;
}
