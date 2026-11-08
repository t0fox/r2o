/* Q2: C-оракул address pool / next-question из quicprobe.c.
 *
 * Включает quicprobe.c, чтобы вызвать static qp_pinned_or_next; резолвер
 * подменён детерминированным stub. Печатаются только pool и next-адреса. */
#include "quicprobe.c"

#include <stdio.h>
#include <string.h>

static size_t stub_resolve(const char *sni, char out[][D2K_QUIC_ADDR_LEN],
                           size_t cap) {
    (void)sni;
    static const char *extra[] = {
        "192.0.2.1", "2001:db8::2", "192.0.2.1", "192.0.2.3",
    };
    size_t count = sizeof extra / sizeof extra[0];
    if (count > cap) count = cap;
    for (size_t i = 0; i < count; i++) {
        snprintf(out[i], D2K_QUIC_ADDR_LEN, "%s", extra[i]);
    }
    return count;
}

static void print_pool(const char *name, const char *ip) {
    char pool[D2K_QUIC_MAX_ADDRS][D2K_QUIC_ADDR_LEN];
    size_t count = d2k_quic_build_pool(ip, "x.example", pool,
                                       D2K_QUIC_MAX_ADDRS);
    printf("case %s\nn=%zu\n", name, count);
    for (size_t i = 0; i < count; i++) {
        printf("%zu=%s\n", i, pool[i]);
    }
}

int main(void) {
    d2k_quic_resolve_hook = stub_resolve;
    print_pool("pool-v4", "192.0.2.2");
    print_pool("pool-v6", "2001:db8:1234:5678::1");

    char pool[3][D2K_QUIC_ADDR_LEN];
    snprintf(pool[0], sizeof pool[0], "192.0.2.2");
    snprintf(pool[1], sizeof pool[1], "192.0.2.1");
    snprintf(pool[2], sizeof pool[2], "192.0.2.3");

    size_t next = 0;
    const char *address = qp_pinned_or_next(
        (const char (*)[D2K_QUIC_ADDR_LEN])pool, 3, &next, 0);
    printf("case next-pinned\naddr=%s\nnext=%zu\n", address ? address : "none",
           next);

    next = 0;
    for (int step = 0; step < 4; step++) {
        address = qp_pinned_or_next(
            (const char (*)[D2K_QUIC_ADDR_LEN])pool, 3, &next, 1);
        printf("case next-residual-%d\naddr=%s\nnext=%zu\n", step,
               address ? address : "none", next);
    }
    return 0;
}
