/* C-оракул: route cache/blend/declared maxlen (datapath/raw.c:278-340). */
#include <stdio.h>
#include <string.h>

#include "raw.c"

static void put_route(d2k_raw *raw, uint8_t family, const uint8_t *ip,
                      size_t mtu) {
    memset(raw->route, 0, sizeof raw->route);
    raw->route[0].family = family;
    memcpy(raw->route[0].ip, ip, family == 6 ? 16 : 4);
    raw->route[0].mtu = mtu;
    raw->route_next = 1;
}

int main(void) {
    d2k_raw raw;
    memset(&raw, 0, sizeof raw);
    raw.fd = -1;
    raw.fd6 = -1;
    raw.fragment_fd = -1;
    uint8_t v4[4] = {198, 51, 100, 2};
    uint8_t v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

    put_route(&raw, 4, v4, 1400);
    raw.maxlen = 1500;
    raw.maxlen_declared = 0;
    printf("hit_plain %zu\n", d2k_raw_route_maxlen_family(&raw, v4, 4));

    raw.maxlen = 1200;
    raw.maxlen_declared = 1;
    printf("hit_declared_cap %zu\n",
           d2k_raw_route_maxlen_family(&raw, v4, 4));

    raw.maxlen = 1200;
    raw.maxlen_declared = 0;
    printf("hit_route_above_cap %zu\n",
           d2k_raw_route_maxlen_family(&raw, v4, 4));

    raw.maxlen = 0;
    raw.maxlen_declared = 0;
    printf("maxlen_zero %zu\n", d2k_raw_maxlen(&raw));

    put_route(&raw, 6, v6, 1400);
    raw.maxlen = 1500;
    raw.maxlen_declared = 1;
    printf("v6_hit %zu\n", d2k_raw_route_maxlen_family(&raw, v6, 6));

    raw.route[0].mtu = 1300;
    printf("v6_lowered %zu\n", d2k_raw_route_maxlen_family(&raw, v6, 6));
    return 0;
}
