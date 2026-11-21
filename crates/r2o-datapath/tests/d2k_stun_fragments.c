#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "d2k_ipfrag.h"

int main(void) {
    uint8_t packet[256], src[16], dst[16];
    uint8_t request[20] = {0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42};
    memset(request + 8, 0x37, sizeof request - 8);
    d2k_ipfrag_plan plan;
    d2k_ipfrag_span spans[3];
    if (d2k_ipfrag_shape(1, &plan) != 0)
        return 1;
    for (int family = 4; family <= 6; family += 2) {
        int af = family == 4 ? AF_INET : AF_INET6;
        if (inet_pton(af, family == 4 ? "192.0.2.1" : "2001:db8::1", src) != 1 ||
            inet_pton(af, family == 4 ? "198.51.100.2" : "2001:db8::2", dst) != 1)
            return 2;
        size_t n = family == 4
            ? d2k_udpfrag_build_ex(src, dst, 50001, 3478, request, sizeof request, &plan,
                                  7, 64, 0, packet, sizeof packet, spans)
            : d2k_udpfrag6_build_ex(src, dst, 50001, 3478, request, sizeof request, &plan,
                                   7, 64, 0, 0, packet, sizeof packet, spans);
        if (n != 2)
            return 3;
        for (size_t i = 0; i < n; ++i) {
            uint8_t *f = packet + spans[i].off;
            /* Случайные IP ID и зависящую от них контрольную сумму сравниваем отдельно. */
            if (family == 4) {
                memset(f + 4, 0, 2);
                memset(f + 10, 0, 2);
            } else {
                memset(f + 44, 0, 4);
            }
            for (size_t j = 0; j < spans[i].len; ++j)
                printf("%02x", f[j]);
            putchar('\n');
        }
    }
    return 0;
}
