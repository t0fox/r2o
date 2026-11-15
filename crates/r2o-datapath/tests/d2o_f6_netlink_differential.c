/* C-оракул d2k_f6_route/d2k_f6_neighbor на инъекции rtnetlink.
 *
 * Стенд scripts/test-datapath-f6-netlink-differential.sh подключает
 * f6_netlink_shim.c через LD_PRELOAD; сценарий задаёт R2O_F6_SCENARIO.
 * Вывод побайтно сравнивается с Rust `raw::tests::f6_netlink_differential_matches_c`.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_ip6frag_send.h"

int main(void) {
    static const uint8_t src[16] = {
        0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t dst[16] = {
        0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    int ifindex = 0;
    uint8_t gateway[16];
    int rc = d2k_f6_route(src, dst, 0x2e, &ifindex, gateway);
    if (rc != 0) {
        printf("route rc=-1 errno=%d\n", errno);
        return 0;
    }
    char text[INET6_ADDRSTRLEN] = "";
    (void)inet_ntop(AF_INET6, gateway, text, sizeof text);
    printf("route rc=0 ifindex=%d gateway=%s\n", ifindex, text);

    uint8_t mac[6] = {0};
    int nrc = d2k_f6_neighbor(ifindex, gateway, mac);
    if (nrc != 0) {
        printf("neighbor rc=-1 errno=%d\n", errno);
        return 0;
    }
    printf("neighbor rc=0 mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0;
}
