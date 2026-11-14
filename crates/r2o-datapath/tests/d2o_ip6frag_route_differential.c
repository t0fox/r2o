/* C-оракул: d2k_f6_route/neighbor/prepare на veth (AF_PACKET-внутренности).
 *
 * Проверяются RTM_GETROUTE с src/dst/mark, RTM_GETNEIGH (NDA_DST/NDA_LLADDR),
 * MTU>=1280 и HWADDR без реальной отправки. */
#include <arpa/inet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_ip6frag_send.h"

int main(void) {
    static const uint8_t src[16] = {
        0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t dst[16] = {
        0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    uint8_t gateway[16] = {0};
    int ifindex = 0;
    int rc = d2k_f6_route(src, dst, 0, &ifindex, gateway);
    char ifname[IF_NAMESIZE] = "";
    if (rc == 0) {
        (void)if_indextoname((unsigned)ifindex, ifname);
    }
    char gateway_text[INET6_ADDRSTRLEN] = "";
    (void)inet_ntop(AF_INET6, gateway, gateway_text, sizeof gateway_text);
    printf("route rc=%d ifname=%s gateway=%s\n", rc, ifname, gateway_text);

    uint8_t mac[6] = {0};
    int nrc = -1;
    if (rc == 0) {
        nrc = d2k_f6_neighbor(ifindex, gateway, mac);
    }
    printf("neigh rc=%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n", nrc,
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    uint8_t packet[56];
    memset(packet, 0, sizeof packet);
    packet[0] = 0x60;
    packet[4] = 0;
    packet[5] = 16; /* payload: 8 fragment + 8 данных */
    packet[6] = 44;
    packet[7] = 64;
    memcpy(packet + 8, src, 16);
    memcpy(packet + 24, dst, 16);
    packet[40] = 17; /* UDP во фрагменте */
    packet[42] = 0;
    packet[43] = 1; /* M=1 */
    packet[44] = 0x12;
    packet[45] = 0x34;
    packet[46] = 0x50;
    packet[47] = 0x01;
    packet[48] = 0x12;
    packet[49] = 0x34;
    packet[50] = 0x01;
    packet[51] = 0xbb;
    packet[52] = 0;
    packet[53] = 8;
    d2k_ip6frag_sender sender;
    d2k_ip6frag_sender_init(&sender);
    int prc = d2k_ip6frag_prepare(&sender, packet, sizeof packet, 0);
    printf("prepare_short rc=%d\n", prc);
    d2k_ip6frag_sender_close(&sender);

    uint8_t long_packet[1300];
    memset(long_packet, 0, sizeof long_packet);
    long_packet[0] = 0x60;
    long_packet[4] = 0x04;
    long_packet[5] = 0xec; /* 1260: 8 fragment + 1252 данных */
    long_packet[6] = 44;
    long_packet[7] = 64;
    memcpy(long_packet + 8, src, 16);
    memcpy(long_packet + 24, dst, 16);
    long_packet[40] = 17;
    long_packet[43] = 1;
    long_packet[44] = 0x12;
    long_packet[45] = 0x34;
    long_packet[46] = 0x50;
    long_packet[47] = 0x02;
    d2k_ip6frag_sender_init(&sender);
    prc = d2k_ip6frag_prepare(&sender, long_packet, sizeof long_packet, 0);
    printf("prepare_long rc=%d\n", prc);
    d2k_ip6frag_sender_close(&sender);
    return 0;
}
