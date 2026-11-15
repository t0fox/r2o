/* C-оракул состояния d2k_ip6frag_sender: init/close идемпотентны, после
 * close отправка не оставляет открытого fd. Запускается в netns без
 * маршрута к 2001:db8:dead::1, поэтому send обязан упасть до открытия
 * AF_PACKET с ENETUNREACH.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_ip6frag_send.h"

static void build_packet(uint8_t packet[56]) {
    static const uint8_t src[16] = {
        0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t dst[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    memset(packet, 0, 56);
    packet[0] = 0x60;
    packet[4] = 0;
    packet[5] = 16;
    packet[6] = 44;
    packet[7] = 64;
    memcpy(packet + 8, src, 16);
    memcpy(packet + 24, dst, 16);
    packet[40] = 17;
    packet[43] = 1;
    packet[44] = 0x12;
    packet[45] = 0x34;
    packet[46] = 0x50;
    packet[47] = 0x01;
}

int main(void) {
    uint8_t packet[56];
    build_packet(packet);
    d2k_ip6frag_sender sender;
    d2k_ip6frag_sender_init(&sender);
    printf("sender_init_fd=%d\n", sender.fd);
    d2k_ip6frag_sender_close(&sender);
    printf("sender_close1_fd=%d\n", sender.fd);
    d2k_ip6frag_sender_close(&sender);
    printf("sender_close2_fd=%d\n", sender.fd);
    errno = 0;
    ssize_t rc = d2k_ip6frag_send(&sender, packet, sizeof packet, 0);
    printf("sender_send_after_close rc=%d errno=%d fd_after=%d\n",
           rc < 0 ? -1 : 0, errno, sender.fd);
    return 0;
}
