/* C-оракул ENOBUFS NFQUEUE: переполнение SO_RCVBUF.
 *
 * Стенд (scripts/test-datapath-enobufs-differential.sh) заранее ставит
 * nft-правило output udp dport 9998 -> queue 65002 bypass. Скрипт также
 * поднимает lo. Программа открывает очередь с крошечным rcvbuf, посылает
 * пачку датаграмм и читает: ядро обязано вернуть -2 (ENOBUFS) и увеличить
 * счётчик потерянных сообщений.
 */
#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_nfq.h"

int main(void) {
    d2k_nfq_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.queue = 65002;
    cfg.copy_range = 0xffff;
    cfg.maxlen = 0xffff;
    cfg.fail_open = 1;
    cfg.rcvbuf = 4096;

    char err[256] = {0};
    d2k_nfq *q = d2k_nfq_open(&cfg, err, sizeof err);
    if (!q) {
        fprintf(stderr, "d2k_nfq_open: %s\n", err);
        return 1;
    }

    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp < 0) {
        perror("socket");
        d2k_nfq_close(q);
        return 1;
    }
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9998);
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    unsigned char payload[60000];
    memset(payload, 0x5a, sizeof payload);
    for (unsigned i = 0; i < 512; i++) {
        (void)sendto(udp, payload, sizeof payload, 0,
                     (struct sockaddr *)&dst, sizeof dst);
    }
    close(udp);
    usleep(300000);

    unsigned char buf[65536];
    int rc = 0;
    for (unsigned i = 0; i < 256; i++) {
        ssize_t n = d2k_nfq_recv(q, buf, sizeof buf, err, sizeof err);
        if (n == -2) {
            rc = -2;
            break;
        }
        if (n < 0) {
            rc = (int)n;
            break;
        }
    }
    printf("recv_rc=%d lost=%llu\n", rc,
           (unsigned long long)d2k_nfq_lost(q));
    d2k_nfq_close(q);
    return 0;
}
