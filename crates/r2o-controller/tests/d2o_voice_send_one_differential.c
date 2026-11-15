/* C-оракул voice `send_one`/`voice_ask`: реальный connected UDP-сокет,
 * приманка copies 1/2/3 и пустой/непустой pre. Trace датаграмм снимает
 * loopback-приёмник; здесь печатается только tally. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "voice.c"

static const uint8_t decoy[20] = {
    'r', '2', 'o', '-', 't', 'e', 's', 't', '-', 'v',
    'o', 'i', 'c', 'e', '-', 'a', 'r', 'm', '!', '!',
};

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s host:port copies wait_ms\n", argv[0]);
        return 2;
    }
    char *colon = strrchr(argv[1], ':');
    if (!colon) return 2;
    *colon = '\0';
    struct in_addr addr;
    if (inet_pton(AF_INET, argv[1], &addr) != 1) return 2;
    uint16_t port = (uint16_t)strtoul(colon + 1, NULL, 10);
    int copies = atoi(argv[2]);
    uint32_t wait_ms = (uint32_t)strtoul(argv[3], NULL, 10);

    const uint8_t *pre = copies > 0 ? decoy : NULL;
    size_t pre_len = copies > 0 ? sizeof decoy : 0;
    uint32_t rtt = 0;
    d2k_tally t = voice_ask(addr.s_addr, port, pre, pre_len, copies,
                            wait_ms, 0, D2K_VOICE_REPEATS, &rtt);
    printf("tally pass=%d fail=%d err=%d marked=%d rtt=%u\n",
           t.pass, t.fail, t.err, t.marked, (unsigned)rtt);
    return 0;
}
