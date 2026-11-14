/* C-оракул: последовательность BIND+PARAMS d2k_nfq_open (nfq.c:203-224).
 *
 * Печатаются точные байты сообщений: queue=4242, seq=1/2, AF_INET всегда. */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "d2k_nl.h"

static void print_hex(const char *name, const uint8_t *bytes, size_t length) {
    printf("%s len=%zu hex=", name, length);
    for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
    printf("\n");
}

static void run(const char *prefix, int fail_open) {
    uint8_t message[256];
    size_t length = d2k_nl_cfg_cmd(message, sizeof message, 4242, 1,
                                   D2K_NFQNL_CFG_CMD_BIND, AF_INET);
    char name[64];
    snprintf(name, sizeof name, "%s-bind", prefix);
    print_hex(name, message, length);
    uint32_t flags = fail_open ? D2K_NFQA_CFG_F_FAIL_OPEN : 0;
    uint32_t mask = D2K_NFQA_CFG_F_FAIL_OPEN | D2K_NFQA_CFG_F_GSO;
    length = d2k_nl_cfg_params(message, sizeof message, 4242, 2, 65535,
                               D2K_NFQNL_COPY_PACKET, 1024, flags, mask);
    snprintf(name, sizeof name, "%s-params", prefix);
    print_hex(name, message, length);
}

int main(void) {
    run("open", 1);
    run("no-fail-open", 0);
    return 0;
}
