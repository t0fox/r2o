/* C-оракул live NFQUEUE: open/recv/parse/verdict в текущем netns. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_nfq.h"
#include "d2k_nl.h"

static uint64_t fnv(const uint8_t *bytes, size_t length) {
    uint64_t hash = 1469598103934665603ull;
    for (size_t i = 0; i < length; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

int main(void) {
    const char *queue_env = getenv("R2O_NFQ_LIVE_QUEUE");
    if (!queue_env) {
        printf("open=0\n");
        return 2;
    }
    d2k_nfq_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.queue = (uint16_t)strtoul(queue_env, NULL, 10);
    cfg.copy_range = 65535;
    cfg.maxlen = 1024;
    cfg.fail_open = 1;
    cfg.rcvbuf = 4 * 1024 * 1024;
    char err[256];
    d2k_nfq *queue = d2k_nfq_open(&cfg, err, sizeof err);
    printf("open=%d\n", queue ? 1 : 0);
    fflush(stdout);
    if (!queue) return 0;
    int one = 1;
    (void)setsockopt(d2k_nfq_fd(queue), SOL_SOCKET, SO_TIMESTAMP, &one, sizeof one);

    uint8_t packet[65536];
    ssize_t length = d2k_nfq_recv(queue, packet, sizeof packet, err, sizeof err);
    if (length <= 0) {
        printf("recv=%zd\n", length);
        fflush(stdout);
        d2k_nfq_close(queue);
        return 0;
    }
    d2k_nl_iter it;
    d2k_nl_msg message;
    d2k_nl_iter_init(&it, packet, (size_t)length);
    if (!d2k_nl_next(&it, &message)) {
        printf("recv=parse_fail\n");
        fflush(stdout);
        d2k_nfq_close(queue);
        return 0;
    }
    d2k_nl_pkt parsed;
    if (d2k_nl_packet(&message, &parsed) != 0) {
        printf("recv=packet_fail\n");
        fflush(stdout);
        d2k_nfq_close(queue);
        return 0;
    }
    size_t ihl = parsed.have_payload && parsed.payload_len ? (size_t)(parsed.payload[0] & 15) * 4 : 0;
    uint64_t hash = ihl && ihl <= parsed.payload_len
                        ? fnv(parsed.payload + ihl, parsed.payload_len - ihl)
                        : 0;
    printf("recv=1 hook=%u hw=%u outdev=%u mark=%u have_id=%u id_nonzero=%u "
           "payload_len=%zu l4hash=%016llx cap=%u trunc=%u ts=%u lost=%llu\n",
           (unsigned)parsed.hook, (unsigned)parsed.hw_protocol,
           (unsigned)parsed.outdev, (unsigned)parsed.mark,
           (unsigned)parsed.have_hdr, (unsigned)(parsed.id != 0),
           parsed.payload_len, (unsigned long long)hash,
           (unsigned)parsed.cap_len, (unsigned)parsed.truncated,
           (unsigned)parsed.have_tstamp,
           (unsigned long long)d2k_nfq_lost(queue));
    fflush(stdout);
    if (parsed.have_hdr) {
        (void)d2k_nfq_verdict(queue, parsed.id, D2K_NF_ACCEPT, err, sizeof err);
    }
    d2k_nfq_close(queue);
    return 0;
}
