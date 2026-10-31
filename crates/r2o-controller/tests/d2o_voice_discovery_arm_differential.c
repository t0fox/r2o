#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_meas.h"
#include "d2k_quicprobe.h"
#include "d2k_stun.h"
#include "d2k_udpruntime.h"
#include "d2k_voice_discovery.h"

static int mark_hook(int fd, uint32_t mark) {
    (void)fd;
    (void)mark;
    return 0;
}

d2k_mark_fn d2k_mark_hook = mark_hook;

int d2k_voice_arm_plan(const uint8_t *decoy, size_t dlen, unsigned copies,
                       char *buf, size_t cap) {
    (void)decoy;
    (void)dlen;
    (void)copies;
    (void)buf;
    (void)cap;
    return -1;
}

int d2k_udp_plan_send(int fd, const char *text, const uint8_t *payload,
                      size_t len, uint32_t mark) {
    (void)fd;
    (void)text;
    (void)payload;
    (void)len;
    (void)mark;
    return -1;
}

size_t d2k_stun_request(uint8_t *out, size_t cap,
                        uint8_t txid[D2K_STUN_TXID_LEN]) {
    static uint8_t next_id = 0x40;
    if (!out || !txid || cap < D2K_STUN_HDR_LEN) {
        return 0;
    }
    memset(out, 0, D2K_STUN_HDR_LEN);
    out[1] = 1;
    out[4] = 0x21;
    out[5] = 0x12;
    out[6] = 0xa4;
    out[7] = 0x42;
    for (size_t i = 0; i < D2K_STUN_TXID_LEN; i++) {
        txid[i] = next_id++;
    }
    memcpy(out + 8, txid, D2K_STUN_TXID_LEN);
    return D2K_STUN_HDR_LEN;
}

static unsigned probes;

static d2k_discovery_result probe(uint32_t ip, uint16_t port,
                                  const uint8_t *prefix, size_t len,
                                  uint32_t wait, uint32_t mark) {
    (void)ip;
    (void)port;
    (void)len;
    (void)wait;
    (void)mark;
    probes++;
    return (d2k_discovery_result){
        .sent = prefix ? D2K_DISCOVERY_EXCHANGES : 3,
        .received = prefix ? D2K_DISCOVERY_EXCHANGES : 2,
        .error = 0,
        .marked = 1,
    };
}

int main(void) {
    d2k_voice_opt options = {0};
    d2k_voice_res result = {0};
    uint8_t expected_prefix[20] = {0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42};
    static const char hex[] = "0123456789abcdef";
    d2k_discovery_probe_hook = probe;
    for (size_t i = 8; i < sizeof expected_prefix; i++) {
        expected_prefix[i] = (uint8_t)(0x40 + i - 8);
    }
    if (!d2k_voice_discovery_search(&options, &result) ||
        result.verdict != D2K_VOICE_BLOCKED || !result.discovery_verified ||
        result.arm_len != sizeof expected_prefix || result.arm_copies != 1 ||
        memcmp(result.arm_bytes, expected_prefix, sizeof expected_prefix) ||
        probes != 6) {
        fprintf(stderr, "D2O did not return the verified Discovery arm\n");
        return 1;
    }
    fputs("PREFIX:", stdout);
    for (size_t i = 0; i < result.arm_len; i++) {
        putchar(hex[result.arm_bytes[i] >> 4]);
        putchar(hex[result.arm_bytes[i] & 0x0f]);
    }
    putchar('\n');
    printf("Приём:     %s ×%d; серия Discovery проверена, звук проверяется в приложении\n",
           result.fake_arm, result.arm_copies);
    return 0;
}
