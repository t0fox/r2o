/* C/Rust differential: d2k_raw_send error/accounting paths (a378). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "raw.c"

static void wr16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

int main(void) {
    const char *scenario = getenv("FAKE_SENDTO_SCENARIO");
    if (!scenario) scenario = "ok";
    int large = !strcmp(scenario, "emsgsize");
    uint8_t packet[1200];
    size_t length = large ? sizeof packet : 36;
    memset(packet, 0, sizeof packet);
    packet[0] = 0x45;
    wr16(packet + 2, (uint16_t)length);
    wr16(packet + 4, 9);
    packet[8] = 64;
    packet[9] = 17;
    packet[12] = 192; packet[13] = 0; packet[14] = 2; packet[15] = 1;
    packet[16] = 198; packet[17] = 51; packet[18] = 100; packet[19] = 2;
    wr16(packet + 20, 51234);
    wr16(packet + 22, 443);
    wr16(packet + 24, (uint16_t)(length - 20));

    d2k_raw raw;
    memset(&raw, 0, sizeof raw);
    raw.fd = socket(AF_INET, SOCK_DGRAM, 0);
    raw.fd6 = -1;
    raw.fragment_fd = -1;
    raw.maxlen = 1500;
    raw.route[0].family = 4;
    memcpy(raw.route[0].ip, packet + 16, 4);
    raw.route[0].mtu = 1500;
    raw.route_next = 1;

    char error[160];
    size_t sent_length = !strcmp(scenario, "invalid") ? 19 : length;
    int rc = d2k_raw_send(&raw, packet, sent_length, error, sizeof error);
    printf("%s rc=%d sent=%llu errors=%llu busy=%llu maxlen=%zu route=%zu\n",
           scenario, rc < 0 ? -1 : 0,
           (unsigned long long)raw.sent, (unsigned long long)raw.errors,
           (unsigned long long)raw.busy, raw.maxlen, raw.route[0].mtu);
    return 0;
}
