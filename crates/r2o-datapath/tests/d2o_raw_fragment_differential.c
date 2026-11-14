/* C/Rust differential: отдельный IPv4-сокет фрагментов с IP_NODEFRAG.
 *
 * C `d2k_raw_prepare` (datapath/raw.c) открывает `fragment_fd` лениво при
 * первом IPv4-фрагменте, требует IP_HDRINCL + IP_NODEFRAG + SO_MARK и НЕ
 * откатывается на обычный сокет. Сценарии:
 *   ok          — setsockopt проходит, фрагмент уходит через fragment_fd;
 *   nofrag_fail — IP_NODEFRAG отвергнут, отправка фрагмента завершается
 *                 ошибкой (errors++), обычный пакет по-прежнему уходит.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "raw.c"

static void wr16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void run_one(d2k_raw *raw, const char *scenario, const char *kind,
                    const uint8_t *packet, size_t length) {
    char error[160];
    int rc = d2k_raw_send(raw, packet, length, error, sizeof error);
    printf("%s %s rc=%d fd=%d sent=%llu errors=%llu busy=%llu\n",
           scenario, kind, rc < 0 ? -1 : 0, raw->fragment_fd >= 0,
           (unsigned long long)raw->sent, (unsigned long long)raw->errors,
           (unsigned long long)raw->busy);
}

int main(void) {
    const char *scenario = getenv("FAKE_OPEN_SCENARIO");
    if (!scenario) {
        scenario = "ok";
    }
    uint8_t packet[36];
    memset(packet, 0, sizeof packet);
    packet[0] = 0x45;
    wr16(packet + 2, sizeof packet);
    wr16(packet + 4, 9);
    packet[8] = 64;
    packet[9] = 17;
    packet[12] = 192;
    packet[13] = 0;
    packet[14] = 2;
    packet[15] = 1;
    packet[16] = 198;
    packet[17] = 51;
    packet[18] = 100;
    packet[19] = 2;
    wr16(packet + 20, 51234);
    wr16(packet + 22, 443);
    wr16(packet + 24, 16);
    memset(packet + 28, 'a', 8);

    char error[160];
    d2k_raw *raw = d2k_raw_open(0, NULL, error, sizeof error);
    if (!raw) {
        printf("%s open rc=-1\n", scenario);
        return 2;
    }

    uint8_t fragment[36];
    memcpy(fragment, packet, sizeof fragment);
    wr16(fragment + 6, 0x2000);
    run_one(raw, scenario, "fragment", fragment, sizeof fragment);
    run_one(raw, scenario, "plain", packet, sizeof packet);

    d2k_raw_close(raw);
    return 0;
}
