/* C-оракул: is_discord_ip_discovery_response (datapath/session.c:552-564).
 *
 * session.c включается целиком: нужна статическая функция; неиспользуемые
 * секции выбрасываются --gc-sections. */
#include "session.c"

#include <stdio.h>
#include <string.h>

static const uint8_t SSRC[4] = {0x12, 0x34, 0x56, 0x78};

static void make(uint8_t *packet, const uint8_t *text, size_t length,
                 int nul_after_text) {
    memset(packet, 0, 74);
    packet[0] = 0; packet[1] = 2; packet[2] = 0; packet[3] = 70;
    memcpy(packet + 4, SSRC, 4);
    memcpy(packet + 8, text, length);
    if (nul_after_text && 8 + length < 72) packet[8 + length] = 0;
    packet[72] = 0xC3; packet[73] = 0x5C; /* 50012 */
}

static void print(const char *name, const uint8_t *packet, size_t length,
                  const uint8_t *ssrc) {
    printf("%s result=%d\n", name,
           is_discord_ip_discovery_response(packet, length, ssrc) ? 1 : 0);
}

int main(void) {
    uint8_t packet[74];
    static const uint8_t valid[] = "203.0.113.7";
    static const uint8_t colons[] = "::";
    static const uint8_t dots[] = "...";
    static const uint8_t ip_port[] = "1.2.3.4:443";
    static const uint8_t nul_tail[] = "1.2.3.4\0::";
    static const uint8_t control[] = "1.2.3.4\x01";
    static const uint8_t letters[] = "abc";
    static const uint8_t space[] = "1.2.3.4 tail";
    static const uint8_t ones[] = "11111111111111111111";

    make(packet, valid, sizeof valid - 1, 1);
    print("valid", packet, 74, SSRC);
    make(packet, colons, sizeof colons - 1, 1);
    print("colons", packet, 74, SSRC);
    make(packet, dots, sizeof dots - 1, 1);
    print("dots", packet, 74, SSRC);
    make(packet, ip_port, sizeof ip_port - 1, 1);
    print("ip-port", packet, 74, SSRC);
    make(packet, nul_tail, sizeof nul_tail - 1, 0);
    print("nul-tail", packet, 74, SSRC);
    make(packet, control, sizeof control - 1, 1);
    print("control", packet, 74, SSRC);
    make(packet, letters, sizeof letters - 1, 1);
    print("letters", packet, 74, SSRC);
    make(packet, space, sizeof space - 1, 1);
    print("space", packet, 74, SSRC);
    make(packet, ones, sizeof ones - 1, 0);
    print("no-nul", packet, 74, SSRC);
    memset(packet, 0, 74);
    packet[0] = 0; packet[1] = 2; packet[2] = 0; packet[3] = 70;
    memcpy(packet + 4, SSRC, 4);
    packet[72] = 0xC3; packet[73] = 0x5C;
    print("empty", packet, 74, SSRC);
    make(packet, valid, sizeof valid - 1, 1);
    packet[72] = 0; packet[73] = 0;
    print("zero-port", packet, 74, SSRC);
    make(packet, valid, sizeof valid - 1, 1);
    static const uint8_t other_ssrc[4] = {0x12, 0x34, 0x56, 0x79};
    print("other-ssrc", packet, 74, other_ssrc);
    make(packet, valid, sizeof valid - 1, 1);
    print("short", packet, 73, SSRC);
    make(packet, valid, sizeof valid - 1, 1);
    packet[1] = 3;
    print("bad-header", packet, 74, SSRC);
    return 0;
}
