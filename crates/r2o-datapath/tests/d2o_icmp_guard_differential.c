#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_icmpguard.h"

#define S UINT64_C(1000000000)

static const uint8_t field_icmp[] = {
    0x45,0x70,0x00,0x38,0x00,0x00,0x00,0x00,0xfb,0x01,0x2d,0x19,0x3e,0x73,0x91,0xdd,
    0xc0,0xa8,0x01,0x43,0x0b,0x00,0xe1,0x72,0x00,0x00,0x00,0x00,0x45,0x70,0x04,0xcc,
    0x00,0x01,0x40,0x00,0x01,0x11,0x16,0x59,0xc0,0xa8,0x01,0x43,0x68,0x15,0x34,0x57,
    0xd8,0x8b,0x01,0xbb,0x04,0xb8,0x34,0x8e,
};

static size_t fake4(uint8_t *packet) {
    const size_t len = 1228;
    memset(packet, 0, len);
    packet[0] = 0x45;
    packet[2] = (uint8_t)(len >> 8);
    packet[3] = (uint8_t)len;
    packet[4] = 0;
    packet[5] = 1;
    packet[6] = 0x40;
    packet[8] = 3;
    packet[9] = 17;
    packet[12] = 192;
    packet[13] = 168;
    packet[14] = 1;
    packet[15] = 67;
    packet[16] = 104;
    packet[17] = 21;
    packet[18] = 52;
    packet[19] = 87;
    packet[20] = 0xd8;
    packet[21] = 0x8b;
    packet[22] = 1;
    packet[23] = 0xbb;
    packet[24] = (uint8_t)((len - 20) >> 8);
    packet[25] = (uint8_t)(len - 20);
    packet[28] = 0xc0;
    return len;
}

int main(void) {
    static d2k_icmpguard guard;
    uint8_t fake[1228];
    const uint64_t now = UINT64_C(100) * S;
    size_t len = fake4(fake);
    uint64_t seen = 0;

    d2k_icmpguard_init(&guard);
    if (!d2k_icmpguard_note(&guard, fake, len, 63, now)) {
        return 1;
    }
    for (unsigned i = 0; i < 2; i++) {
        if ((field_icmp[0] >> 4) == 4 && sizeof field_icmp >= 20 && field_icmp[9] == 1) {
            seen++;
        }
        if (!d2k_icmpguard_check(&guard, field_icmp, sizeof field_icmp, now + S / 30)) {
            return 2;
        }
    }
    printf("ICMP time-exceeded: получено %" PRIu64 ", снято на свои фальшивки %" PRIu64
           "; фальшивок с пониженным TTL запомнено %" PRIu64 "\n",
           seen, d2k_icmpguard_dropped(&guard), d2k_icmpguard_noted(&guard));
    return 0;
}
