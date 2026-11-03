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

static size_t fake6(uint8_t *packet, uint8_t hop_limit, uint8_t protocol,
                    uint16_t source_port, uint16_t destination_port) {
    const size_t len = 48;
    memset(packet, 0, len);
    packet[0] = 0x60;
    packet[5] = 8;
    packet[6] = protocol;
    packet[7] = hop_limit;
    packet[8] = 0x20; packet[9] = 0x01; packet[10] = 0x0d; packet[11] = 0xb8;
    packet[23] = 0x67;
    packet[24] = 0x26; packet[25] = 0x06; packet[26] = 0x47;
    packet[39] = 0x87;
    packet[40] = (uint8_t)(source_port >> 8);
    packet[41] = (uint8_t)source_port;
    packet[42] = (uint8_t)(destination_port >> 8);
    packet[43] = (uint8_t)destination_port;
    if (protocol == 17) { packet[45] = 8; }
    else { packet[47] = 1; }
    return len;
}

static size_t icmp6(uint8_t *packet, uint8_t kind, uint8_t code,
                    const uint8_t *quote, size_t quote_len) {
    const size_t len = 48 + quote_len;
    memset(packet, 0, len);
    packet[0] = 0x60;
    packet[4] = (uint8_t)((8 + quote_len) >> 8);
    packet[5] = (uint8_t)(8 + quote_len);
    packet[6] = 58;
    packet[7] = 250;
    packet[8] = 0x20; packet[9] = 1; packet[10] = 0x0d; packet[11] = 0xb8;
    packet[23] = 3;
    packet[24] = 0x20; packet[25] = 1; packet[26] = 0x0d; packet[27] = 0xb8;
    packet[39] = 0x67;
    packet[40] = kind;
    packet[41] = code;
    memcpy(packet + 48, quote, quote_len);
    return len;
}

static int check6(d2k_icmpguard *guard, const uint8_t *packet, size_t len,
                  uint64_t now, uint64_t *seen) {
    if (len >= 40 && (packet[0] >> 4) == 6 && packet[6] == 58) { (*seen)++; }
    return d2k_icmpguard_check(guard, packet, len, now);
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

    uint8_t fake_v6[48], quote[48], packet[128];
    uint64_t seen_v6 = 0;
    d2k_icmpguard_init(&guard);
    const size_t fake_v6_len = fake6(fake_v6, 3, 17, 55435, 443);
    if (!d2k_icmpguard_note(&guard, fake_v6, fake_v6_len, 64, now)) { return 3; }

    size_t packet_len = icmp6(packet, 3, 0, fake_v6, fake_v6_len);
    const int first_match = check6(&guard, packet, packet_len, now + S / 30, &seen_v6);
    const int second_match = check6(&guard, packet, packet_len, now + S / 30, &seen_v6);

    packet_len = icmp6(packet, 2, 0, fake_v6, fake_v6_len);
    const int packet_too_big = check6(&guard, packet, packet_len, now + S / 30, &seen_v6);

    memcpy(quote, fake_v6, fake_v6_len);
    quote[43] ^= 1;
    packet_len = icmp6(packet, 3, 0, quote, fake_v6_len);
    const int changed_port = check6(&guard, packet, packet_len, now + S / 30, &seen_v6);

    memcpy(quote, fake_v6, fake_v6_len);
    quote[7] = 4;
    packet_len = icmp6(packet, 3, 0, quote, fake_v6_len);
    const int raised_hop_limit = check6(&guard, packet, packet_len, now + S / 30, &seen_v6);

    packet_len = icmp6(packet, 3, 0, fake_v6, fake_v6_len);
    const int expired = check6(&guard, packet, packet_len,
                               now + D2K_ICMPGUARD_KEEP_NS + 1, &seen_v6);
    if (!first_match || !second_match || packet_too_big || changed_port ||
        raised_hop_limit || expired) { return 4; }
    printf("ICMPv6: получено %" PRIu64 ", снято на свои фальшивки %" PRIu64
           "; фальшивок с пониженным TTL запомнено %" PRIu64 "\n",
           seen_v6, d2k_icmpguard_dropped(&guard), d2k_icmpguard_noted(&guard));
    return 0;
}
