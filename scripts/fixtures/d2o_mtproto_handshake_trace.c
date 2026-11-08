#include "tg_mtproto.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static size_t unhex(const char *text, uint8_t *out, size_t cap) {
    size_t n = strlen(text);
    if ((n & 1u) != 0 || n / 2 > cap) return 0;
    for (size_t i = 0; i < n / 2; ++i) {
        unsigned value = 0;
        if (sscanf(text + 2 * i, "%2x", &value) != 1) return 0;
        out[i] = (uint8_t)value;
    }
    return n / 2;
}

static void print_hex(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
}

static void report(const char *name, const uint8_t *packet, size_t packet_len,
                   const uint8_t *secret, size_t secret_len, int obfuscated) {
    tg_mtproto_init parsed;
    memset(&parsed, 0, sizeof parsed);
    int rc = obfuscated
        ? tg_mtproto_parse_obfuscated2(packet, &parsed)
        : tg_mtproto_parse_secret(packet, secret, secret_len, &parsed);
    printf("%s ok=%d", name, rc == 0 ? 1 : 0);
    if (rc == 0) {
        printf(" dc=%u media=%d proto=%d prekey=", parsed.dc_id,
               parsed.is_media, (int)parsed.proto);
        print_hex(parsed.prekey_iv, sizeof parsed.prekey_iv);
    }
    putchar('\n');
    (void)packet_len;
}

int main(void) {
    uint8_t packet[TG_MTPROTO_HANDSHAKE_LEN];
    uint8_t secret[16];
    size_t packet_len = unhex(
        "0001020304050607000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f0001020304050607"
        "08090a0b0c0d0e0f87aeb3fe059b4807", packet, sizeof packet);
    if (packet_len != sizeof packet) return 2;
    report("direct", packet, packet_len, NULL, 0, 1);

    uint8_t secret_packet[TG_MTPROTO_HANDSHAKE_LEN];
    packet_len = unhex(
        "0001020304050607000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f0001020304050607"
        "08090a0b0c0d0e0f7c380b6e418caed2", secret_packet, sizeof secret_packet);
    if (packet_len != sizeof secret_packet) return 2;
    unhex("101112131415161718191a1b1c1d1e1f", secret, sizeof secret);
    report("secret", secret_packet, packet_len, secret, sizeof secret, 0);
    uint8_t wrong[16];
    memset(wrong, 0xa5, sizeof wrong);
    report("wrong-secret", secret_packet, packet_len, wrong, sizeof wrong, 0);

    uint8_t zero[TG_MTPROTO_HANDSHAKE_LEN] = {0};
    report("zero", zero, sizeof zero, NULL, 0, 1);

    uint8_t reserved[TG_MTPROTO_HANDSHAKE_LEN];
    memcpy(reserved, packet, sizeof reserved);
    memcpy(reserved, "GET ", 4);
    report("get-prefix", reserved, sizeof reserved, NULL, 0, 1);
    memcpy(reserved, packet, sizeof reserved);
    memset(reserved + 4, 0, 4);
    report("zero-prefix", reserved, sizeof reserved, NULL, 0, 1);
    return 0;
}
