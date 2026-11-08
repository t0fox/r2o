/* TG7: C-оракул MTProto 2.0 decrypt на векторах D2O.
 *
 * Печатает те же строки, что Rust example `tg7_trace.rs`.
 */
#define _POSIX_C_SOURCE 200809L
#include "tg_mtproto.h"

#include <stdio.h>
#include <string.h>

static const char *SERVER_CIPHERTEXT =
    "7a7183c2c10e4f4df945fa9a9abd35e7c3840b61f045304f39674c19c0e20978"
    "4f50f6226a073529d675c92cbf0bfa8c99a79b3f39c72a5d9a026d431ab7407c"
    "a04ecc55187d6c45f17871524edd90cea02ed728e14d7cb18aea2a636158f094"
    "59a9437710d894c79f368c4e8164b7647ea98612aefe942c5d92121acb8db02d"
    "ccceb66d0f8720ac12a06db0582bfd955be34f365118e3bab8cd080ce6b45b28"
    "eac56dcd2a29374e";
static const char *SERVER_AUTH_KEY =
    "5d2e7d65f49ec28bd029a88761ea27b8a4c79f12226525443e7d7c596ef33035"
    "30db2107e89aa997c7a0164ab694187adeff156bd6ef7118a1962347753c0e7e"
    "89a0354b8ec364f9997e71bc6923fb86e8e43491e010606a6ce845e2fa019409"
    "77ef0aa32adf5a97dbf6d428ec0434d717a2d3ad19622cc05887642113c7965f"
    "fb862a3e3ccb0ab95addda57f89245dbd76b492348f8e94bd5a7c0e0b8480852"
    "3cfd1ea80b32fe9ad198bc2e103fceb7d52492ecc0273a28674bc923eee59265"
    "ab17a002df1f4aa2c59b819a5e5e1d105ec117336f5c76c6b187037d4b4270c"
    "ee9cc21071d97e9bca220c6d7b01b998cf2e5cdb9a50ecda1852a36e635690c8e";
static const char *SERVER_PLAINTEXT =
    "fc826a02248b28fd60f2c4822443ad6801f0c1c2918b305e0200000058000000"
    "dcf8f1730200000001a8c1c2918b305e010000001c0000000809c29ec4fd33ad"
    "918b305e18a88ea607ee5816fc826a02248b28fd01ccc1c2918b305e0200000014"
    "000000c5737734c4fd33ad918b305e6408300000000000fce66704a3cd8ee9d0a"
    "e6fab672c60c04a3f1fd4490e51f6";

static size_t decode_hex(const char *hex, uint8_t *out, size_t cap) {
    size_t len = strlen(hex);
    if ((len & 1u) != 0 || len / 2 > cap) return 0;
    for (size_t i = 0; i < len / 2; i++) {
        unsigned value = 0;
        if (sscanf(hex + 2 * i, "%2x", &value) != 1) return 0;
        out[i] = (uint8_t)value;
    }
    return len / 2;
}

static void print_hex(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
}

static void run_case(const char *name, const char *ciphertext_hex,
                     const char *auth_key_hex, int tamper_offset) {
    uint8_t packet[512], auth_key[256], plaintext[512];
    size_t packet_len = decode_hex(ciphertext_hex, packet, sizeof packet);
    size_t key_len = decode_hex(auth_key_hex, auth_key, sizeof auth_key);
    if (packet_len == 0 || key_len != 256) {
        printf("%s ok=0\n", name);
        return;
    }
    if (tamper_offset == -2) {
        packet_len -= 8;
    } else if (tamper_offset >= 0) {
        packet[tamper_offset] ^= 1u;
    }
    size_t plaintext_len = 0;
    int rc = tg_mtproto_v2_decrypt(auth_key, packet, packet_len, plaintext,
                                   sizeof plaintext, &plaintext_len);
    if (rc != 0) {
        printf("%s ok=0\n", name);
        return;
    }
    printf("%s ok=1 len=%zu plain=", name, plaintext_len);
    print_hex(plaintext, plaintext_len);
    putchar('\n');
}

int main(void) {
    run_case("valid", SERVER_CIPHERTEXT, SERVER_AUTH_KEY, -1);
    run_case("tampered-message-key", SERVER_CIPHERTEXT, SERVER_AUTH_KEY, 24);
    run_case("wrong-key-id", SERVER_CIPHERTEXT, SERVER_AUTH_KEY, 0);
    uint8_t expected[512];
    size_t expected_len = decode_hex(SERVER_PLAINTEXT, expected,
                                     sizeof expected);
    uint8_t packet[512];
    size_t packet_len = decode_hex(SERVER_CIPHERTEXT, packet, sizeof packet);
    uint8_t auth_key[256], plaintext[512];
    decode_hex(SERVER_AUTH_KEY, auth_key, sizeof auth_key);
    size_t plaintext_len = 0;
    int rc = tg_mtproto_v2_decrypt(auth_key, packet, packet_len, plaintext,
                                   sizeof plaintext, &plaintext_len);
    printf("vector-match ok=%d\n",
           rc == 0 && plaintext_len == expected_len &&
                   memcmp(plaintext, expected, expected_len) == 0
               ? 1
               : 0);
    run_case("truncated", SERVER_CIPHERTEXT, SERVER_AUTH_KEY, -2);
    return 0;
}
