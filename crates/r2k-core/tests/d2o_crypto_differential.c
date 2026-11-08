/* M6: C-оракул crypto.c (SHA/HMAC/HKDF/AES-128-ECB/AES-128-GCM).
 *
 * Печатает hex-результаты для фиксированных входов; Rust-пример повторяет
 * те же входы через sha2/hmac/hkdf/aes/aes-gcm. */
#include "d2k_crypto.h"

#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", bytes[i]);
    }
}

static void print_case(const char *name, const uint8_t *bytes, size_t length) {
    printf("case %s\n", name);
    print_hex(bytes, length);
    printf("\n");
}

int main(void) {
    uint8_t output[64];
    uint8_t plain[256];
    uint8_t key[100];
    uint8_t message[50];
    for (size_t i = 0; i < sizeof plain; i++) plain[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof key; i++) key[i] = (uint8_t)(0xa0 + i);
    for (size_t i = 0; i < sizeof message; i++) message[i] = (uint8_t)(0x30 + i);

    d2k_sha256((const uint8_t *)"abc", 3, output);
    print_case("sha256-abc", output, 32);
    d2k_sha256(plain, 100, output);
    print_case("sha256-100", output, 32);

    d2k_hmac_sha256((const uint8_t *)"key", 3, (const uint8_t *)"message", 7, output);
    print_case("hmac-key-message", output, 32);
    d2k_hmac_sha256(key, sizeof key, message, sizeof message, output);
    print_case("hmac-long", output, 32);

    static const uint8_t salt[20] = {
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    };
    static const uint8_t dcid[8] = { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    uint8_t secret[32];
    d2k_hkdf_extract(salt, sizeof salt, dcid, sizeof dcid, secret);
    print_case("hkdf-extract", secret, 32);

    uint8_t expanded[32];
    if (d2k_hkdf_expand_label(secret, "client in", expanded, 32) != 0) return 2;
    print_case("hkdf-client-in", expanded, 32);
    uint8_t quic_key[16];
    if (d2k_hkdf_expand_label(secret, "quic key", quic_key, 16) != 0) return 3;
    print_case("hkdf-quic-key", quic_key, 16);
    uint8_t derived[32];
    if (d2k_hkdf_expand_label_ctx(secret, "derived", plain, 32, derived, 32) != 0) return 4;
    print_case("hkdf-derived-ctx", derived, 32);

    static const uint8_t fips_key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    static const uint8_t fips_plain[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    d2k_aes128_ecb(fips_key, fips_plain, output);
    print_case("aes128-ecb", output, 16);

    static const uint8_t gcm_key[16] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    };
    static const uint8_t gcm_iv[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88,
    };
    static const char aad[] = "additional data";
    static const char gcm_plain[] = "hello gcm world";
    uint8_t ciphertext[sizeof gcm_plain - 1];
    uint8_t tag[16];
    if (d2k_aes128_gcm_encrypt(gcm_key, gcm_iv, (const uint8_t *)aad, sizeof aad - 1,
                               (const uint8_t *)gcm_plain, sizeof gcm_plain - 1,
                               ciphertext, tag) != 0) return 5;
    print_case("gcm-ciphertext", ciphertext, sizeof ciphertext);
    print_case("gcm-tag", tag, sizeof tag);

    uint8_t sealed[sizeof ciphertext + sizeof tag];
    memcpy(sealed, ciphertext, sizeof ciphertext);
    memcpy(sealed + sizeof ciphertext, tag, sizeof tag);
    uint8_t opened[sizeof ciphertext];
    memset(opened, 0xaa, sizeof opened);
    if (d2k_aes128_gcm_decrypt(gcm_key, gcm_iv, (const uint8_t *)aad, sizeof aad - 1,
                               sealed, sizeof sealed, opened) != 0) return 6;
    print_case("gcm-opened", opened, sizeof opened);

    sealed[sizeof ciphertext] ^= 0x01;
    memset(opened, 0xaa, sizeof opened);
    int bad = d2k_aes128_gcm_decrypt(gcm_key, gcm_iv, (const uint8_t *)aad, sizeof aad - 1,
                                     sealed, sizeof sealed, opened);
    printf("case gcm-bad-tag\nrc=%d\n", bad);
    print_hex(opened, sizeof opened);
    printf("\n");
    return 0;
}
