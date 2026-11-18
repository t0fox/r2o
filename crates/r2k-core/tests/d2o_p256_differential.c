#include "d2k_p256.h"

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

/* p256.c тянет t13_random только для keypair; этот differential его не зовёт. */
int d2k_t13_random(uint8_t *out, size_t len) {
    (void)out;
    (void)len;
    return -1;
}

static int hex(const char *text, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned value = 0;
        if (sscanf(text + 2 * i, "%2x", &value) != 1) return -1;
        out[i] = (uint8_t)value;
    }
    return 0;
}

static const char *scalars[] = {
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "0000000000000000000000000000000000000000000000000000000000000003",
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
};

int main(void) {
    uint8_t scalar[32], peer_scalar[32];
    uint8_t public_key[65], peer_public[65], shared[32];
    size_t count = sizeof scalars / sizeof scalars[0];
    for (size_t i = 0; i < count; i++) {
        if (hex(scalars[i], scalar, sizeof scalar) != 0) return 2;
        if (d2k_p256_public(scalar, public_key) != 0) {
            printf("pub %s -\n", scalars[i]);
            continue;
        }
        printf("pub %s ", scalars[i]);
        for (size_t j = 0; j < sizeof public_key; j++) printf("%02x", public_key[j]);
        printf("\n");
    }
    for (size_t i = 0; i < count; i++) {
        if (hex(scalars[i], scalar, sizeof scalar) != 0) return 2;
        for (size_t j = 0; j < count; j++) {
            if (hex(scalars[j], peer_scalar, sizeof peer_scalar) != 0) return 2;
            if (d2k_p256_public(peer_scalar, peer_public) != 0) continue;
            if (d2k_p256_ecdh(scalar, peer_public, shared) != 0) {
                printf("ecdh %s %s -\n", scalars[i], scalars[j]);
                continue;
            }
            printf("ecdh %s %s ", scalars[i], scalars[j]);
            for (size_t k = 0; k < sizeof shared; k++) printf("%02x", shared[k]);
            printf("\n");
        }
    }
    return 0;
}
