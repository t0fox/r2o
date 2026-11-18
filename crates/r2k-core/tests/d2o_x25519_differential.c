#include "d2k_crypto.h"

#include <stdio.h>

static int hex(const char *text, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned value = 0;
        if (sscanf(text + 2 * i, "%2x", &value) != 1) return -1;
        out[i] = (uint8_t)value;
    }
    return 0;
}

static const char *scalars[] = {
    "0100000000000000000000000000000000000000000000000000000000000000",
    "0200000000000000000000000000000000000000000000000000000000000000",
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
    "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "0000000000000000000000000000000000000000000000000000000000000000",
};

int main(void) {
    uint8_t scalar[32], peer_scalar[32], public_key[32], peer_public[32], shared[32];
    size_t count = sizeof scalars / sizeof scalars[0];
    for (size_t i = 0; i < count; i++) {
        if (hex(scalars[i], scalar, sizeof scalar) != 0) return 2;
        if (d2k_x25519_base(public_key, scalar) != 0) {
            printf("base %s -\n", scalars[i]);
            continue;
        }
        printf("base %s ", scalars[i]);
        for (size_t j = 0; j < sizeof public_key; j++) printf("%02x", public_key[j]);
        printf("\n");
    }
    for (size_t i = 0; i < count; i++) {
        if (hex(scalars[i], scalar, sizeof scalar) != 0) return 2;
        for (size_t j = 0; j < count; j++) {
            if (hex(scalars[j], peer_scalar, sizeof peer_scalar) != 0) return 2;
            if (d2k_x25519_base(peer_public, peer_scalar) != 0) continue;
            if (d2k_x25519(shared, scalar, peer_public) != 0) {
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
