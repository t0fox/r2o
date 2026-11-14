/* C/Rust differential: C `d2k_hold_flush`/mismatch release-колбэк против
 * Rust `remove_slot`/`release_held_packets` (release_original).
 *
 * Колбэк C получает id и байты; принадлежность (owned/ACCEPT) — решение
 * вызывающего, как `hold_owns` в d2kd.c. Здесь она задана таблицей id.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d2k_hold.h"

static uint32_t nonowned[64];
static size_t nonowned_count;

static int is_owned(uint32_t id) {
    return id == 11 || id == 12;
}

static uint64_t fnv1a(const uint8_t *bytes, size_t length) {
    uint64_t hash = 14695981039346656037ull;
    for (size_t i = 0; i < length; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

static uint32_t packet_sequence(const uint8_t *packet, size_t length) {
    if (length < 28) {
        return 0;
    }
    return (uint32_t)packet[24] << 24 | (uint32_t)packet[25] << 16 |
           (uint32_t)packet[26] << 8 | packet[27];
}

static void release(void *ctx, uint32_t id, const uint8_t *packet,
                    size_t length) {
    (void)ctx;
    uint32_t sequence = packet_sequence(packet, length);
    printf("obs id=%u seq=%u len=%zu fnv=%016llx\n", id, sequence, length,
           (unsigned long long)fnv1a(packet, length));
    if (is_owned(id)) {
        printf("own id=%u seq=%u len=%zu fnv=%016llx\n", id, sequence, length,
               (unsigned long long)fnv1a(packet, length));
    } else if (nonowned_count < sizeof nonowned / sizeof nonowned[0]) {
        nonowned[nonowned_count++] = id;
    }
}

static size_t packet(uint8_t *out, uint16_t source_port, uint32_t sequence,
                     uint8_t flags, const uint8_t *payload, size_t length) {
    size_t total = 40 + length;
    memset(out, 0, total);
    out[0] = 0x45;
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[8] = 64;
    out[9] = 6;
    out[12] = 192;
    out[13] = 0;
    out[14] = 2;
    out[15] = 10;
    out[16] = 198;
    out[17] = 51;
    out[18] = 100;
    out[19] = 20;
    out[20] = (uint8_t)(source_port >> 8);
    out[21] = (uint8_t)source_port;
    out[22] = (uint8_t)(443 >> 8);
    out[23] = (uint8_t)(443 & 0xff);
    out[24] = (uint8_t)(sequence >> 24);
    out[25] = (uint8_t)(sequence >> 16);
    out[26] = (uint8_t)(sequence >> 8);
    out[27] = (uint8_t)sequence;
    out[28] = 0;
    out[29] = 0;
    out[30] = 0x0b;
    out[31] = 0xb8;
    out[32] = 5 << 4;
    out[33] = flags;
    if (length) {
        memcpy(out + 40, payload, length);
    }
    return total;
}

static int feed(d2k_hold *hold, uint32_t id, const uint8_t *data, size_t length,
                uint64_t now, uint64_t revision, int allow,
                d2k_hold_batch *batch) {
    return d2k_hold_feed(hold, id, data, length, now, revision, allow, 0, 0,
                         release, NULL, batch);
}

int main(void) {
    const uint64_t now = 1000;
    const uint8_t hello[9] = {22, 3, 3, 0, 4, 1, 0, 0, 0};
    uint8_t p[1600];
    d2k_hold_batch batch;

    // Два слота: owned (id 11,12) и не-owned (id 21,22). flush ALL.
    d2k_hold *hold = d2k_hold_new();
    printf("== flush ==\n");
    (void)feed(hold, 10, p, packet(p, 50000, 1000, 0x02, NULL, 0), now, 0, 0,
               &batch);
    (void)feed(hold, 11, p, packet(p, 50000, 1001, 0x18, hello, 5), now, 0,
               D2K_HOLD_TLS, &batch);
    (void)feed(hold, 12, p, packet(p, 50000, 1006, 0x18, hello + 5, 2), now, 0,
               D2K_HOLD_TLS, &batch);
    (void)feed(hold, 20, p, packet(p, 50001, 2000, 0x02, NULL, 0), now, 0, 0,
               &batch);
    (void)feed(hold, 21, p, packet(p, 50001, 2001, 0x18, hello, 5), now, 0,
               D2K_HOLD_TLS, &batch);
    d2k_hold_stats stats;
    d2k_hold_get_stats(hold, &stats);
    printf("flush pending=%zu\n", stats.pending);
    d2k_hold_flush(hold, now + D2K_HOLD_WAIT_NS, 0, 1, release, NULL);
    printf("flush released=");
    for (size_t i = 0; i < nonowned_count; i++) {
        if (i) {
            printf(",");
        }
        printf("%u", nonowned[i]);
    }
    printf("\n");
    d2k_hold_get_stats(hold, &stats);
    printf("flush stats pending=%zu released=%llu mismatched=%llu\n",
           stats.pending, (unsigned long long)stats.released,
           (unsigned long long)stats.mismatched);
    d2k_hold_free(hold);
    nonowned_count = 0;

    // Mismatch: старый слот 31 отпускается, затем текущий 32.
    hold = d2k_hold_new();
    printf("== mismatch ==\n");
    (void)feed(hold, 30, p, packet(p, 50002, 3000, 0x02, NULL, 0), now, 0, 0,
               &batch);
    (void)feed(hold, 31, p, packet(p, 50002, 3001, 0x18, hello, 5), now, 0,
               D2K_HOLD_TLS, &batch);
    int rc = feed(hold, 32, p, packet(p, 50002, 3006, 0x08, hello + 5, 4), now,
                  0, D2K_HOLD_TLS, &batch);
    printf("mismatch rc=%d released=", rc);
    for (size_t i = 0; i < nonowned_count; i++) {
        if (i) {
            printf(",");
        }
        printf("%u", nonowned[i]);
    }
    printf("\n");
    d2k_hold_get_stats(hold, &stats);
    printf("mismatch stats pending=%zu released=%llu mismatched=%llu\n",
           stats.pending, (unsigned long long)stats.released,
           (unsigned long long)stats.mismatched);
    d2k_hold_free(hold);
    return 0;
}
