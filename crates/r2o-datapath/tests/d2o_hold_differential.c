/* D6: C-оракул TCP hold/order/ownership/release. */
#define _POSIX_C_SOURCE 200809L
#include "d2k_hold.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t released[256];
static size_t nreleased;

static void release(void *ctx, uint32_t id, const uint8_t *packet, size_t length) {
    (void)ctx;
    (void)packet;
    (void)length;
    if (nreleased < sizeof released / sizeof released[0]) {
        released[nreleased++] = id;
    }
}

static int compare_u32(const void *left, const void *right) {
    uint32_t a = *(const uint32_t *)left;
    uint32_t b = *(const uint32_t *)right;
    return (a > b) - (a < b);
}

static void print_released(void) {
    qsort(released, nreleased, sizeof released[0], compare_u32);
    for (size_t i = 0; i < nreleased; i++) {
        if (i) printf(",");
        printf("%u", released[i]);
    }
}

static size_t packet(uint8_t *out, uint32_t sequence, uint8_t flags,
                     const uint8_t *payload, size_t length) {
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
    out[20] = 50000 >> 8;
    out[21] = 50000 & 0xff;
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
    out[32] = 0x50;
    out[33] = flags;
    if (length) memcpy(out + 40, payload, length);
    return total;
}

static int feed(d2k_hold *hold, uint32_t id, const uint8_t *packet, size_t length,
                uint64_t now, uint64_t revision, int allow,
                d2k_hold_batch *batch) {
    return d2k_hold_feed(hold, id, packet, length, now, revision, allow, 0, 0,
                         release, NULL, batch);
}

static const uint8_t hello[9] = { 22, 3, 3, 0, 4, 1, 0, 0, 0 };

int main(void) {
    uint8_t p[1600];
    d2k_hold_batch batch;

    {
        d2k_hold *hold = d2k_hold_new();
        size_t length = packet(p, 1000, 0x02, NULL, 0);
        int rc = feed(hold, 1, p, length, 1, 0, 0, &batch);
        printf("A syn %s released=", rc == 0 ? "pass" : "other");
        print_released();
        printf("\n");
        nreleased = 0;
        length = packet(p, 1001, 0x18, hello, 5);
        rc = feed(hold, 2, p, length, 1, 0, D2K_HOLD_TLS, &batch);
        printf("A first %s released=", rc == 1 ? "wait" : "other");
        print_released();
        printf("\n");
        nreleased = 0;
        length = packet(p, 1006, 0x18, hello + 5, 4);
        rc = feed(hold, 3, p, length, 1, 0, 0, &batch);
        if (rc == 2) {
            printf("A second ready ids=");
            for (size_t i = 0; i < batch.count; i++) {
                if (i) printf(",");
                printf("%u", batch.ids[i]);
            }
            printf(" body=%d originals=%zu lens=",
                   memcmp(batch.packet + 40, hello, sizeof hello) == 0,
                   batch.orig_count);
            for (size_t i = 0; i < batch.orig_count; i++) {
                if (i) printf(",");
                printf("%zu", batch.orig_len[i]);
            }
            printf("\n");
        } else {
            printf("A second other released=");
            print_released();
            printf("\n");
        }
        nreleased = 0;
        d2k_hold_free(hold);
    }

    {
        d2k_hold *hold = d2k_hold_new();
        size_t length = packet(p, 9000, 0x02, NULL, 0);
        int rc = feed(hold, 1, p, length, 1, 0, 0, &batch);
        printf("B syn %s released=", rc == 0 ? "pass" : "other");
        print_released();
        printf("\n");
        nreleased = 0;
        length = packet(p, 9006, 0x18, hello + 5, 4);
        rc = d2k_hold_feed(hold, 2, p, length, 1, 0, D2K_HOLD_TLS, 9001, 1,
                           release, NULL, &batch);
        printf("B tail %s released=", rc == 1 ? "wait" : "other");
        print_released();
        printf("\n");
        nreleased = 0;
        length = packet(p, 9001, 0x18, hello, 5);
        rc = feed(hold, 3, p, length, 1, 0, 0, &batch);
        if (rc == 2) {
            printf("B head ready ids=");
            for (size_t i = 0; i < batch.count; i++) {
                if (i) printf(",");
                printf("%u", batch.ids[i]);
            }
            printf(" seq=%u\n",
                   ((unsigned)batch.packet[24] << 24) |
                       ((unsigned)batch.packet[25] << 16) |
                       ((unsigned)batch.packet[26] << 8) | batch.packet[27]);
        } else {
            printf("B head other released=");
            print_released();
            printf("\n");
        }
        nreleased = 0;
        d2k_hold_free(hold);
    }

    {
        d2k_hold *hold = d2k_hold_new();
        size_t length = packet(p, 1000, 0x02, NULL, 0);
        int rc = feed(hold, 1, p, length, 1, 0, 0, &batch);
        printf("C syn %s released=", rc == 0 ? "pass" : "other");
        print_released();
        printf("\n");
        nreleased = 0;
        length = packet(p, 1001, 0x18, hello, 5);
        rc = feed(hold, 2, p, length, 1, 0, D2K_HOLD_TLS, &batch);
        printf("C first %s released=", rc == 1 ? "wait" : "other");
        print_released();
        printf("\n");
        nreleased = 0;
        d2k_hold_flush(hold, 1 + D2K_HOLD_WAIT_NS, 0, 0, release, NULL);
        printf("C flush released=");
        print_released();
        printf("\n");
        d2k_hold_stats stats;
        d2k_hold_get_stats(hold, &stats);
        printf("C stats timed_out=%llu timed_out_packets=%llu pending=%zu\n",
               (unsigned long long)stats.timed_out,
               (unsigned long long)stats.timed_out_pkts, stats.pending);
        nreleased = 0;
        d2k_hold_free(hold);
    }

    {
        d2k_hold *hold = d2k_hold_new();
        size_t length = packet(p, 2000, 0x02, NULL, 0);
        int rc = feed(hold, 3, p, length, 1, 4, 0, &batch);
        printf("D syn %s released=", rc == 0 ? "pass" : "other");
        print_released();
        printf("\n");
        nreleased = 0;
        length = packet(p, 2001, 0x18, hello, 5);
        rc = feed(hold, 4, p, length, 1, 4, D2K_HOLD_TLS, &batch);
        printf("D first %s released=", rc == 1 ? "wait" : "other");
        print_released();
        printf("\n");
        nreleased = 0;
        d2k_hold_flush(hold, 1, 5, 0, release, NULL);
        printf("D revision released=");
        print_released();
        printf("\n");
        d2k_hold_stats stats;
        d2k_hold_get_stats(hold, &stats);
        printf("D stats plan_changed=%llu released=%llu pending=%zu\n",
               (unsigned long long)stats.plan_changed,
               (unsigned long long)stats.released, stats.pending);
        nreleased = 0;
        d2k_hold_free(hold);
    }

    {
        d2k_hold *hold = d2k_hold_new();
        size_t length = packet(p, 3000, 0x02, NULL, 0);
        (void)feed(hold, 1, p, length, 1, 0, 0, &batch);
        length = packet(p, 3001, 0x18, hello, 5);
        for (uint32_t id = 2; id <= 9; id++) {
            (void)feed(hold, id, p, length, 1, 0, D2K_HOLD_TLS, &batch);
        }
        int rc = feed(hold, 10, p, length, 1, 0, 0, &batch);
        printf("E ninth released=");
        print_released();
        printf(" outcome=%s\n", rc == 1 ? "wait" : rc == 2 ? "ready" : "pass");
        nreleased = 0;
        d2k_hold_free(hold);
    }
    return 0;
}
