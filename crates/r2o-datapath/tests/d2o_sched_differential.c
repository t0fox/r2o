/* D21: C-оракул ядра очереди отложенной отправки. */
#define _POSIX_C_SOURCE 200809L
#include "d2k_sched.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void mark(uint8_t *bytes, size_t length, uint32_t id) {
    memset(bytes, 0xcc, length);
    bytes[0] = (uint8_t)(id >> 24);
    bytes[1] = (uint8_t)(id >> 16);
    bytes[2] = (uint8_t)(id >> 8);
    bytes[3] = (uint8_t)id;
}

static uint32_t idof(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static void push_raw(d2k_sched *sched, const char *label, uint32_t id,
                     uint64_t due, size_t length) {
    uint8_t packet[64];
    d2k_key key;
    memset(&key, 0, sizeof key);
    mark(packet, length, id);
    int rc = d2k_sched_push(sched, due, packet, length, &key);
    printf("%s push id=%u rc=%d\n", label, id, rc);
}

static void pop_ex(d2k_sched *sched, const char *label, uint64_t now,
                   size_t outcap) {
    uint8_t out[64];
    size_t length = 0;
    d2k_key key;
    uint64_t execution = 0;
    int owned = 0;
    uint32_t owner_id = 0;
    int rc = d2k_sched_pop_due_ex(sched, now, out, outcap, &length, &key,
                                  &execution, &owned, &owner_id);
    if (rc == 1) {
        printf("%s pop id=%u rc=1 len=%zu owned=%d qid=%u\n", label, idof(out),
               length, owned, owner_id);
    } else if (rc == -1) {
        printf("%s pop rc=-1 len=0 owned=%d qid=%u\n", label, owned, owner_id);
    } else {
        printf("%s pop rc=0 len=0\n", label);
    }
}

int main(void) {
    {
        d2k_sched *sched = d2k_sched_new(4, 64);
        printf("empty count=%zu next=0 refusals=%llu\n", d2k_sched_count(sched),
               (unsigned long long)d2k_sched_refusals(sched));
        pop_ex(sched, "empty", 0, 64);
        d2k_sched_free(sched);
    }
    {
        d2k_sched *sched = d2k_sched_new(8, 64);
        static const uint64_t dues[5] = { 900, 100, 500, 50, 700 };
        for (uint32_t i = 0; i < 5; i++) {
            push_raw(sched, "order", i, dues[i], 8);
        }
        for (int i = 0; i < 5; i++) {
            pop_ex(sched, "order", 100000, 64);
        }
        printf("order count=%zu next=0 refusals=%llu\n", d2k_sched_count(sched),
               (unsigned long long)d2k_sched_refusals(sched));
        d2k_sched_free(sched);
    }
    {
        d2k_sched *sched = d2k_sched_new(4, 64);
        for (uint32_t id = 1; id <= 3; id++) {
            push_raw(sched, "stable", id, 500, 8);
        }
        for (int i = 0; i < 3; i++) {
            pop_ex(sched, "stable", 500, 64);
        }
        d2k_sched_free(sched);
    }
    {
        d2k_sched *sched = d2k_sched_new(2, 64);
        push_raw(sched, "cap", 1, 10, 8);
        push_raw(sched, "cap", 2, 10, 8);
        push_raw(sched, "cap", 3, 10, 8);
        printf("cap count=%zu refusals=%llu\n", d2k_sched_count(sched),
               (unsigned long long)d2k_sched_refusals(sched));
        d2k_sched_free(sched);
    }
    {
        d2k_sched *sched = d2k_sched_new(4, 8);
        uint8_t packet[16];
        d2k_key key;
        memset(&key, 0, sizeof key);
        mark(packet, sizeof packet, 1);
        int rc = d2k_sched_push(sched, 10, packet, sizeof packet, &key);
        printf("slot push id=1 len=16 rc=%d\n", rc);
        push_raw(sched, "slot", 2, 10, 8);
        printf("slot count=%zu refusals=%llu\n", d2k_sched_count(sched),
               (unsigned long long)d2k_sched_refusals(sched));
        pop_ex(sched, "slot", 10, 64);
        d2k_sched_free(sched);
    }
    {
        d2k_sched *sched = d2k_sched_new(2, 8);
        push_raw(sched, "grow", 1, 10, 8);
        printf("grow 16 rc=%d\n", d2k_sched_grow_slot_size(sched, 16));
        printf("grow 16 rc=%d\n", d2k_sched_grow_slot_size(sched, 16));
        printf("grow 4 rc=%d\n", d2k_sched_grow_slot_size(sched, 4));
        printf("grow max rc=%d\n", d2k_sched_grow_slot_size(sched, (size_t)-1));
        push_raw(sched, "grow", 2, 11, 16);
        pop_ex(sched, "grow", 10, 64);
        pop_ex(sched, "grow", 11, 64);
        d2k_sched_free(sched);
    }
    {
        d2k_sched *sched = d2k_sched_new(4, 64);
        uint8_t packet[20];
        mark(packet, sizeof packet, 7);
        int rc = d2k_sched_push_owned(sched, 100, packet, sizeof packet, 4242);
        printf("owned push id=7 rc=%d\n", rc);
        push_raw(sched, "owned", 8, 100, 20);
        pop_ex(sched, "owned", 100, 64);
        pop_ex(sched, "owned", 100, 64);
        mark(packet, sizeof packet, 9);
        rc = d2k_sched_push_owned(sched, 200, packet, sizeof packet, 77);
        printf("owned push id=9 rc=%d\n", rc);
        pop_ex(sched, "owned", 200, 8);
        printf("owned count=%zu refusals=%llu\n", d2k_sched_count(sched),
               (unsigned long long)d2k_sched_refusals(sched));
        d2k_sched_free(sched);
    }
    {
        d2k_sched *sched = d2k_sched_new(4, 64);
        push_raw(sched, "oversize", 1, 10, 20);
        pop_ex(sched, "oversize", 10, 8);
        printf("oversize count=%zu refusals=%llu\n", d2k_sched_count(sched),
               (unsigned long long)d2k_sched_refusals(sched));
        d2k_sched_free(sched);
    }
    {
        d2k_sched *sched = d2k_sched_new(4, 64);
        push_raw(sched, "next", 1, 5000, 8);
        printf("next next=%llu\n",
               (unsigned long long)d2k_sched_next_ns(sched));
        pop_ex(sched, "next", 4999, 64);
        printf("next next=%llu\n",
               (unsigned long long)d2k_sched_next_ns(sched));
        pop_ex(sched, "next", 5000, 64);
        printf("next next=%llu\n",
               (unsigned long long)d2k_sched_next_ns(sched));
        d2k_sched_free(sched);
    }
    return 0;
}
