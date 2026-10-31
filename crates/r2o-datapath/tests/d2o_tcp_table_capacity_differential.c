#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "d2k_track.h"

static void make_key(d2k_key *key, uint16_t index, int reverse) {
    uint8_t client[4] = {10, 0, (uint8_t)(index >> 8), (uint8_t)index};
    uint8_t server[4] = {203, 0, 113, 8};
    uint16_t port = (uint16_t)(10000 + index);
    uint8_t client_port[2] = {(uint8_t)(port >> 8), (uint8_t)port};
    const uint8_t server_port[2] = {1, 187};

    if (reverse) {
        (void)d2k_key_make(key, 6, server, client, server_port, client_port);
    } else {
        (void)d2k_key_make(key, 6, client, server, client_port, server_port);
    }
}

int main(void) {
    d2k_table *table = d2k_track_new(64);
    if (!table) return 2;

    size_t inserted = 0;
    for (uint16_t index = 1; index <= 48; index++) {
        d2k_key key;
        make_key(&key, index, 0);
        if (d2k_track_get(table, &key, 100) != NULL) inserted++;
    }

    d2k_key refused_a, refused_b, reverse_known;
    make_key(&refused_a, 49, 0);
    make_key(&refused_b, 50, 0);
    make_key(&reverse_known, 1, 1);
    const int first_refused = d2k_track_get(table, &refused_a, 200) == NULL;
    const int second_refused = d2k_track_get(table, &refused_b, 201) == NULL;
    const int reverse_hit = d2k_track_get(table, &reverse_known, 202) != NULL;
    const size_t count_at_limit = d2k_track_count(table);
    const uint64_t refusals_at_limit = d2k_track_refusals(table);
    const size_t expired = d2k_track_expire(table, 60202, 60000, NULL, NULL);
    const size_t count_after_expiry = d2k_track_count(table);
    const int accepted_after_expiry = d2k_track_get(table, &refused_a, 60203) != NULL;
    const uint64_t refusals_after_expiry = d2k_track_refusals(table);
    const size_t count_after_reuse = d2k_track_count(table);

    d2k_table *rounded = d2k_track_new(65);
    if (!rounded) return 3;
    printf("request64_slots=%zu_limit=%zu_inserted=%zu_refused=%d_reverse_hit=%d_count=%zu_refusals=%" PRIu64 "\n",
           d2k_track_capacity(table), d2k_track_capacity(table) - d2k_track_capacity(table) / 4,
           inserted, first_refused + second_refused, reverse_hit, count_at_limit, refusals_at_limit);
    printf("request65_slots=%zu_limit=%zu\n", d2k_track_capacity(rounded),
           d2k_track_capacity(rounded) - d2k_track_capacity(rounded) / 4);
    printf("expired=%zu_remaining=%zu_accepted_after_expiry=%d_refusals=%" PRIu64 "_count=%zu\n",
           expired, count_after_expiry, accepted_after_expiry,
           refusals_after_expiry, count_after_reuse);

    d2k_track_free(rounded);
    d2k_track_free(table);
    return inserted == 48 && first_refused && second_refused && reverse_hit &&
                   count_at_limit == 48 && refusals_at_limit == 2 && expired == 48 &&
                   count_after_expiry == 0 && accepted_after_expiry &&
                   refusals_after_expiry == 2 && count_after_reuse == 1
               ? 0
               : 1;
}
