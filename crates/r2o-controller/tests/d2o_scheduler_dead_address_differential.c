#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

int d2k_hello_ech_offer(const uint8_t *bytes, size_t length, uint8_t *config_id)
{
    (void)bytes;
    (void)length;
    (void)config_id;
    return 0;
}

int main(void)
{
    d2k_sched *scheduler = calloc(1, sizeof *scheduler);
    if (!scheduler) return 1;
    task address = {0};
    snprintf(address.name, sizeof address.name, "%s", "dead.example");
    snprintf(address.ip, sizeof address.ip, "%s", "192.0.2.10");
    address.port = 443;
    address.transport = 6;
    address.family = 4;

    scheduler->now_ms = 1000;
    int64_t first = dead_step(scheduler, &address);
    dead_address *entry = dead_find(scheduler, address.name, address.transport,
                                    address.family, address.ip);
    printf("dead_retry_seconds %lld", (long long)(first / 1000));
    scheduler->now_ms = entry->until_ms;
    int64_t second = dead_step(scheduler, &address);
    printf(" %lld", (long long)(second / 1000));
    entry = dead_find(scheduler, address.name, address.transport,
                      address.family, address.ip);
    scheduler->now_ms = entry->until_ms;
    int64_t third = dead_step(scheduler, &address);
    printf(" %lld\n", (long long)(third / 1000));
    entry = dead_find(scheduler, address.name, address.transport,
                      address.family, address.ip);
    printf("dead_recheck_retains_expired_record %d\n", entry != NULL);
    printf("dead_other_ip_allowed %d\n",
           dead_find(scheduler, address.name, address.transport, address.family,
                     "192.0.2.11") == NULL);
    printf("dead_other_name_allowed %d\n",
           dead_find(scheduler, "other.example", address.transport, address.family,
                     address.ip) == NULL);
    printf("dead_other_transport_allowed %d\n",
           dead_find(scheduler, address.name, 17, address.family, address.ip) == NULL);
    printf("dead_other_family_allowed %d\n",
           dead_find(scheduler, address.name, address.transport, 6, address.ip) == NULL);
    /* The donor key intentionally omits port: every service on that address is blocked. */
    task another_port = address;
    another_port.port = 8443;
    printf("dead_same_ip_other_port_blocked %d\n",
           dead_find(scheduler, another_port.name, another_port.transport,
                     another_port.family, another_port.ip) != NULL);
    memset(entry, 0, sizeof *entry);
    printf("dead_clear_allows_address %d\n",
           dead_find(scheduler, address.name, address.transport,
                     address.family, address.ip) == NULL);
    free(scheduler);

    d2k_sched *ring = calloc(1, sizeof *ring);
    if (!ring) return 2;
    for (unsigned index = 0; index < SCHED_COOLDOWN_SLOTS; index++) {
        task slot = {0};
        snprintf(slot.name, sizeof slot.name, "ring-%03u.example", index);
        snprintf(slot.ip, sizeof slot.ip, "192.0.2.%u", index + 1);
        slot.transport = 6;
        slot.family = 4;
        ring->now_ms = 1000 + (int64_t)index;
        dead_step(ring, &slot);
    }
    task replacement = {0};
    snprintf(replacement.name, sizeof replacement.name, "%s", "ring-new.example");
    snprintf(replacement.ip, sizeof replacement.ip, "%s", "198.51.100.1");
    replacement.transport = 6;
    replacement.family = 4;
    ring->now_ms = 2000;
    dead_step(ring, &replacement);
    printf("dead_ring_evicts_earliest %d\n",
           dead_find(ring, "ring-000.example", 6, 4, "192.0.2.1") == NULL);
    printf("dead_ring_keeps_next %d\n",
           dead_find(ring, "ring-001.example", 6, 4, "192.0.2.2") != NULL);
    printf("dead_ring_keeps_new %d\n",
           dead_find(ring, "ring-new.example", 6, 4, "198.51.100.1") != NULL);
    free(ring);
    return 0;
}
