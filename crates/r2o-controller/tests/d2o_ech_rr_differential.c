/* C-оракул production core/sched.c: ech_rr_store / ech_rr_known.
 *
 * Включает sched.c с -ffunction-sections/-data-sections; вызываются только
 * две функции кэша HTTPS RR, остальные секции выбрасываются gc-sections.
 */
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

static void print_known(d2k_sched *scheduler, const char *label,
                        const char *name, const char *public_name)
{
    printf("%s=%d\n", label, ech_rr_known(scheduler, name, public_name));
}

int main(void)
{
    d2k_sched *scheduler = calloc(1, sizeof *scheduler);
    if (!scheduler) return 2;
    scheduler->now_ms = 1000;

    print_known(scheduler, "before", "positive.example", "public.example");
    ech_rr_store(scheduler, "positive.example", 1, "public.example");
    print_known(scheduler, "positive_match", "positive.example", "public.example");
    print_known(scheduler, "positive_other", "positive.example", "other.example");

    ech_rr_store(scheduler, "negative.example", 0, "");
    print_known(scheduler, "negative_empty", "negative.example", "");
    print_known(scheduler, "negative_other", "negative.example", "public.example");

    scheduler->now_ms = 1000 + 6LL * 3600 * 1000;
    print_known(scheduler, "positive_at_ttl", "positive.example", "public.example");
    scheduler->now_ms += 1;
    print_known(scheduler, "positive_after_ttl", "positive.example", "public.example");

    scheduler->now_ms = 1000 + 30LL * 60 * 1000;
    print_known(scheduler, "negative_at_ttl", "negative.example", "");
    scheduler->now_ms += 1;
    print_known(scheduler, "negative_after_ttl", "negative.example", "");
    free(scheduler);

    d2k_sched *ring = calloc(1, sizeof *ring);
    if (!ring) return 3;
    ring->now_ms = 1000;
    for (unsigned index = 0; index < SCHED_ECH_RR; index++) {
        char name[64];
        snprintf(name, sizeof name, "rr-%03u.example", index);
        ech_rr_store(ring, name, 1, "public.example");
    }
    /* Повтор существующего имени не двигает курсор кольца. */
    ech_rr_store(ring, "rr-000.example", 1, "public.example");
    ech_rr_store(ring, "new.example", 1, "public.example");
    print_known(ring, "ring_update_keeps_000", "rr-000.example", "public.example");
    print_known(ring, "ring_new_present", "new.example", "public.example");
    print_known(ring, "ring_next_present", "rr-001.example", "public.example");
    free(ring);
    return 0;
}
