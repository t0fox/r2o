#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "sched.c"

static d2k_sched scheduler;
static d2k_catalog catalog;
static task probe_task;

static void run_case(int search_owned)
{
    memset(&probe_task, 0, sizeof probe_task);
    snprintf(probe_task.name, sizeof probe_task.name, "%s", "ladder.example");
    snprintf(probe_task.ip, sizeof probe_task.ip, "%s", "198.51.100.20");
    probe_task.transport = 6;
    probe_task.family = 4;
    probe_task.port = 443;
    probe_task.search_owned = search_owned;
    probe_task.owned_fallback = 0;
    probe_task.ladder_unmeasurable = 1;
    probe_task.rx_volume_candidate_pending = 0;
    probe_task.vol.rx_cut = 0;
    probe_task.vol.verdict = 0;
    probe_task.fb_next = 0;
    probe_task.n_tried = 0;
    size_t len = 0;
    if (d2k_hello_from_profile(D2K_SHAPE_MODERN, probe_task.name,
                               probe_task.trig, sizeof probe_task.trig, &len) != 0) {
        fprintf(stderr, "hello fixture failed\n");
        return;
    }
    probe_task.trig_len = len;
    size_t added = refill_from_fallback(&scheduler, &probe_task);
    printf("search_owned=%d added_nonzero=%d\n", search_owned, added > 0);
}

int main(void)
{
    memset(&scheduler, 0, sizeof scheduler);
    memset(&catalog, 0, sizeof catalog);
    scheduler.cat = &catalog;
    run_case(0);
    run_case(1);
    return 0;
}
