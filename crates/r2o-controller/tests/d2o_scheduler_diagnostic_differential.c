#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include "sched.c"

static uint64_t observed_id;
static unsigned observed_trigger;

static void observe(void *context, const d2k_diag_event *event) {
    (void)context;
    observed_id = event->id;
    observed_trigger = event->trigger;
}

int main(void) {
    d2k_sched *scheduler = calloc(1, sizeof *scheduler);
    task *target = calloc(1, sizeof *target);
    if (!scheduler || !target) return 1;
    if (pthread_mutex_init(&scheduler->mu, NULL)) return 1;
    scheduler->diagnostic = observe;
    snprintf(target->name, sizeof target->name, "diagnostic.example");
    target->transport = 6;
    target->family = 4;
    target->report_id = 1;
    target->trigger_code = 3;
    search_report(scheduler, target, 0, "inconclusive", "fallback");
    printf("id=%llu\ntrigger=%u\n", (unsigned long long)observed_id, observed_trigger);
    pthread_mutex_destroy(&scheduler->mu);
    free(target);
    free(scheduler);
    return observed_id != 1 || observed_trigger != 3;
}
