#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include "sched.c"

static d2k_diag_event observed;

static void observe(void *context, const d2k_diag_event *event) {
    (void)context;
    observed = *event;
}

int main(void) {
    d2k_sched *scheduler = calloc(1, sizeof *scheduler);
    task *target = calloc(1, sizeof *target);
    if (!scheduler || !target) return 1;
    if (pthread_mutex_init(&scheduler->mu, NULL)) return 1;
    scheduler->diagnostic = observe;
    snprintf(target->name, sizeof target->name, "timing.example");
    target->transport = 6;
    target->family = 4;
    target->report_id = 1;
    target->trigger_code = 3;
    target->report_admitted_ms = 0;
    target->report_queue_ms = 6000;
    target->probes = 5;
    target->ask_probes = 3;
    search_report(scheduler, target, 10000, "inconclusive", "fallback");
    printf("elapsed_ms=%lld\nqueue_ms=%lld\nprobe_units=%lld\n",
           (long long)observed.elapsed_ms, (long long)observed.queue_ms,
           (long long)observed.probe_units);
    pthread_mutex_destroy(&scheduler->mu);
    free(target);
    free(scheduler);
    return observed.elapsed_ms != 10000 || observed.queue_ms != 6000 ||
           observed.probe_units != 8;
}
