#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include "sched.c"

static d2k_diag_event observed;
static char observed_reason[D2K_REASON_MAX];

static void observe(void *context, const d2k_diag_event *event) {
    (void)context;
    observed = *event;
    snprintf(observed_reason, sizeof observed_reason, "%s", event->reason);
}

int main(void) {
    d2k_sched *scheduler = calloc(1, sizeof *scheduler);
    task *target = calloc(1, sizeof *target);
    if (!scheduler || !target) return 1;
    if (pthread_mutex_init(&scheduler->mu, NULL)) return 1;
    scheduler->diagnostic = observe;
    snprintf(target->name, sizeof target->name, "queue-full.example");
    snprintf(target->ip, sizeof target->ip, "198.51.100.1");
    target->transport = 6;
    target->family = 4;
    target->trigger_shape = 1;
    target->report_id = 1;
    target->trigger_code = 3;
    search_report(scheduler, target, 0, "queue-full", "none");
    printf("id=%llu\nfamily=%u\ntrigger=%u\nelapsed_ms=%lld\n"
           "queue_ms=%lld\nprobe_units=%lld\ntarget=%s\nip=%s\npath=%s\n"
           "kind=%s\nshape=%u\nprotocol=%s\noutcome=%s\nreason=%s\n"
           "reason_source=last-classifier-context\n",
           (unsigned long long)observed.id, observed.family, observed.trigger,
           (long long)observed.elapsed_ms, (long long)observed.queue_ms,
           (long long)observed.probe_units, observed.target, observed.ip,
           observed.path, observed.kind, observed.shape, observed.protocol,
           observed.outcome, observed_reason);
    pthread_mutex_destroy(&scheduler->mu);
    free(target);
    free(scheduler);
    return observed.id != 1 || observed.trigger != 3 ||
           observed.elapsed_ms != 0 || observed.queue_ms != 0 ||
           observed.probe_units != 0;
}
