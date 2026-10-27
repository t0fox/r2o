#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sched.c"

static d2k_diag_event observed;
static char target[128], protocol[32], outcome[32], reason[128], ip[64], path[32], kind[16];

static void copy_field(char *to, size_t capacity, const char *from) {
    snprintf(to, capacity, "%s", from ? from : "");
}

static void observe(void *context, const d2k_diag_event *event) {
    (void)context;
    observed = *event;
    copy_field(target, sizeof target, event->target);
    copy_field(protocol, sizeof protocol, event->protocol);
    copy_field(outcome, sizeof outcome, event->outcome);
    copy_field(reason, sizeof reason, event->reason);
    copy_field(ip, sizeof ip, event->ip);
    copy_field(path, sizeof path, event->path);
    copy_field(kind, sizeof kind, event->kind);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    d2k_sched *scheduler = calloc(1, sizeof *scheduler);
    task *search = calloc(1, sizeof *search);
    if (!scheduler || !search) return 1;
    if (pthread_mutex_init(&scheduler->mu, NULL)) return 1;
    scheduler->diagnostic = observe;
    snprintf(search->name, sizeof search->name, "@discord-voice");
    snprintf(search->ip, sizeof search->ip, "104.29.156.5");
    search->transport = 17;
    search->family = 4;
    search->trigger_code = 3;
    search->trigger_shape = 5;
    search->report_id = 1;
    search->report_admitted_ms = 100;
    search->report_queue_ms = 200;
    search->state = T_VOICE_TRIAL;
    search->n_plans = 1;
    search->next_plan = 1;
    search->probes = 35;
    search_report(scheduler, search, 6100, argv[1], NULL);
    printf("id=%llu\nfamily=%u\ntrigger=%u\nelapsed_ms=%lld\nqueue_ms=%lld\nprobe_units=%lld\n"
           "target=%s\nip=%s\npath=%s\nkind=%s\nshape=%u\nprotocol=%s\noutcome=%s\nreason=%s\n",
           (unsigned long long)observed.id, observed.family, observed.trigger,
           (long long)observed.elapsed_ms, (long long)observed.queue_ms,
           (long long)observed.probe_units, target, ip, path, kind,
           observed.shape, protocol, outcome, reason);
    pthread_mutex_destroy(&scheduler->mu);
    free(search);
    free(scheduler);
    return 0;
}
