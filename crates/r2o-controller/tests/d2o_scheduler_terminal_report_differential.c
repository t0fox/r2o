/* C-оракул терминальных отчётов scheduler: task_reset/local-abort,
 * task_fail/failed, task_done/cancelled, remeasure_snapped/superseded,
 * d2k_sched_free/shutdown. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static d2k_diag_event observed;
static void observe(void *context, const d2k_diag_event *event) {
    (void)context;
    observed = *event;
    const char *reason_source =
        strcmp(observed.protocol, "http") == 0 ? "terminal-code"
                                                : "last-classifier-context";
    printf("event id=%llu target=%s protocol=%s family=%u trigger=%u "
           "outcome=%s path=%s probe_units=%lld elapsed_ms=%lld "
           "queue_ms=%lld ip=%s kind=%s shape=%u reason=%s reason_source=%s\n",
           (unsigned long long)observed.id, observed.target, observed.protocol,
           observed.family, observed.trigger, observed.outcome, observed.path,
           (long long)observed.probe_units, (long long)observed.elapsed_ms,
           (long long)observed.queue_ms, observed.ip, observed.kind,
           observed.shape, observed.reason, reason_source);
}

static void init_task(task *t, int index, const char *host, const char *ip,
                      uint8_t transport, uint8_t shape, int probes, int ask,
                      int64_t elapsed, int64_t queue, const char *reason) {
    memset(t, 0, sizeof *t);
    snprintf(t->name, sizeof t->name, "%s", host);
    snprintf(t->ip, sizeof t->ip, "%s", ip);
    t->transport = transport;
    t->family = 4;
    t->trigger_shape = shape;
    t->state = T_ASKING;
    t->probes = probes;
    t->ask_probes = ask;
    t->report_id = (uint64_t)index;
    t->trigger_code = (uint8_t)index;
    t->trigger_flow.family = 4;
    t->report_admitted_ms = 100000 - elapsed;
    t->report_queue_ms = queue;
    snprintf(t->res.reason, sizeof t->res.reason, "%s", reason);
}

int main(void) {
    d2k_sched *s = calloc(1, sizeof *s);
    if (!s) return 1;
    s->wake[0] = -1;
    s->wake[1] = -1;
    s->now_ms = 100000;
    s->clock_seen = 1;
    s->diagnostic = observe;
    if (pthread_mutex_init(&s->mu, NULL)) return 1;

    task t;
    init_task(&t, 1, "abort.example", "198.51.100.60", 6, 1, 5, 3, 1000,
              200, "локальный сброс");
    task_reset(s, &t);

    init_task(&t, 2, "failed.example", "198.51.100.61", 6, 1, 4, 2, 2000,
              300, "измерение без классификации");
    task_fail(s, &t, s->now_ms);

    init_task(&t, 3, "cancelled.example", "198.51.100.62", 6, 1, 3, 1, 3000,
              400, "поиск отменён");
    task_done(s, &t);

    init_task(&t, 4, "superseded.example", "198.51.100.63", 6, 1, 2, 1, 4000,
              500, "перемер снимком");
    static const uint8_t remeasure_bytes[16] = {
        0x16, 0x03, 0x01, 0x00, 0x0c, 0x01, 0x00, 0x00,
        0x08, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    remeasure_snapped(s, &t, remeasure_bytes, sizeof remeasure_bytes);

    init_task(&s->tasks[0], 5, "shutdown-a.example", "198.51.100.64", 6, 1, 1,
              1, 5000, 600, "остановка A");
    init_task(&s->tasks[1], 6, "shutdown-b.example", "198.51.100.65", 17, 3, 2,
              1, 6000, 700, "остановка B");
    s->tasks[0].state = T_ASKING;
    s->tasks[1].state = T_ASKING;
    d2k_sched_free(s);
    return 0;
}
