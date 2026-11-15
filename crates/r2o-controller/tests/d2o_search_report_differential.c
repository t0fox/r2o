/* C/Rust differential: search_report/d2k_diag_event для 6 событий. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static d2k_diag_event observed;
static void observe(void *context, const d2k_diag_event *event) {
    (void)context;
    observed = *event;
}

typedef struct {
    const char *name;
    const char *host;
    const char *ip;
    uint8_t transport, family, shape;
    task_state state;
    int by_addr;
    int probes, ask_probes;
    int64_t report_queue_ms, queued_ms;
    int clock_seen;
    const char *outcome, *path;
} scenario;

int main(void) {
    static d2k_sched s;
    static d2k_catalog cat;
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    if (pthread_mutex_init(&s.mu, NULL)) return 1;
    s.cat = &cat;
    s.diagnostic = observe;

    const int64_t now = 10000;
    const scenario scenarios[] = {
        {"asking", "asking.example", "198.51.100.10", 6, 4, 1,
         T_ASKING, 0, 5, 3, 2000, 0, 0, "inconclusive", "property"},
        {"queued", "queued.example", "198.51.100.11", 6, 4, 1,
         T_QUEUED, 0, 0, 0, 1000, 6000, 1, "queue-full", "none"},
        {"planning", "planning.example", "198.51.100.12", 6, 6, 2,
         T_PLANNING, 0, 2, 1, 3000, 0, 0, "probe-confirmed", "own-plan"},
        {"verify", "verify.example", "198.51.100.13", 17, 4, 3,
         T_VERIFY, 0, 3, 2, 4000, 0, 0, "probe-confirmed", "ladder"},
        {"addr", "198.51.100.14", "198.51.100.14", 6, 4, 1,
         T_ASKING, 1, 1, 2, 5000, 0, 0, "probe-clear", "direct"},
        {"fallback", "fallback.example", "198.51.100.15", 6, 4, 1,
         T_ASKING, 0, 4, 4, 6000, 0, 0, "failed", "fallback"},
    };
    for (size_t i = 0; i < sizeof scenarios / sizeof scenarios[0]; i++) {
        task t;
        memset(&t, 0, sizeof t);
        snprintf(t.name, sizeof t.name, "%s", scenarios[i].host);
        snprintf(t.ip, sizeof t.ip, "%s", scenarios[i].ip);
        t.transport = scenarios[i].transport;
        t.family = scenarios[i].family;
        t.trigger_shape = scenarios[i].shape;
        t.state = scenarios[i].state;
        t.by_addr = scenarios[i].by_addr;
        t.probes = scenarios[i].probes;
        t.ask_probes = scenarios[i].ask_probes;
        t.report_id = (uint64_t)i + 1;
        const int64_t elapsed = (int64_t)(i * 1000 + 1000);
        t.report_admitted_ms = now - elapsed;
        if (scenarios[i].state == T_QUEUED) {
            t.report_queue_ms = 0;
            t.queued_ms = now - elapsed;
        } else {
            t.report_queue_ms = elapsed;
            t.queued_ms = 0;
        }
        t.trigger_code = (uint8_t)i + 1;
        t.trigger_flow.family = scenarios[i].family;
        s.clock_seen = scenarios[i].clock_seen;
        s.now_ms = now;
        search_report(&s, &t, now, scenarios[i].outcome, scenarios[i].path);
        printf("%s id=%llu target=%s protocol=%s family=%u trigger=%u "
               "outcome=%s path=%s probe_units=%lld elapsed_ms=%lld "
               "queue_ms=%lld ip=%s kind=%s shape=%u\n",
               scenarios[i].name, (unsigned long long)observed.id,
               observed.target, observed.protocol, observed.family,
               observed.trigger, observed.outcome, observed.path,
               (long long)observed.probe_units, (long long)observed.elapsed_ms,
               (long long)observed.queue_ms, observed.ip, observed.kind,
               observed.shape);
    }
    pthread_mutex_destroy(&s.mu);
    return 0;
}
