/* C/Rust differential: search_report/d2k_diag_event для всех call-site
 * исходов C sched.c: stun/discovery-confirmed, queue-full, local-abort,
 * cancelled, shutdown, failed, superseded, probe-direct, probe-partial,
 * probe-clear, probe-confirmed, unknown, inconclusive. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

static d2k_diag_event observed;
static d2k_sched s;
static void observe(void *context, const d2k_diag_event *event) {
    (void)context;
    observed = *event;
}

enum { PATH_NONE = 1, PATH_OWN, PATH_LADDER, PATH_FALLBACK, PATH_PROPERTY };

static void setup_default_path(task *t, int mode) {
    if (mode == PATH_NONE) {
        return;
    }
    t->next_plan = 1;
    t->n_plans = 1;
    snprintf(t->plans[0], sizeof t->plans[0], "plan-default-path");
    if (mode == PATH_OWN) {
        t->own_first = 2;
    } else if (mode == PATH_LADDER) {
        t->rx_hashes[0] = fnv1a(t->plans[0]);
        t->n_rx_hashes = 1;
    } else if (mode == PATH_FALLBACK) {
        t->fb_queue = 1;
        t->fb_from = 0;
    }
}

static uint64_t sequence;
static int64_t now = 100000;

static void run(const char *name, const char *host, const char *ip,
                uint8_t transport, uint8_t family, uint8_t shape,
                task_state state, int by_addr, int probes, int ask_probes,
                int clock_seen, int64_t elapsed, int64_t queue_ms,
                const char *outcome, const char *path, const char *reason,
                int default_path) {
    task t;
    memset(&t, 0, sizeof t);
    snprintf(t.name, sizeof t.name, "%s", host);
    snprintf(t.ip, sizeof t.ip, "%s", ip);
    t.transport = transport;
    t.family = family;
    t.trigger_shape = shape;
    t.state = state;
    t.by_addr = by_addr;
    t.probes = probes;
    t.ask_probes = ask_probes;
    t.report_id = ++sequence;
    t.trigger_code = strcmp(host, "@discord-voice") == 0
                         ? 3
                         : (uint8_t)(sequence & 0xff);
    t.trigger_flow.family = family;
    t.report_admitted_ms = now - elapsed;
    if (state == T_QUEUED) {
        t.report_queue_ms = 0;
        t.queued_ms = now - elapsed;
    } else {
        t.report_queue_ms = queue_ms;
        t.queued_ms = 0;
    }
    snprintf(t.res.reason, sizeof t.res.reason, "%s", reason);
    setup_default_path(&t, default_path);
    static int initialized;
    if (!initialized) {
        memset(&s, 0, sizeof s);
        if (pthread_mutex_init(&s.mu, NULL)) return;
        s.diagnostic = observe;
        initialized = 1;
    }
    s.clock_seen = clock_seen;
    s.now_ms = now;
    search_report(&s, &t, now, outcome, path);

    const char *reason_source =
        strcmp(observed.protocol, "http") == 0 ? "terminal-code"
                                                : "last-classifier-context";
    printf("%s id=%llu target=%s protocol=%s family=%u trigger=%u "
           "outcome=%s path=%s probe_units=%lld elapsed_ms=%lld "
           "queue_ms=%lld ip=%s kind=%s shape=%u reason=%s reason_source=%s\n",
           name, (unsigned long long)observed.id, observed.target,
           observed.protocol, observed.family, observed.trigger,
           observed.outcome, observed.path, (long long)observed.probe_units,
           (long long)observed.elapsed_ms, (long long)observed.queue_ms,
           observed.ip, observed.kind, observed.shape, observed.reason,
           reason_source);
}

int main(void) {
    /* Уже существовавшие 6 событий. */
    run("asking", "asking.example", "198.51.100.10", 6, 4, 1,
        T_ASKING, 0, 5, 3, 0, 1000, 1000, "inconclusive", "property",
        "проба не подтвердила", 0);
    run("queued", "queued.example", "198.51.100.11", 6, 4, 1,
        T_QUEUED, 0, 0, 0, 1, 2000, 0, "queue-full", "none",
        "очередь переполнена", 0);
    run("planning", "planning.example", "198.51.100.12", 6, 6, 2,
        T_PLANNING, 0, 2, 1, 0, 3000, 3000, "probe-confirmed", "own-plan",
        "план применён", 0);
    run("verify", "verify.example", "198.51.100.13", 17, 4, 3,
        T_VERIFY, 0, 3, 2, 0, 4000, 4000, "probe-confirmed", "ladder",
        "лестница подтверждена", 0);
    run("addr", "198.51.100.14", "198.51.100.14", 6, 4, 1,
        T_ASKING, 1, 1, 2, 0, 5000, 5000, "probe-clear", "direct",
        "адрес проходит", 0);
    run("fallback", "fallback.example", "198.51.100.15", 6, 4, 1,
        T_ASKING, 0, 4, 4, 0, 6000, 6000, "failed", "fallback",
        "нет ответа", 0);

    /* Остальные call-site исходы sched.c. */
    run("local-abort", "local-abort.example", "198.51.100.16", 6, 4, 1,
        T_ASKING, 0, 0, 0, 0, 7000, 7000, "local-abort", NULL,
        "локальный сбой", PATH_NONE);
    run("cancelled", "cancelled.example", "198.51.100.17", 6, 4, 1,
        T_ASKING, 0, 1, 0, 0, 8000, 8000, "cancelled", NULL,
        "поиск отменён", PATH_NONE);
    run("shutdown", "shutdown.example", "198.51.100.18", 6, 4, 1,
        T_ASKING, 0, 2, 1, 0, 9000, 9000, "shutdown", NULL,
        "остановка", PATH_LADDER);
    run("superseded", "superseded.example", "198.51.100.19", 6, 4, 1,
        T_ASKING, 0, 3, 1, 0, 10000, 10000, "superseded", NULL,
        "заменён новым поиском", PATH_OWN);
    run("probe-direct", "probe-direct.example", "198.51.100.20", 6, 4, 1,
        T_ASKING, 0, 4, 1, 0, 11000, 11000, "probe-direct", "direct",
        "прямой ответ", 0);
    run("unknown", "unknown.example", "198.51.100.21", 6, 4, 1,
        T_ASKING, 0, 5, 1, 0, 12000, 12000, "unknown", "none",
        "адрес не принимал соединений", 0);
    run("probe-partial", "probe-partial.example", "198.51.100.22", 6, 4, 1,
        T_ASKING, 0, 6, 1, 0, 13000, 13000, "probe-partial", "own-plan",
        "бюджет исчерпан", 0);
    run("failed-default", "failed-default.example", "198.51.100.23", 6, 4, 1,
        T_ASKING, 0, 7, 1, 0, 14000, 14000, "failed", NULL,
        "сбой по умолчанию", PATH_PROPERTY);
    run("cancelled-default", "cancelled-default.example", "198.51.100.24",
        6, 4, 1, T_ASKING, 0, 8, 1, 0, 15000, 15000, "cancelled", NULL,
        "отмена по умолчанию", PATH_FALLBACK);

    /* Голосовые call-sites: voice_finish_measure и voice_confirm. */
    run("inconclusive-voice", "@discord-voice", "198.51.100.25", 17, 4, 5,
        T_ASKING, 0, 4, 2, 0, 16000, 16000, "inconclusive", "none",
        "", 0);
    run("probe-clear-voice", "@discord-voice", "198.51.100.26", 17, 4, 5,
        T_ASKING, 0, 3, 2, 0, 17000, 17000, "probe-clear", "unknown",
        "", 0);
    run("probe-direct-voice", "@discord-voice", "198.51.100.27", 17, 4, 5,
        T_ASKING, 0, 2, 2, 0, 18000, 18000, "probe-direct", "direct",
        "", 0);
    run("stun-confirmed", "@discord-voice", "198.51.100.28", 17, 4, 5,
        T_ASKING, 0, 3, 2, 0, 19000, 200, "stun-confirmed", "property",
        "", 0);
    run("discovery-confirmed", "@discord-voice", "198.51.100.29", 17, 4, 5,
        T_ASKING, 0, 4, 2, 0, 20000, 200, "discovery-confirmed",
        "property", "", 0);

    pthread_mutex_destroy(&s.mu);
    return 0;
}
