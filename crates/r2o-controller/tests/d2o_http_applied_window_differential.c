#include "d2k_httpsearch.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int next_fd;
    unsigned open_count, set_probe_count;
    uint16_t sport_be;
    d2k_hs_job job;
    uint8_t plan_id[16], trial_id[16];
} fixture;

static int open_port(void *ctx, uint8_t family, int *fd, uint16_t *sport_be) {
    fixture *f = ctx;
    (void)family;
    *fd = 100 + f->next_fd++;
    *sport_be = htons((uint16_t)(41000 + f->open_count++));
    f->sport_be = *sport_be;
    return 0;
}

static void close_port(void *ctx, int fd) { (void)ctx; (void)fd; }

static int hex_value(char c) { return c >= 'a' ? c - 'a' + 10 : c - '0'; }

static int set_probe(void *ctx, const char *host, uint8_t family, uint16_t sport_be,
                     const char *text, const uint8_t trial_id[16]) {
    fixture *f = ctx;
    (void)host;
    (void)family;
    (void)sport_be;
    const char *id = strstr(text, "\nid ");
    if (!id) { return -1; }
    for (int i = 0; i < 16; i++) {
        f->plan_id[i] = (uint8_t)(hex_value(id[4 + 2 * i]) << 4 |
                                  hex_value(id[5 + 2 * i]));
    }
    memcpy(f->trial_id, trial_id, 16);
    f->set_probe_count++;
    return 0;
}

static int del_probe(void *ctx, const char *host, uint8_t family, uint16_t sport_be) {
    (void)ctx;
    (void)host;
    (void)family;
    (void)sport_be;
    return 0;
}

static int set_plan(void *ctx, const char *host, uint8_t family, const char *text,
                    const uint8_t token[16]) {
    (void)ctx;
    (void)host;
    (void)family;
    (void)text;
    (void)token;
    return 0;
}

static int del_plan(void *ctx, const char *host, uint8_t family,
                    const d2k_binding_context *binding) {
    (void)ctx;
    (void)host;
    (void)family;
    (void)binding;
    return 0;
}

static int start_probe(void *ctx, const d2k_hs_job *job) {
    ((fixture *)ctx)->job = *job;
    return 0;
}

static void say(void *ctx, const char *line) { (void)ctx; (void)line; }
static void changed(void *ctx) { (void)ctx; }

static d2k_httpsearch *start_candidate(fixture *f) {
    d2k_hs_ops ops = {open_port, close_port, set_probe, del_probe, set_plan, del_plan,
                      start_probe, say, changed, f};
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    if (!hs) { return NULL; }
    static const uint8_t server[16] = {37, 221, 67, 160};
    d2k_httpsearch_portal(hs, "rutracker.org", 4, server, 1);

    d2k_hs_result base = {0};
    base.answer = D2K_HS_INJECTED;
    base.seq = f->job.seq;
    base.fd = f->job.fd;
    base.requests_sent = 2;
    base.local_ip[0] = 127;
    base.local_ip[3] = 1;
    base.local_port = ntohs(f->sport_be);
    d2k_httpsearch_result(hs, &base, 2);
    if (f->set_probe_count != 1) { d2k_httpsearch_free(hs); return NULL; }

    d2k_httpsearch_ack(hs, f->trial_id, 1, 3);
    d2k_hs_result trial = {0};
    trial.answer = D2K_HS_INJECTED;
    trial.seq = f->job.seq;
    trial.fd = f->job.fd;
    trial.requests_sent = 2;
    trial.local_ip[0] = 127;
    trial.local_ip[3] = 1;
    trial.local_port = ntohs(f->sport_be);
    d2k_httpsearch_result(hs, &trial, 100);
    return hs;
}

static d2k_ev applied_event(const fixture *f, uint64_t execution_id) {
    static const uint8_t server[16] = {37, 221, 67, 160};
    d2k_ev event = {0};
    event.kind = D2K_EV_APPLIED;
    event.family = 4;
    event.transport = 6;
    event.low_ip[0] = 127;
    event.low_ip[3] = 1;
    memcpy(event.high_ip, server, sizeof server);
    event.low_port = ntohs(f->sport_be);
    event.high_port = 80;
    memcpy(event.plan_id, f->plan_id, 16);
    memcpy(event.trial_id, f->trial_id, 16);
    event.execution_id = execution_id;
    event.execution_binding.epoch[0] = 7;
    event.execution_binding.generation = 1;
    event.execution_binding.family = 4;
    event.execution_binding.kind = D2K_BIND_NAME;
    event.execution_binding.shape = D2K_PLAN_SHAPE_HTTP;
    event.execution_binding.temporary = 1;
    return event;
}

static unsigned in_window_count(void) {
    fixture f = {0};
    d2k_httpsearch *hs = start_candidate(&f);
    if (!hs) { return 99; }
    d2k_ev first = applied_event(&f, 1);
    d2k_ev duplicate = first;
    d2k_ev second = applied_event(&f, 2);
    unsigned accepted = 0;
    accepted += (unsigned)d2k_httpsearch_control(hs, &first, 101);
    accepted += (unsigned)d2k_httpsearch_control(hs, &duplicate, 102);
    d2k_httpsearch_tick(hs, 599);
    accepted += (unsigned)d2k_httpsearch_control(hs, &second, 599);
    d2k_httpsearch_free(hs);
    return accepted;
}

static unsigned outside_window_count(void) {
    fixture f = {0};
    d2k_httpsearch *hs = start_candidate(&f);
    if (!hs) { return 99; }
    d2k_ev first = applied_event(&f, 1);
    d2k_ev second = applied_event(&f, 2);
    unsigned accepted = (unsigned)d2k_httpsearch_control(hs, &first, 101);
    d2k_httpsearch_tick(hs, 600);
    accepted += (unsigned)d2k_httpsearch_control(hs, &second, 601);
    d2k_httpsearch_free(hs);
    return accepted;
}

int main(void) {
    d2k_hs_probe_ms = 100;
    unsigned inside = in_window_count();
    unsigned outside = outside_window_count();
    if (inside != 2 || outside != 1) {
        fprintf(stderr, "unexpected donor APPLIED counts: inside=%u outside=%u\n",
                inside, outside);
        return 1;
    }
    printf("inside=%u\noutside=%u\n", inside, outside);
    return 0;
}
