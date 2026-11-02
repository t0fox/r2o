#include "d2k_httpsearch.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int next_fd;
    unsigned open_count, set_probe_count;
    uint8_t family;
    uint8_t client[16], server[16];
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

static d2k_httpsearch *start_candidate(fixture *f, uint8_t family) {
    f->family = family;
    if (family == 6) {
        if (inet_pton(AF_INET6, "2001:db8::1", f->client) != 1 ||
            inet_pton(AF_INET6, "2001:db8::4", f->server) != 1) {
            return NULL;
        }
    } else if (inet_pton(AF_INET, "127.0.0.1", f->client) != 1 ||
               inet_pton(AF_INET, "37.221.67.160", f->server) != 1) {
        return NULL;
    }

    d2k_hs_ops ops = {open_port, close_port, set_probe, del_probe, set_plan, del_plan,
                      start_probe, say, changed, f};
    d2k_httpsearch *hs = d2k_httpsearch_new(&ops);
    if (!hs) { return NULL; }
    d2k_httpsearch_portal(hs, "rutracker.org", family, f->server, 1);

    d2k_hs_result base = {0};
    base.answer = D2K_HS_INJECTED;
    base.seq = f->job.seq;
    base.fd = f->job.fd;
    base.requests_sent = 2;
    memcpy(base.local_ip, f->client, sizeof base.local_ip);
    base.local_port = ntohs(f->sport_be);
    d2k_httpsearch_result(hs, &base, 2);
    if (f->set_probe_count != 1) { d2k_httpsearch_free(hs); return NULL; }

    d2k_httpsearch_ack(hs, f->trial_id, 1, 3);
    d2k_hs_result trial = {0};
    trial.answer = D2K_HS_INJECTED;
    trial.seq = f->job.seq;
    trial.fd = f->job.fd;
    trial.requests_sent = 2;
    memcpy(trial.local_ip, f->client, sizeof trial.local_ip);
    trial.local_port = ntohs(f->sport_be);
    d2k_httpsearch_result(hs, &trial, 100);
    return hs;
}

static d2k_ev applied_event(const fixture *f, uint64_t execution_id) {
    d2k_ev event = {0};
    event.kind = D2K_EV_APPLIED;
    event.family = f->family;
    event.transport = 6;
    memcpy(event.low_ip, f->client, sizeof event.low_ip);
    memcpy(event.high_ip, f->server, sizeof event.high_ip);
    event.low_port = ntohs(f->sport_be);
    event.high_port = 80;
    memcpy(event.plan_id, f->plan_id, 16);
    memcpy(event.trial_id, f->trial_id, 16);
    event.execution_id = execution_id;
    event.execution_binding.epoch[0] = 7;
    event.execution_binding.generation = 1;
    event.execution_binding.family = f->family;
    event.execution_binding.kind = D2K_BIND_NAME;
    event.execution_binding.shape = D2K_PLAN_SHAPE_HTTP;
    event.execution_binding.temporary = 1;
    return event;
}

static unsigned in_window_count(uint8_t family) {
    fixture f = {0};
    d2k_httpsearch *hs = start_candidate(&f, family);
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

static unsigned outside_window_count(uint8_t family) {
    fixture f = {0};
    d2k_httpsearch *hs = start_candidate(&f, family);
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
    unsigned inside4 = in_window_count(4);
    unsigned outside4 = outside_window_count(4);
    unsigned inside6 = in_window_count(6);
    unsigned outside6 = outside_window_count(6);
    if (inside4 != 2 || outside4 != 1 || inside6 != 2 || outside6 != 1) {
        fprintf(stderr, "unexpected donor APPLIED counts: ipv4 inside=%u outside=%u; "
                        "ipv6 inside=%u outside=%u\n",
                inside4, outside4, inside6, outside6);
        return 1;
    }
    printf("ipv4_inside=%u\nipv4_outside=%u\nipv6_inside=%u\nipv6_outside=%u\n",
           inside4, outside4, inside6, outside6);
    return 0;
}
