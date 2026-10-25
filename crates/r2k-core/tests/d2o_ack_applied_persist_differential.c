#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sched.c"
#include "d2k_udpruntime.h"

int d2k_plan_load(const uint8_t *buf, size_t len, d2k_plan **out,
                  char *err, size_t errlen) {
    (void)buf; (void)len; (void)out; (void)err; (void)errlen; abort();
}
void d2k_plan_free(d2k_plan *plan) { (void)plan; abort(); }
size_t d2k_plan_max_emit(const d2k_plan *plan) { (void)plan; abort(); }
int d2k_voice_arm_plan(const uint8_t *decoy, size_t dlen, unsigned copies,
                       char *buf, size_t cap) {
    (void)decoy; (void)dlen; (void)copies; (void)buf; (void)cap; abort();
}
int d2k_quic_compose_plan(const d2k_quic_arm *arm, const d2k_quic_props *props,
                          char *buf, size_t cap) {
    (void)arm; (void)props; (void)buf; (void)cap; abort();
}
int d2k_quic_question_plan(const d2k_quic_arm_question *question,
                           char *text, size_t cap) {
    (void)question; (void)text; (void)cap; abort();
}
int d2k_udp_plan_send(int fd, const char *text, const uint8_t *payload,
                      size_t len, uint32_t mark) {
    (void)fd; (void)text; (void)payload; (void)len; (void)mark; abort();
}

static int decode_hex(const char *text, uint8_t *out, size_t cap, size_t *len) {
    size_t n = strlen(text);
    if ((n & 1u) || n / 2 > cap) return -1;
    for (size_t i = 0; i < n; i += 2) {
        char byte[3] = {text[i], text[i + 1], '\0'};
        char *end = NULL;
        unsigned long value = strtoul(byte, &end, 16);
        if (!end || *end || value > 255) return -1;
        out[i / 2] = (uint8_t)value;
    }
    *len = n / 2;
    return 0;
}

static int write_all(int fd, const uint8_t *bytes, size_t len) {
    while (len) {
        ssize_t n = write(fd, bytes, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        bytes += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_fixture(const char *path, uint8_t *ack, size_t *ack_len,
                        uint8_t *applied, size_t *applied_len,
                        char *name, size_t name_cap, char ip[46],
                        uint16_t *local_port, uint16_t *server_port,
                        unsigned *status, unsigned long *save_interval_ms) {
    FILE *fixture = fopen(path, "r");
    if (!fixture) return -1;
    char kind[32], value[1024], extra;
    unsigned seen = 0;
    while (fscanf(fixture, "%31s %1023s", kind, value) == 2) {
        if (kind[0] == '#') {
            int ch;
            while ((ch = fgetc(fixture)) != '\n' && ch != EOF) { }
            continue;
        }
        if (strcmp(kind, "ACK") == 0) {
            if (decode_hex(value, ack, 256, ack_len) != 0) goto fail;
            seen |= 1u;
        } else if (strcmp(kind, "APPLIED") == 0) {
            if (decode_hex(value, applied, 256, applied_len) != 0) goto fail;
            seen |= 2u;
        } else if (strcmp(kind, "TARGET") == 0) {
            snprintf(name, name_cap, "%s", value);
            if (fscanf(fixture, "%45s %hu %hu %u%c", ip, local_port,
                       server_port, status, &extra) < 4) goto fail;
            seen |= 4u;
        } else if (strcmp(kind, "SAVE_INTERVAL_MS") == 0) {
            char *end = NULL;
            *save_interval_ms = strtoul(value, &end, 10);
            if (!end || *end || *save_interval_ms == 0) goto fail;
            seen |= 8u;
        } else {
            goto fail;
        }
    }
    fclose(fixture);
    if (seen != 15u) fprintf(stderr, "fixture fields seen=0x%x\n", seen);
    return seen == 15u ? 0 : -1;
fail:
    fprintf(stderr, "malformed fixture row: %s %s\n", kind, value);
    fclose(fixture);
    return -1;
}

typedef struct {
    jmp_buf checkpoint;
    int reached_failure;
} fallback_gate_capture;

static void capture_fallback_gate(void *context, const char *line) {
    fallback_gate_capture *capture = context;
    if (capture->reached_failure) longjmp(capture->checkpoint, 1);
    if (strstr(line, "беру следующего кандидата")) capture->reached_failure = 1;
}

static int fallback_gate_cases(void) {
    for (unsigned mode = 0; mode < 12; mode++) {
        d2k_catalog catalog = {0};
        d2k_sched *scheduler = d2k_sched_new(&catalog, -1, 0);
        fallback_gate_capture *capture = calloc(1, sizeof *capture);
        if (!scheduler || !capture) return 30;
        task *candidate = &scheduler->tasks[0];
        task_reset(scheduler, candidate);
        candidate->state = T_VERIFY;
        candidate->res_ready = 1;
        candidate->transport = mode == 1 ? 17 : 6;
        candidate->family = 4;
        candidate->started_ms = 1000;
        candidate->search_owned = mode != 2;
        candidate->owned_fallback = mode == 3;
        candidate->own_first = mode == 4 ? 2 : 0;
        candidate->n_plans = candidate->next_plan = 1;
        candidate->n_known = mode == 5 ? 1 : 0;
        candidate->probes = sched_probe_cap(candidate);
        snprintf(candidate->name, sizeof candidate->name, "gate.example");
        snprintf(candidate->ip, sizeof candidate->ip, "198.51.100.2");
        candidate->port = 443;
        snprintf(candidate->plans[0], sizeof candidate->plans[0], "d2k-plan 1 5\nproto tcp tls\n");
        candidate->arm_hash = mode == 6 ? 0 : fnv1a(candidate->plans[0]);
        if (mode == 7) candidate->arm_hash++;
        candidate->ver.local_port = 42000;
        candidate->ver.local_ip4[0] = 192;
        candidate->ver.local_ip4[2] = 2;
        candidate->ver.local_ip4[3] = 1;
        candidate->ver.level = mode == 11 ? D2K_VER_NOT_MEASURED : D2K_VER_HANDSHAKE;
        candidate->ver.local_limit = mode == 9;
        candidate->ver_dropped0 = 7;
        scheduler->dropped_seen = mode == 10 ? 8 : 7;
        if (mode != 8) {
            candidate->ver_seen = 1;
            d2k_flowkey *applied = &candidate->ver_early[0];
            applied->family = 4;
            applied->transport = candidate->transport;
            memcpy(applied->a_ip, candidate->ver.local_ip4, 4);
            applied->a_port = candidate->ver.local_port;
            inet_pton(AF_INET, candidate->ip, applied->b_ip);
            applied->b_port = candidate->port;
        }
        d2k_sched_set_say(scheduler, capture_fallback_gate, capture);
        /* Stop at the next log after the transition, before planning can start work. */
        if (setjmp(capture->checkpoint) == 0) d2k_sched_tick(scheduler, 1001);
        scheduler->say_fn = NULL;
        if (!capture->reached_failure) return 31;
        printf("%u %d\n", mode, candidate->owned_fallback != 0);
        d2k_sched_free(scheduler);
        d2k_catalog_free(&catalog);
        free(capture);
    }
    return 0;
}

static int fallback_queue_cases(void) {
    for (unsigned shape = 1; shape <= 2; shape++) {
        d2k_catalog catalog = {0};
        d2k_sched *scheduler = d2k_sched_new(&catalog, -1, 0);
        if (!scheduler) return 40;
        task *candidate = &scheduler->tasks[0];
        task_reset(scheduler, candidate);
        candidate->transport = 6;
        candidate->search_owned = candidate->owned_fallback = 1;
        if (d2k_hello_from_profile((d2k_shape)shape, "queue.example", candidate->trig,
                                  sizeof candidate->trig, &candidate->trig_len)) return 41;
        char measured[4096];
        if (d2k_fallback_plan(12, (d2k_shape)shape, SCHED_DECOY, 1492, measured, sizeof measured)) return 42;
        tried_add(candidate, (uint32_t)fnv1a(measured));
        unsigned emitted = 0;
        for (;;) {
            scheduler->send_cap = emitted < 3 ? 1492 : emitted < 13 ? 1200 : 100;
            if (candidate->next_plan >= candidate->n_plans && !refill_from_fallback(scheduler, candidate)) break;
            const char *text = candidate->plans[candidate->next_plan++];
            printf("%u %u %u\n%s", shape, emitted++, (uint32_t)fnv1a(text), text);
        }
        if (emitted <= 30) return 43;
        d2k_sched_free(scheduler);
        d2k_catalog_free(&catalog);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--snapshot-owner")) {
        for (unsigned mode = 0; mode < 8; mode++) {
            d2k_catalog catalog = {0};
            d2k_sched *scheduler = d2k_sched_new(&catalog, -1, 0);
            if (!scheduler) return 50;
            task *candidate = &scheduler->tasks[0];
            task_reset(scheduler, candidate);
            candidate->state = T_ASKING;
            candidate->transport = 6;
            candidate->family = 4;
            candidate->trigger_shape = candidate->asked_shape = D2K_SHAPE_MODERN;
            candidate->trig_snapped = (mode & 1) != 0;
            candidate->reasked = (mode & 2) != 0;
            snprintf(candidate->name, sizeof candidate->name, "owner.example");
            d2k_shape input_shape = (mode & 4) ? D2K_SHAPE_LEGACY : D2K_SHAPE_MODERN;
            if (d2k_hello_from_profile(D2K_SHAPE_MODERN, candidate->name,
                candidate->trig, sizeof candidate->trig, &candidate->trig_len)) return 51;
            d2k_ev event = {0};
            event.transport = 6;
            event.family = 4;
            snprintf(event.name, sizeof event.name, "%s", candidate->name);
            if (d2k_hello_from_profile(input_shape, candidate->name,
                event.shape, sizeof event.shape, &event.shape_len)) return 51;
            on_shape(scheduler, &event);
            printf("%u %d\n", mode, candidate->stop != 0);
            if ((candidate->stop != 0) != (mode == 0)) return 52;
            d2k_sched_free(scheduler);
            d2k_catalog_free(&catalog);
        }
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--fallback-queue")) return fallback_queue_cases();
    if (argc == 2 && !strcmp(argv[1], "--fallback-gate")) return fallback_gate_cases();
    if (argc == 2 && !strcmp(argv[1], "--task-deadline")) {
        const int64_t elapsed[] = {0, 590999, 591000, 591001, 599999, 600000, 600001};
        for (size_t i = 0; i < sizeof elapsed / sizeof elapsed[0]; i++) {
            d2k_catalog catalog = {0};
            d2k_sched *scheduler = d2k_sched_new(&catalog, -1, 0);
            if (!scheduler) return 20;
            task *candidate = &scheduler->tasks[0];
            task_reset(scheduler, candidate);
            candidate->state = T_SHAPE_WAIT;
            candidate->transport = 17;
            candidate->family = 4;
            candidate->started_ms = 1000;
            d2k_sched_tick(scheduler, 1000 + elapsed[i]);
            int remains = candidate->state == T_SHAPE_WAIT;
            printf("%lld %d\n", (long long)elapsed[i], remains);
            if (remains != (elapsed[i] <= SCHED_TASK_LIFE_MS)) return 21;
            d2k_sched_free(scheduler);
            d2k_catalog_free(&catalog);
        }
        return 0;
    }
    if (argc != 3) return 2;
    uint8_t ack_wire[256], applied_wire[256];
    size_t ack_len = 0, applied_len = 0;
    char name[256], ip[46];
    uint16_t local_port = 0, server_port = 0;
    unsigned status = 0;
    unsigned long save_interval_ms = 0;
    if (read_fixture(argv[1], ack_wire, &ack_len, applied_wire, &applied_len,
                     name, sizeof name, ip, &local_port,
                     &server_port, &status, &save_interval_ms) != 0) {
        fprintf(stderr, "invalid shared chain fixture\n");
        return 3;
    }

    d2k_catalog catalog = {0}, saved = {0};
    d2k_sched *scheduler = d2k_sched_new(&catalog, -1, 0);
    if (!scheduler) {
        fprintf(stderr, "d2k_sched_new failed\n");
        return 4;
    }
    task *candidate = &scheduler->tasks[0];
    candidate->state = T_TRIAL_SETTLE;
    candidate->probe_fd = -1;
    memset(candidate->trial_ack_id, 0x22, sizeof candidate->trial_ack_id);

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        fprintf(stderr, "socketpair failed\n");
        return 5;
    }
    if (write_all(fds[1], ack_wire, ack_len) != 0 ||
        write_all(fds[1], applied_wire, applied_len) != 0) return 6;

    char err[256] = {0};
    d2k_ev event;
    int rc = d2k_link_next(fds[0], &event, 1000, err, sizeof err);
    if (rc != 0 ||
        event.kind != D2K_EV_ACK || d2k_sched_event(scheduler, &event) != 0 ||
        !candidate->trial_acked) {
        fprintf(stderr, "candidate ACK rejected: rc=%d kind=%d code=0x%04x trial=%02x state=%d acked=%d: %s\n",
                rc, (int)event.kind, event.code, event.trial_id[0],
                (int)candidate->state, candidate->trial_acked, err);
        return 7;
    }

    candidate->state = T_VERIFY_WAIT;
    candidate->family = 4;
    candidate->transport = 6;
    snprintf(candidate->name, sizeof candidate->name, "%s", name);
    snprintf(candidate->ip, sizeof candidate->ip, "%s", ip);
    candidate->port = server_port;
    candidate->n_plans = 1;
    candidate->next_plan = 1;
    snprintf(candidate->plans[0], sizeof candidate->plans[0],
             "d2k-plan 1 6\nproto tcp tls\n");
    memset(candidate->ver_plan_id, 0x11, sizeof candidate->ver_plan_id);
    candidate->ver.fd = -1;
    candidate->ver.level = D2K_VER_APPLICATION;
    candidate->ver.status = (int)status;
    candidate->ver.name_ok = 1;

    if (d2k_link_next(fds[0], &event, 1000, err, sizeof err) != 0 ||
        event.kind != D2K_EV_APPLIED) {
        fprintf(stderr, "APPLIED frame rejected: %s\n", err);
        return 8;
    }
    candidate->ver_flow.family = event.family;
    candidate->ver_flow.transport = event.transport;
    memcpy(candidate->ver_flow.a_ip, event.low_ip, sizeof event.low_ip);
    memcpy(candidate->ver_flow.b_ip, event.high_ip, sizeof event.high_ip);
    candidate->ver_flow.a_port = event.low_port;
    candidate->ver_flow.b_port = event.high_port;
    if (d2k_sched_event(scheduler, &event) != 0 || !candidate->ver_ok) {
        fprintf(stderr, "APPLIED did not prove this candidate flow\n");
        return 9;
    }
    verify_confirm(scheduler, candidate, 1);
    close(fds[0]);
    close(fds[1]);

    if (catalog.n_boxes == 0 || catalog.boxes[0].n_binds != 1 ||
        strcmp(catalog.boxes[0].binds[0].target, name) != 0 ||
        catalog.boxes[0].binds[0].level != 3) {
        fprintf(stderr, "verify_confirm did not add level-3 target binding\n");
        return 10;
    }
    if (d2k_catalog_save_atomic(&catalog, argv[2], err, sizeof err) != 0 ||
        d2k_catalog_load(argv[2], &saved, err, sizeof err) != 0) {
        fprintf(stderr, "catalog persistence failed: %s\n", err);
        return 11;
    }
    if (saved.n_boxes == 0 || saved.boxes[0].n_binds != 1 ||
        strcmp(saved.boxes[0].binds[0].target, name) != 0 ||
        saved.boxes[0].binds[0].level != 3) {
        fprintf(stderr, "persisted catalog lost level-3 target binding\n");
        return 12;
    }

    printf("candidate_chain ack=yes applied=yes catalog_binding=%s level=3 persisted=yes save_interval_ms=%lu\n",
           name, save_interval_ms);
    d2k_catalog_free(&saved);
    d2k_catalog_free(&catalog);
    d2k_sched_free(scheduler);
    return 0;
}
