#define _POSIX_C_SOURCE 200809L

#include <errno.h>
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

int main(int argc, char **argv) {
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
