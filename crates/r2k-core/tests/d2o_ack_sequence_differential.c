#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"
#include "d2k_udpruntime.h"

static unsigned spawn_attempts;
static int reject_spawn(void) {
    spawn_attempts++;
    return -1;
}

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

static int parse_id(const char *text, uint8_t id[D2K_TRIAL_ID_LEN]) {
    if (strlen(text) != D2K_TRIAL_ID_LEN * 2) return -1;
    for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) {
        char byte[3] = {text[i * 2], text[i * 2 + 1], '\0'};
        char *end = NULL;
        unsigned long value = strtoul(byte, &end, 16);
        if (!end || *end || value > 255) return -1;
        id[i] = (uint8_t)value;
    }
    return 0;
}

static int begin_candidate(d2k_sched *scheduler, unsigned long command,
                           const char *trial_text) {
    memset(scheduler, 0, sizeof *scheduler);
    scheduler->wake[0] = -1;
    scheduler->wake[1] = -1;
    task *candidate = &scheduler->tasks[0];
    candidate->state = T_TRIAL_SETTLE;
    if (command == D2K_CMD_SET_NAME_PROBE) {
        return parse_id(trial_text, candidate->trial_ack_id);
    }
    if (command == D2K_CMD_SET_ADDR_PROBE) {
        candidate->by_addr = 1;
        return parse_id(trial_text, candidate->addr_probe_trial_id);
    }
    return -1;
}

static int print_candidate_result(const d2k_sched *scheduler,
                                  const char *case_name) {
    if (!scheduler->tasks[0].trial_acked) {
        fprintf(stderr, "%s did not accept the exact candidate ACK\n", case_name);
        return -1;
    }
    printf("%s acked=yes\n", case_name);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *fixture = fopen(argv[1], "r");
    if (!fixture) return 2;

    d2k_sched *scheduler = calloc(1, sizeof *scheduler);
    if (!scheduler) {
        fclose(fixture);
        return 8;
    }
    char case_name[64], previous_case[64] = "";
    char expected_command_text[16], expected_trial_text[33];
    char ack_command_text[16], ack_trial_text[33];
    char line[256];
    uint8_t expected_trial[D2K_TRIAL_ID_LEN];
    unsigned rows = 0, case_rows = 0, cases = 0;
    unsigned long expected_command = 0;
    while (fgets(line, sizeof line, fixture)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "%63s %15s %32s %15s %32s", case_name,
                   expected_command_text, expected_trial_text,
                   ack_command_text, ack_trial_text) != 5) {
            fclose(fixture);
            return 3;
        }
        char *expected_end = NULL;
        unsigned long row_expected_command = strtoul(expected_command_text,
                                                      &expected_end, 0);
        uint8_t row_expected_trial[D2K_TRIAL_ID_LEN];
        if (!expected_end || *expected_end ||
            parse_id(expected_trial_text, row_expected_trial) != 0) {
            fclose(fixture);
            free(scheduler);
            return 3;
        }
        if (!previous_case[0] || strcmp(previous_case, case_name) != 0) {
            if (previous_case[0]) {
                if (case_rows != 3 || print_candidate_result(scheduler, previous_case) != 0) {
                    fclose(fixture);
                    free(scheduler);
                    return 4;
                }
            }
            case_rows = 0;
            cases++;
            strcpy(previous_case, case_name);
            expected_command = row_expected_command;
            memcpy(expected_trial, row_expected_trial, sizeof expected_trial);
            if (begin_candidate(scheduler, expected_command, expected_trial_text) != 0) {
                fclose(fixture);
                free(scheduler);
                return 3;
            }
        } else if (row_expected_command != expected_command ||
                   memcmp(row_expected_trial, expected_trial, sizeof expected_trial) != 0) {
            fclose(fixture);
            free(scheduler);
            return 4;
        }

        char *end = NULL;
        unsigned long command = strtoul(ack_command_text, &end, 0);
        uint8_t trial_id[D2K_TRIAL_ID_LEN];
        if (!end || *end || command > UINT16_MAX ||
            parse_id(ack_trial_text, trial_id) != 0) {
            fclose(fixture);
            return 3;
        }

        d2k_ev event;
        memset(&event, 0, sizeof event);
        event.kind = D2K_EV_ACK;
        event.code = (uint16_t)command;
        event.num = 1u << 8;
        memcpy(event.trial_id, trial_id, sizeof event.trial_id);
        if (d2k_sched_event(scheduler, &event) != 0) {
            free(scheduler);
            fclose(fixture);
            return 5;
        }
        case_rows++;
        rows++;
    }
    fclose(fixture);
    if (rows != 6 || cases != 2 || case_rows != 3 ||
        print_candidate_result(scheduler, previous_case) != 0) {
        free(scheduler);
        return 6;
    }
    free(scheduler);

    d2k_catalog catalog;
    memset(&catalog, 0, sizeof catalog);
    d2k_sched *settle = d2k_sched_new(&catalog, -1, 0);
    if (!settle) return 8;
    task *pending = &settle->tasks[0];
    pending->state = T_TRIAL_SETTLE;
    pending->trial_until_ms = SCHED_TRIAL_SETTLE_MS;
    pending->probe_fd = -1;
    spawn_attempts = 0;
    d2k_sched_spawn_hook = reject_spawn;
    d2k_sched_tick(settle, 0);
    d2k_sched_tick(settle, SCHED_TRIAL_SETTLE_MS - 1);
    if (spawn_attempts != 0) {
        d2k_sched_spawn_hook = NULL;
        d2k_sched_free(settle);
        return 9;
    }
    d2k_sched_tick(settle, SCHED_TRIAL_SETTLE_MS);
    unsigned settled = spawn_attempts == 1;
    d2k_sched_spawn_hook = NULL;
    d2k_sched_free(settle);
    if (!settled) return 10;
    printf("missing_ack settle_ms=%u candidate_ready=yes\n",
           (unsigned)SCHED_TRIAL_SETTLE_MS);
    return 0;
}
