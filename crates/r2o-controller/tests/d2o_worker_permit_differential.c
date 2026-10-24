#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

const d2k_domain_group *d2k_group_match(const d2k_group_state *state,
                                       const char *name,
                                       const d2k_group_key *key)
{
    (void)state;
    (void)name;
    (void)key;
    abort();
}

int d2k_cat_shape_fits(uint8_t stored, uint8_t got)
{
    (void)stored;
    (void)got;
    abort();
}

int d2k_group_key_same(const d2k_group_key *left, const d2k_group_key *right)
{
    (void)left;
    (void)right;
    abort();
}

int d2k_domain_member(const char *name, const char *suffix)
{
    (void)name;
    (void)suffix;
    abort();
}

static int parse_yes_no(const char *text, int *value)
{
    if (!strcmp(text, "yes")) {
        *value = 1;
        return 0;
    }
    if (!strcmp(text, "no")) {
        *value = 0;
        return 0;
    }
    return -1;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    FILE *fixture = fopen(argv[1], "r");
    if (!fixture) return 2;

    char line[2048];
    unsigned cases = 0;
    while (fgets(line, sizeof line, fixture)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char *save = NULL;
        char *case_name = strtok_r(line, " \t\r\n", &save);
        char *limit_text = strtok_r(NULL, " \t\r\n", &save);
        char *other_text = strtok_r(NULL, " \t\r\n", &save);
        char *sequence_text = strtok_r(NULL, " \t\r\n", &save);
        char *turn_text = strtok_r(NULL, " \t\r\n", &save);
        char *parked_text = strtok_r(NULL, " \t\r\n", &save);
        char *expect_request_text = strtok_r(NULL, " \t\r\n", &save);
        char *expected_pick = strtok_r(NULL, " \t\r\n", &save);
        char *expect_resume_text = strtok_r(NULL, " \t\r\n", &save);
        if (!case_name || !limit_text || !other_text || !sequence_text ||
            !turn_text || !parked_text || !expect_request_text ||
            !expected_pick || !expect_resume_text) {
            fclose(fixture);
            return 3;
        }
        unsigned long limit = strtoul(limit_text, NULL, 10);
        unsigned long other_active = strtoul(other_text, NULL, 10);
        unsigned long long tcp_sequence = strtoull(sequence_text, NULL, 10);
        unsigned long long quic_turn = strtoull(turn_text, NULL, 10);
        int already_parked, expect_request, expect_resume;
        if (limit == 0 || limit > SCHED_MAX_TASKS ||
            other_active >= SCHED_MAX_TASKS ||
            parse_yes_no(parked_text, &already_parked) ||
            parse_yes_no(expect_request_text, &expect_request) ||
            parse_yes_no(expect_resume_text, &expect_resume)) {
            fclose(fixture);
            return 3;
        }

        d2k_sched *scheduler = calloc(1, sizeof *scheduler);
        if (!scheduler) {
            fclose(fixture);
            return 6;
        }
        pthread_mutex_init(&scheduler->mu, NULL);
        pthread_cond_init(&scheduler->question_cv, NULL);
        scheduler->meas_limit = limit;
        scheduler->tcp_admission_sequence = (uint64_t)tcp_sequence;

        task *quic = &scheduler->tasks[0];
        quic->state = T_ASKING;
        quic->transport = 17;
        quic->job = JOB_CLASSIFY;
        quic->quic_parked = already_parked;
        quic->quic_yield_waiting = already_parked;
        quic->quic_yield_request = already_parked;
        quic->quic_parked_ms = 100;
        quic->quic_tcp_turn = (uint64_t)quic_turn;
        snprintf(quic->name, sizeof quic->name, "active-quic.example");

        for (unsigned long i = 0; i < other_active; i++) {
            task *active = &scheduler->tasks[1 + i];
            active->state = T_ASKING;
            active->transport = 6;
            active->job = JOB_CLASSIFY;
            snprintf(active->name, sizeof active->name, "active-%lu.example", i);
        }

        size_t queued_count = 0;
        for (char *entry = strtok_r(NULL, " \t\r\n", &save); entry;
             entry = strtok_r(NULL, " \t\r\n", &save)) {
            char *entry_save = NULL;
            char *name = strtok_r(entry, "/", &entry_save);
            char *transport_text = strtok_r(NULL, "/", &entry_save);
            char *queued_event_text = strtok_r(NULL, "/", &entry_save);
            char *hot_event_text = strtok_r(NULL, "/", &entry_save);
            if (!name || !transport_text || !queued_event_text || !hot_event_text ||
                queued_count >= SCHED_MAX_TASKS - other_active - 1) {
                free(scheduler);
                fclose(fixture);
                return 3;
            }
            unsigned long transport = strtoul(transport_text, NULL, 10);
            if (transport != 6 && transport != 17) {
                free(scheduler);
                fclose(fixture);
                return 3;
            }
            task *queued = &scheduler->tasks[1 + other_active + queued_count++];
            queued->state = T_QUEUED;
            queued->transport = (uint8_t)transport;
            queued->queued_event = strtoull(queued_event_text, NULL, 10);
            queued->hot_event = strtoull(hot_event_text, NULL, 10);
            queued->trigger_planned = D2K_LINK_PLANNED_YES;
            queued->rx_volume_only = 1;
            snprintf(queued->name, sizeof queued->name, "%s", name);
        }

        quic_yield_tick(scheduler, 200);
        int actual_request = quic->quic_yield_request != 0;
        if (actual_request != expect_request) {
            fprintf(stderr, "%s: C requested yield=%d, expected %d\n",
                    case_name, actual_request, expect_request);
            free(scheduler);
            fclose(fixture);
            return 4;
        }

        if (strcmp(expected_pick, "-")) {
            quic->quic_parked = 1;
            task *selected = queued_pick(scheduler);
            if (!selected || strcmp(selected->name, expected_pick)) {
                fprintf(stderr, "%s: C selected %s, expected %s\n", case_name,
                        selected ? selected->name : "<none>", expected_pick);
                free(scheduler);
                fclose(fixture);
                return 4;
            }
        }

        int actual_resume = 0;
        if (already_parked) {
            actual_resume = !quic->quic_parked && !quic->quic_yield_waiting;
        }
        if (actual_resume != expect_resume) {
            fprintf(stderr, "%s: C resumed=%d, expected %d\n",
                    case_name, actual_resume, expect_resume);
            free(scheduler);
            fclose(fixture);
            return 4;
        }
        printf("%s yield=%s pick=%s resume=%s\n", case_name,
               actual_request ? "yes" : "no",
               strcmp(expected_pick, "-") ? expected_pick : "-",
               actual_resume ? "yes" : "no");
        pthread_cond_destroy(&scheduler->question_cv);
        pthread_mutex_destroy(&scheduler->mu);
        free(scheduler);
        cases++;
    }
    fclose(fixture);
    return cases == 3 ? 0 : 5;
}
