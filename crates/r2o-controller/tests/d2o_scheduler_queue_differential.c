#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

/* These are unreachable for the unplanned fixture tasks. Abort if a future
 * fixture accidentally enters the donor's family-recovery predicate. */
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
        char *expected = strtok_r(NULL, " \t\r\n", &save);
        char *mode = strtok_r(NULL, " \t\r\n", &save);
        char *count_text = strtok_r(NULL, " \t\r\n", &save);
        if (!case_name || !expected || !mode || !count_text ||
            (strcmp(mode, "normal") && strcmp(mode, "quic_yield"))) {
            fclose(fixture);
            return 3;
        }

        char *end = NULL;
        unsigned long count = strtoul(count_text, &end, 10);
        if (!end || *end || count == 0 || count > SCHED_MAX_TASKS) {
            fclose(fixture);
            return 3;
        }

        d2k_sched *scheduler = calloc(1, sizeof *scheduler);
        if (!scheduler) {
            fclose(fixture);
            return 6;
        }
        for (unsigned long i = 0; i < count; i++) {
            char *entry = strtok_r(NULL, " \t\r\n", &save);
            char name[256], task_state[16];
            unsigned transport;
            unsigned long long queued_event, hot_event;
            long long queued_age_ms;
            if (!entry || sscanf(entry, "%255[^/]/%u/%llu/%llu/%lld/%15s", name,
                                 &transport, &queued_event, &hot_event,
                                 &queued_age_ms, task_state) != 6 ||
                (transport != 6 && transport != 17) || queued_age_ms < 0) {
                free(scheduler);
                fclose(fixture);
                return 3;
            }
            task *queued = &scheduler->tasks[i];
            if (!strcmp(task_state, "queued")) {
                queued->state = T_QUEUED;
            } else if (!strcmp(task_state, "parked") && transport == 17) {
                queued->state = T_ASKING;
                queued->quic_parked = 1;
            } else {
                free(scheduler);
                fclose(fixture);
                return 3;
            }
            queued->transport = (uint8_t)transport;
            queued->queued_event = (uint64_t)queued_event;
            queued->hot_event = (uint64_t)hot_event;
            queued->queued_ms = -queued_age_ms;
            memcpy(queued->name, name, strlen(name) + 1);
        }
        if (strtok_r(NULL, " \t\r\n", &save)) {
            free(scheduler);
            fclose(fixture);
            return 3;
        }

        task *selected = queued_pick(scheduler);
        if (!selected || strcmp(selected->name, expected)) {
            fprintf(stderr, "%s: C selected %s, expected %s\n", case_name,
                    selected ? selected->name : "<none>", expected);
            free(scheduler);
            fclose(fixture);
            return 4;
        }
        printf("%s %s\n", case_name, selected->name);
        free(scheduler);
        cases++;
    }
    fclose(fixture);
    return cases == 4 ? 0 : 5;
}
