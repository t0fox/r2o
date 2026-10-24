#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    FILE *fixture = fopen(argv[1], "r");
    if (!fixture) return 2;

    char line[512];
    unsigned cases = 0;
    while (fgets(line, sizeof line, fixture)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char case_name[64], expected[16], host[256];
        unsigned long long queued_age_ms;
        char extra;
        if (sscanf(line, "%63s %15s %llu %255s %c", case_name, expected,
                   &queued_age_ms, host, &extra) != 4 ||
            (strcmp(expected, "queued") && strcmp(expected, "expired")) ||
            queued_age_ms > (unsigned long long)INT64_MAX - 1) {
            fclose(fixture);
            return 3;
        }

        d2k_catalog catalog = {0};
        d2k_sched *scheduler = d2k_sched_new(&catalog, -1, 0);
        if (!scheduler) {
            fclose(fixture);
            return 6;
        }
        task *queued = &scheduler->tasks[0];
        queued->state = T_QUEUED;
        queued->queued_ms = 1;
        queued->trigger_planned = D2K_LINK_PLANNED_YES;
        if (strlen(host) >= sizeof queued->name) {
            d2k_sched_free(scheduler);
            fclose(fixture);
            return 3;
        }
        memcpy(queued->name, host, strlen(host) + 1);

        (void)d2k_sched_tick(scheduler, 1 + (int64_t)queued_age_ms);
        const char *actual = queued->state == T_FREE ? "expired" : "queued";
        if (strcmp(actual, expected)) {
            fprintf(stderr, "%s: d2o selected %s, expected %s\n", case_name,
                    actual, expected);
            d2k_sched_free(scheduler);
            fclose(fixture);
            return 4;
        }
        printf("%s %s\n", case_name, actual);
        d2k_sched_free(scheduler);
        cases++;
    }
    fclose(fixture);
    return cases == 2 ? 0 : 5;
}
