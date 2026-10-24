#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sched.c"

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *fixture = fopen(argv[1], "r");
    if (!fixture) return 2;

    char name[64];
    long long initial_limit, cpu_free, mem_available, mem_total;
    long long ct_count, ct_max, active, queued, max_slots;
    long long expected_limit, expected_limiter;
    char line[512];
    unsigned rows = 0;
    while (fgets(line, sizeof line, fixture)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (sscanf(line, "%63s %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld",
                   name, &initial_limit, &cpu_free, &mem_available, &mem_total,
                   &ct_count, &ct_max, &active, &queued, &max_slots,
                   &expected_limit, &expected_limiter) != 12) {
            fclose(fixture);
            return 3;
        }
        if (initial_limit < 1 || active < 0 || queued < 0 || max_slots < active + queued ||
            max_slots > SCHED_MAX_TASKS || expected_limiter < 0 || expected_limiter > 15) {
            fclose(fixture);
            return 3;
        }

        d2k_sched *scheduler = calloc(1, sizeof *scheduler);
        if (!scheduler) {
            fclose(fixture);
            return 6;
        }
        scheduler->meas_limit = (size_t)initial_limit;
        scheduler->cpu_valid = cpu_free >= 0;
        scheduler->cpu_free_u = cpu_free >= 0 ? (uint64_t)cpu_free : 0;
        scheduler->mem_valid = mem_available >= 0;
        scheduler->mem_avail_kb = mem_available >= 0 ? (uint64_t)mem_available : 0;
        scheduler->mem_total_kb = mem_total >= 0 ? (uint64_t)mem_total : 0;
        scheduler->ct_valid = ct_max > 0;
        scheduler->ct_count = ct_count >= 0 ? (uint64_t)ct_count : 0;
        scheduler->ct_max = ct_max > 0 ? (uint64_t)ct_max : 0;
        scheduler->limit_logged = scheduler->meas_limit;
        scheduler->cpu_logged_valid = scheduler->cpu_valid && scheduler->mem_valid;
        for (size_t i = 0; i < SCHED_MAX_TASKS; i++) {
            if ((long long)i < active) scheduler->tasks[i].state = T_VERIFY;
            else if ((long long)i < active + queued) scheduler->tasks[i].state = T_QUEUED;
            else if ((long long)i < max_slots) scheduler->tasks[i].state = T_FREE;
            else scheduler->tasks[i].state = T_RESTING;
        }

        measure_started(scheduler);
        measure_limit_update(scheduler, 1);
        if ((long long)scheduler->meas_limit != expected_limit ||
            (long long)scheduler->limiter != expected_limiter) {
            fprintf(stderr, "%s: C got %zu/%u, expected %lld/%lld\n", name,
                    scheduler->meas_limit, scheduler->limiter, expected_limit,
                    expected_limiter);
            free(scheduler);
            fclose(fixture);
            return 4;
        }
        printf("%s %zu %u\n", name, scheduler->meas_limit, scheduler->limiter);
        free(scheduler);
        rows++;
    }
    fclose(fixture);
    return rows == 11 ? 0 : 5;
}
