#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include "sched.c"

int main(void) {
    d2k_sched *scheduler = calloc(1, sizeof *scheduler);
    d2k_catalog *catalog = calloc(1, sizeof *catalog);
    if (!scheduler || !catalog) return 1;
    scheduler->cat = catalog;
    scheduler->tasks[0].state = T_QUEUED;
    scheduler->tasks[1].state = T_ASKING;
    scheduler->tasks[1].trig_len = 1;
    scheduler->tasks[2].state = T_ASKING;
    scheduler->tasks[2].trig_len = 1;
    scheduler->tasks[3].state = T_ASKING;
    scheduler->tasks[4].state = T_QUEUED;
    scheduler->tasks[4].snap_len = 1;
    d2k_diag_counts counts = {0};
    d2k_sched_diagnostic_counts(scheduler, &counts);
    printf("snapshots=%llu\n", (unsigned long long)counts.snapshots);
    free(catalog);
    free(scheduler);
    return 0;
}
