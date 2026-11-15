/* C/Rust differential: d2k_sched_diagnostic_counts worker-поля. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "sched.c"

int main(void) {
    static d2k_sched s;
    static d2k_catalog cat;
    memset(&s, 0, sizeof s);
    memset(&cat, 0, sizeof cat);
    s.cat = &cat;
    int64_t now = sched_mono_ms();
    s.now_ms = now;
    s.workers_started = 5;
    s.workers_joined = 4;
    s.worker_start_failures = 2;
    s.worker_join_failures = 1;
    s.last_measurement_done_ms = now - 2000;

    task *t = &s.tasks[0];
    memset(t, 0, sizeof *t);
    t->state = T_ASKING;
    t->transport = 6;
    t->family = 4;
    t->job = JOB_CLASSIFY;
    t->th_live = 1;
    t->worker_started_ms = now - 4000;

    d2k_diag_counts c;
    d2k_sched_diagnostic_counts(&s, &c);
    printf("workers_started=%llu\n", (unsigned long long)c.workers_started);
    printf("workers_joined=%llu\n", (unsigned long long)c.workers_joined);
    printf("worker_start_failures=%llu\n",
           (unsigned long long)c.worker_start_failures);
    printf("worker_join_failures=%llu\n",
           (unsigned long long)c.worker_join_failures);
    printf("worker_oldest_age_s=%lld\n",
           (long long)(c.worker_oldest_age_ms / 1000));
    printf("worker_oldest_type=%s\n", c.worker_oldest_type);
    printf("last_measurement_age_s=%lld\n",
           (long long)(c.last_measurement_age_ms / 1000));
    return 0;
}
