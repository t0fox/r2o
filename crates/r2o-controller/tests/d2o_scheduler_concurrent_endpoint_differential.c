#define _POSIX_C_SOURCE 200809L

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sched.c"

static atomic_uint started;

static void sleep_one_ms(void)
{
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
    nanosleep(&pause, NULL);
}

static d2k_vres hold_tcp_measurement(const char *ip, uint16_t port,
                                    d2k_hello trigger, d2k_hello control,
                                    uint32_t mark, int repeats, uint32_t gap_us,
                                    uint32_t wait_ms,
                                    const volatile sig_atomic_t *stop)
{
    (void)ip;
    (void)port;
    (void)trigger;
    (void)control;
    (void)mark;
    (void)repeats;
    (void)gap_us;
    (void)wait_ms;
    atomic_fetch_add(&started, 1);
    while (!*stop) sleep_one_ms();
    d2k_vres result = {0};
    result.verdict = D2K_V_FLAKY;
    result.owns_search = 1;
    return result;
}

int main(void)
{
    d2k_catalog catalog = {0};
    d2k_sched *scheduler = d2k_sched_new(&catalog, -1, 0);
    if (!scheduler) return 6;
    scheduler->meas_limit = 2;
    d2k_sched_tcp_hook = hold_tcp_measurement;

    for (unsigned index = 0; index < 2; index++) {
        task *target = &scheduler->tasks[index];
        snprintf(target->name, sizeof target->name, "alias-%u.example", index);
        snprintf(target->ip, sizeof target->ip, "%s", "192.0.2.30");
        target->port = 443;
        target->transport = 6;
        target->family = 4;
        target->trigger_code = D2K_SUSPECT_RST;
        target->trigger_shape = D2K_SHAPE_MODERN;
        if (!launch_or_queue(scheduler, target)) {
            d2k_sched_free(scheduler);
            return 4;
        }
    }

    for (unsigned spin = 0; spin < 2000 && atomic_load(&started) != 2; spin++) {
        sleep_one_ms();
    }
    size_t active = measurements_in_flight(scheduler);
    unsigned workers = atomic_load(&started);
    printf("same_endpoint_active %zu\n", active);
    d2k_sched_free(scheduler);
    return active == 2 && workers == 2 ? 0 : 5;
}
