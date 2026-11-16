#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "meas.c"

static volatile sig_atomic_t alarm_seen;

static void on_alarm(int signal_number)
{
    (void)signal_number;
    alarm_seen = 1;
}

static int64_t elapsed_ms(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t)(now.tv_sec - start->tv_sec) * 1000 +
           (now.tv_nsec - start->tv_nsec) / 1000000;
}

int main(void)
{
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    nap_us(20 * 1000);
    int64_t normal_ms = elapsed_ms(&start);
    printf("nap20_ok %d\n", normal_ms >= 15 && normal_ms < 2000 ? 1 : 0);

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_alarm;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (sigaction(SIGALRM, &action, NULL) != 0) {
        perror("sigaction");
        return 1;
    }
    struct itimerval timer;
    memset(&timer, 0, sizeof timer);
    timer.it_value.tv_usec = 20 * 1000;
    if (setitimer(ITIMER_REAL, &timer, NULL) != 0) {
        perror("setitimer");
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    nap_us(100 * 1000);
    int64_t interrupted_ms = elapsed_ms(&start);
    printf("nap100_eintr_ok %d\n",
           interrupted_ms >= 10 && interrupted_ms < 80 ? 1 : 0);
    printf("nap100_seen %d\n", alarm_seen ? 1 : 0);

    struct itimerval stopped;
    memset(&stopped, 0, sizeof stopped);
    (void)setitimer(ITIMER_REAL, &stopped, NULL);
    return 0;
}
