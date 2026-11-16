#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "link.c"

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
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        perror("socketpair");
        return 1;
    }
    char err[256] = {0};

    printf("zero %d\n", wait_readable(fds[0], 0, err, sizeof err));

    uint8_t byte = 0x5a;
    if (send(fds[1], &byte, 1, 0) != 1) {
        perror("send");
        return 1;
    }
    printf("data %d\n", wait_readable(fds[0], 1000, err, sizeof err));
    if (recv(fds[0], &byte, 1, 0) != 1) {
        perror("recv");
        return 1;
    }

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int timeout_rc = wait_readable(fds[0], 20, err, sizeof err);
    int64_t timeout_ms = elapsed_ms(&start);
    printf("timeout_rc %d\n", timeout_rc);
    printf("timeout_ms_ok %d\n", timeout_ms >= 15 && timeout_ms < 2000 ? 1 : 0);

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
    timer.it_value.tv_usec = 10 * 1000;
    if (setitimer(ITIMER_REAL, &timer, NULL) != 0) {
        perror("setitimer");
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    int eintr_rc = wait_readable(fds[0], 100, err, sizeof err);
    int64_t eintr_ms = elapsed_ms(&start);
    printf("eintr_rc %d\n", eintr_rc);
    printf("eintr_seen %d\n", alarm_seen ? 1 : 0);
    printf("eintr_ms_ok %d\n", eintr_ms >= 90 && eintr_ms < 2000 ? 1 : 0);

    close(fds[1]);
    printf("hup_positive %d\n", wait_readable(fds[0], 1000, err, sizeof err) > 0 ? 1 : 0);

    close(fds[0]);
    return 0;
}
