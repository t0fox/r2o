#define _POSIX_C_SOURCE 200809L
#include <sys/socket.h>

#define main donor_test_repeats_main
#include "test_repeats.c"
#undef main

static int accepted_connections;
extern int __real_accept(int, struct sockaddr *, socklen_t *);

int __wrap_accept(int fd, struct sockaddr *address, socklen_t *length)
{
    if (accepted_connections >= 6) {
        return -1;
    }
    int client = __real_accept(fd, address, length);
    if (client >= 0 && ++accepted_connections == 6) {
        close(fd);
        g_srv_fd = -1;
    }
    return client;
}

int main(void)
{
    d2k_opts options = {0};
    d2k_trigger trigger = {0};
    d2k_result result;

    srv_start();
    options.allow_loopback = 1;
    options.repeats = 3;
    options.timeout_ms = 400;
    options.write_gap_ms = 2;
    options.long_gap_ms = 10;
    options.no_raw = 1;
    options.control.accept = D2K_ACCEPT_ANY;
    memcpy(options.control.name, "control", sizeof("control"));
    memcpy(options.control.payload, CTL, sizeof(CTL) - 1);
    options.control.len = sizeof(CTL) - 1;
    trigger.accept = D2K_ACCEPT_ANY;
    memcpy(trigger.payload, PAY, sizeof(PAY) - 1);
    trigger.len = sizeof(PAY) - 1;
    g_ack_pat = "e";

    d2k_classify_run(g_addr, &trigger, &options, &result);
    printf("Inconclusive|%d|%d\n", result.probes, g_ack_calls);
    return result.verdict == D2K_DV_INCONCLUSIVE && result.probes == 10 &&
           g_ack_calls == 1 && accepted_connections == 6
        ? 0 : 1;
}
