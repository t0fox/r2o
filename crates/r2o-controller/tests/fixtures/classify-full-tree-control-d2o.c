#define _POSIX_C_SOURCE 200809L
#include <sys/socket.h>

#define main donor_test_repeats_main
#include "test_repeats.c"
#undef main

static int accepted_connections;
static int close_after_connections = 6;
extern int __real_accept(int, struct sockaddr *, socklen_t *);

int __wrap_accept(int fd, struct sockaddr *address, socklen_t *length)
{
    if (close_after_connections > 0 && accepted_connections >= close_after_connections) {
        return -1;
    }
    int client = __real_accept(fd, address, length);
    if (client >= 0) {
        accepted_connections++;
        if (close_after_connections > 0 && accepted_connections == close_after_connections) {
            close(fd);
            g_srv_fd = -1;
        }
    }
    return client;
}

int main(int argc, char **argv)
{
    d2k_opts options = {0};
    d2k_trigger trigger = {0};
    d2k_result result;

    if (argc != 2) {
        return 2;
    }
    if (strcmp(argv[1], "transport-error") == 0) {
        close_after_connections = 6;
        g_ack_pat = "e";
    } else if (strcmp(argv[1], "control-pass") == 0) {
        close_after_connections = 0;
        g_ctl_pat = "-+";
        g_ack_pat = "e";
    } else if (strcmp(argv[1], "control-unproven") == 0) {
        close_after_connections = 0;
        g_ctl_pat = "+";
        g_ack_pat = "---";
    } else {
        return 2;
    }

    srv_start();
    options.allow_loopback = 1;
    options.repeats = 3;
    options.timeout_ms = 400;
    options.write_gap_ms = 2;
    options.long_gap_ms = 10;
    options.no_raw = 1;
    options.control.accept = strcmp(argv[1], "control-unproven") == 0
        ? D2K_ACCEPT_TLSRECORD : D2K_ACCEPT_ANY;
    memcpy(options.control.name, "control", sizeof("control"));
    memcpy(options.control.payload, CTL, sizeof(CTL) - 1);
    options.control.len = sizeof(CTL) - 1;
    trigger.accept = D2K_ACCEPT_ANY;
    memcpy(trigger.payload, PAY, sizeof(PAY) - 1);
    trigger.len = sizeof(PAY) - 1;

    d2k_classify_run(g_addr, &trigger, &options, &result);
    if (strcmp(argv[1], "transport-error") == 0) {
        printf("Inconclusive|%d|%d\n", result.probes, g_ack_calls);
        return result.verdict == D2K_DV_INCONCLUSIVE && result.probes == 10 &&
               g_ack_calls == 1 && accepted_connections == 6 ? 0 : 1;
    }
    if (strcmp(argv[1], "control-pass") == 0) {
        printf("Opaque|%d|%d\n", result.probes, g_ack_calls);
        return result.verdict == D2K_DV_OPAQUE && result.probes == 8 &&
               g_ack_calls == 0 && accepted_connections == 8 ? 0 : 1;
    }
    printf("Address|%d|%d\n", result.probes, g_ack_calls);
    return result.verdict == D2K_DV_ADDRESS && result.probes == 12 &&
           g_ack_calls == 3 && accepted_connections == 9 ? 0 : 1;
}
