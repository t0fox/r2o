#define _POSIX_C_SOURCE 200809L
#include <sys/socket.h>

#define main donor_test_repeats_main
#include "test_repeats.c"
#undef main

static int accepted_connections;
static int close_after_connections = 6;
static int force_connect_deadline;
static int force_first_connect_error;
static int connect_count;
static int poll_timeout_count;
static int poll_timeouts[16];
extern int __real_accept(int, struct sockaddr *, socklen_t *);
extern int __real_connect(int, const struct sockaddr *, socklen_t);
extern int __real_poll(struct pollfd *, nfds_t, int);
extern ssize_t __real_recv(int, void *, size_t, int);
extern int __real_close(int);

static struct {
    int fd;
    int active;
    int control;
} server_clients[32];

int __wrap_accept(int fd, struct sockaddr *address, socklen_t *length)
{
    if (close_after_connections > 0 && accepted_connections >= close_after_connections) {
        return -1;
    }
    int client = __real_accept(fd, address, length);
    if (client >= 0) {
        int i;
        accepted_connections++;
        for (i = 0; i < (int)(sizeof(server_clients) / sizeof(server_clients[0])); i++) {
            if (!server_clients[i].active) {
                server_clients[i].fd = client;
                server_clients[i].active = 1;
                server_clients[i].control = 0;
                break;
            }
        }
        if (close_after_connections > 0 && accepted_connections == close_after_connections) {
            close(fd);
            g_srv_fd = -1;
        }
    }
    return client;
}

int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length)
{
    if (force_first_connect_error && connect_count++ == 0) {
        errno = ECONNREFUSED;
        return -1;
    }
    if (force_connect_deadline) {
        (void)fd;
        (void)address;
        (void)length;
        errno = EINPROGRESS;
        return -1;
    }
    return __real_connect(fd, address, length);
}

int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    if (force_connect_deadline) {
        (void)fds;
        (void)count;
        if (poll_timeout_count < (int)(sizeof(poll_timeouts) / sizeof(poll_timeouts[0]))) {
            poll_timeouts[poll_timeout_count] = timeout;
        }
        poll_timeout_count++;
        return 0;
    }
    return __real_poll(fds, count, timeout);
}

ssize_t __wrap_recv(int fd, void *buffer, size_t length, int flags)
{
    ssize_t received = __real_recv(fd, buffer, length, flags);
    if (received == (ssize_t)(sizeof(CTL) - 1) &&
        memcmp(buffer, CTL, sizeof(CTL) - 1) == 0) {
        int i;
        for (i = 0; i < (int)(sizeof(server_clients) / sizeof(server_clients[0])); i++) {
            if (server_clients[i].active && server_clients[i].fd == fd) {
                server_clients[i].control = 1;
                break;
            }
        }
    }
    return received;
}

int __wrap_close(int fd)
{
    static const uint8_t alert[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
    int i;
    for (i = 0; i < (int)(sizeof(server_clients) / sizeof(server_clients[0])); i++) {
        if (server_clients[i].active && server_clients[i].fd == fd) {
            server_clients[i].active = 0;
            if (!server_clients[i].control) {
                (void)send(fd, alert, sizeof(alert), 0);
            }
            break;
        }
    }
    return __real_close(fd);
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
    } else if (strcmp(argv[1], "target-unproven") == 0) {
        close_after_connections = 0;
        g_ctl_pat = "+";
        g_ack_pat = "e";
    } else if (strcmp(argv[1], "baseline-deadline") == 0) {
        close_after_connections = 0;
        force_connect_deadline = 1;
        g_ack_pat = "e";
    } else if (strcmp(argv[1], "baseline-mixed-error") == 0) {
        close_after_connections = 0;
        force_first_connect_error = 1;
        g_ack_pat = "e";
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
    trigger.accept = D2K_ACCEPT_SERVERHELLO;
    memcpy(trigger.payload, PAY, sizeof(PAY) - 1);
    trigger.len = sizeof(PAY) - 1;

    d2k_classify_run(g_addr, &trigger, &options, &result);
    if (strcmp(argv[1], "baseline-deadline") == 0) {
        int valid = poll_timeout_count == 6;
        int i;
        for (i = 0; i < 6 && i < poll_timeout_count; i++) {
            int expected = i < 3 ? 400 : 800;
            if (poll_timeouts[i] != expected) valid = 0;
        }
        printf("Flaky|%d|0|", result.probes);
        for (i = 0; i < poll_timeout_count && i < 6; i++) {
            printf("%s%d", i == 0 ? "" : ",", poll_timeouts[i]);
        }
        printf("\n");
        return valid && result.verdict == D2K_DV_FLAKY && result.probes == 6 ? 0 : 1;
    }
    if (strcmp(argv[1], "baseline-mixed-error") == 0) {
        printf("Unreachable|%d|0\n", result.probes);
        return result.verdict == D2K_DV_UNREACHABLE && result.probes == 3 &&
               accepted_connections == 2 ? 0 : 1;
    }
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
    if (strcmp(argv[1], "target-unproven") == 0) {
        printf("Opaque|%d|%d\n", result.probes, g_ack_calls);
        return result.verdict == D2K_DV_OPAQUE && result.probes == 7 &&
               g_ack_calls == 0 && accepted_connections == 7 ? 0 : 1;
    }
    printf("Address|%d|%d\n", result.probes, g_ack_calls);
    return result.verdict == D2K_DV_ADDRESS && result.probes == 12 &&
           g_ack_calls == 3 && accepted_connections == 9 ? 0 : 1;
}
