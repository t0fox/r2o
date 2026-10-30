#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_hello.h"
#include "d2k_meas.h"
#include "d2k_verdict.h"

static const uint8_t serverhello[] = { 0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00 };
static const uint8_t tls_alert[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };
static const uint8_t trigger_sig[] = { 0x16, 0x03, 0x01, 0x00 };
static volatile sig_atomic_t *active_stop;

struct server {
    int fd;
    uint16_t port;
    int max_connections;
    int send_from;
    int send_through;
    int cancel_after;
    int alert;
    pthread_t caller;
    pthread_t thread;
};

static void request_stop(int signal_number) {
    (void)signal_number;
    if (active_stop) {
        *active_stop = 1;
    }
}

static void *serve(void *argument) {
    struct server *server = argument;
    for (int connection = 1; connection <= server->max_connections; connection++) {
        struct pollfd event = { server->fd, POLLIN, 0 };
        if (poll(&event, 1, 3000) <= 0) {
            break;
        }
        int client = accept(server->fd, NULL, NULL);
        if (client < 0) {
            break;
        }
        uint8_t request[2048];
        (void)recv(client, request, sizeof request, 0);
        if (connection == server->cancel_after) {
            (void)pthread_kill(server->caller, SIGUSR1);
        }
        if (connection >= server->send_from && connection <= server->send_through) {
            if (server->alert) {
                (void)send(client, tls_alert, sizeof tls_alert, 0);
            } else {
                (void)send(client, serverhello, sizeof serverhello, 0);
            }
        }
        close(client);
    }
    close(server->fd);
    return NULL;
}

static int start_server(struct server *server, int max_connections,
                        int send_from, int send_through,
                        int cancel_after, int alert) {
    struct sockaddr_in address;
    socklen_t address_length = sizeof address;
    memset(server, 0, sizeof *server);
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) {
        return -1;
    }
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(server->fd, (struct sockaddr *)&address, sizeof address) < 0 ||
        listen(server->fd, 8) < 0 ||
        getsockname(server->fd, (struct sockaddr *)&address, &address_length) < 0) {
        close(server->fd);
        return -1;
    }
    server->port = ntohs(address.sin_port);
    server->max_connections = max_connections;
    server->send_from = send_from;
    server->send_through = send_through;
    server->cancel_after = cancel_after;
    server->alert = alert;
    server->caller = pthread_self();
    if (pthread_create(&server->thread, NULL, serve, server) != 0) {
        close(server->fd);
        return -1;
    }
    return 0;
}

static const char *verdict_name(d2k_verdict verdict) {
    switch (verdict) {
    case D2K_V_CLEAR: return "Clear";
    case D2K_V_FLAKY: return "Flaky";
    case D2K_V_INCONCLUSIVE: return "Inconclusive";
    case D2K_V_UNREACHABLE: return "Unreachable";
    default: return "Other";
    }
}

static int run_case(const char *name, int max_connections,
                    int send_from, int send_through,
                    int cancel_after, int alert,
                    d2k_verdict expected_verdict, unsigned expected_probes) {
    struct server server;
    volatile sig_atomic_t stop = 0;
    struct sigaction action;
    uint8_t hello[64];
    uint8_t control_bytes[64];
    memset(&action, 0, sizeof action);
    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) < 0) {
        return 1;
    }
    active_stop = &stop;
    if (start_server(&server, max_connections, send_from, send_through,
                     cancel_after, alert) < 0) {
        return 1;
    }
    int server_joined = max_connections == 0;
    if (server_joined) {
        pthread_join(server.thread, NULL);
    }
    memset(hello, 0xAA, sizeof hello);
    memcpy(hello, trigger_sig, sizeof trigger_sig);
    d2k_hello trigger = { hello, sizeof hello, NULL, 0, 0, 0 };
    memset(control_bytes, 0xBB, sizeof control_bytes);
    control_bytes[0] = 0x16;
    control_bytes[1] = 0x03;
    control_bytes[2] = 0x03;
    control_bytes[3] = 0x00;
    d2k_hello control = { control_bytes, sizeof control_bytes, NULL, 0, 0, 0 };
    d2k_vres result = d2k_classify_cancelable(
        "127.0.0.1", server.port, trigger, control, 0, 3, 0, 50, &stop);
    if (!server_joined) {
        pthread_join(server.thread, NULL);
    }
    active_stop = NULL;
    printf("%s=%s/%d\n", name, verdict_name(result.verdict), result.probes);
    return result.verdict == expected_verdict && (unsigned)result.probes == expected_probes ? 0 : 1;
}

int main(void) {
    int failed = 0;
    failed |= run_case("clear", 5, 1, 5, 0, 0, D2K_V_CLEAR, 5);
    failed |= run_case("silent", 5, 1, 3, 0, 0, D2K_V_FLAKY, 5);
    failed |= run_case("connect-error", 3, 1, 3, 0, 0, D2K_V_FLAKY, 5);
    failed |= run_case("cancel", 3, 1, 3, 3, 0, D2K_V_INCONCLUSIVE, 3);
    failed |= run_case("all-baseline-errors", 0, 1, 0, 0, 0, D2K_V_UNREACHABLE, 3);
    failed |= run_case("partial-base-error", 2, 1, 0, 0, 0, D2K_V_FLAKY, 6);
    failed |= run_case("unproven", 9, 1, 9, 0, 1, D2K_V_INCONCLUSIVE, 9);
    failed |= run_case("control-partial", 9, 7, 7, 0, 1, D2K_V_FLAKY, 9);
    failed |= run_case("control-error", 7, 7, 7, 0, 1, D2K_V_FLAKY, 9);
    return failed;
}
