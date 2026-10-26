#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_meas.h"

struct server_args {
    int fd;
    size_t payload_bytes;
    int send_phase;
    unsigned interrupt_delay_ms;
    unsigned signal_count;
    unsigned signal_interval_ms;
    unsigned response_delay_ms;
    pthread_t client_thread;
    int failed;
};

static void ignore_sigusr1(int signal_number) { (void)signal_number; }

static unsigned fixture_value(const char *path, const char *key) {
    FILE *file = fopen(path, "r");
    if (!file) { perror(path); exit(2); }
    char line[128];
    size_t key_len = strlen(key);
    while (fgets(line, sizeof line, file)) {
        if (strncmp(line, key, key_len) == 0 && line[key_len] == '=') {
            char *end = NULL;
            unsigned long value = strtoul(line + key_len + 1, &end, 10);
            if (end != line + key_len + 1) {
                fclose(file);
                return (unsigned)value;
            }
            break;
        }
    }
    fclose(file);
    fprintf(stderr, "fixture key missing: %s\n", key);
    exit(2);
}

static void pause_ms(unsigned milliseconds) {
    struct timespec delay = {
        .tv_sec = (time_t)(milliseconds / 1000u),
        .tv_nsec = (long)(milliseconds % 1000u) * 1000000L
    };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) { }
}

static void *serve_one(void *opaque) {
    struct server_args *args = opaque;
    int client = accept(args->fd, NULL, NULL);
    if (client < 0) {
        args->failed = 1;
        close(args->fd);
        return NULL;
    }
    int receive_buffer = 262144;
    (void)setsockopt(client, SOL_SOCKET, SO_RCVBUF,
                     &receive_buffer, sizeof receive_buffer);
    uint8_t bytes[8192];
    size_t received = 0;
    if (!args->send_phase) {
        while (received < args->payload_bytes) {
            size_t remaining = args->payload_bytes - received;
            size_t capacity = remaining < sizeof bytes ? remaining : sizeof bytes;
            ssize_t n = recv(client, bytes, capacity, 0);
            if (n > 0) { received += (size_t)n; continue; }
            if (n < 0 && errno == EINTR) { continue; }
            args->failed = 1;
            close(client);
            close(args->fd);
            return NULL;
        }
    }
    pause_ms(args->interrupt_delay_ms);
    for (unsigned i = 0; i < args->signal_count; i++) {
        if (pthread_kill(args->client_thread, SIGUSR1) != 0) args->failed = 1;
        if (i + 1 < args->signal_count) pause_ms(args->signal_interval_ms);
    }
    unsigned elapsed = args->interrupt_delay_ms +
        (args->signal_count ? args->signal_count - 1 : 0) * args->signal_interval_ms;
    if (args->response_delay_ms > elapsed) pause_ms(args->response_delay_ms - elapsed);
    if (args->send_phase) {
        while (received < args->payload_bytes) {
            size_t remaining = args->payload_bytes - received;
            size_t capacity = remaining < sizeof bytes ? remaining : sizeof bytes;
            ssize_t n = recv(client, bytes, capacity, 0);
            if (n > 0) { received += (size_t)n; continue; }
            if (n < 0 && errno == EINTR) { continue; }
            break;
        }
    }
    if (received == args->payload_bytes) {
        const uint8_t response = 'x';
        (void)send(client, &response, sizeof response, MSG_NOSIGNAL);
    }
    close(client);
    close(args->fd);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    size_t payload_bytes = fixture_value(argv[1], "payload_bytes");
    int send_phase = (int)fixture_value(argv[1], "send_phase");
    unsigned timeout_ms = fixture_value(argv[1], "timeout_ms");
    unsigned interrupt_delay_ms = fixture_value(argv[1], "interrupt_delay_ms");
    unsigned signal_count = fixture_value(argv[1], "signal_count");
    unsigned signal_interval_ms = fixture_value(argv[1], "signal_interval_ms");
    unsigned response_delay_ms = fixture_value(argv[1], "response_delay_ms");
    if (!payload_bytes || payload_bytes > 16u * 1024u * 1024u ||
        (send_phase != 0 && send_phase != 1) ||
        !signal_count || interrupt_delay_ms >= response_delay_ms ||
        (response_delay_ms >= timeout_ms && !send_phase)) {
        fprintf(stderr, "invalid measurement EINTR fixture\n");
        return 2;
    }

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = ignore_sigusr1;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) != 0) { perror("sigaction"); return 2; }

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) { perror("socket"); return 2; }
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&address, sizeof address) != 0 ||
        listen(listener, 1) != 0) {
        perror("bind/listen"); close(listener); return 2;
    }
    socklen_t address_len = sizeof address;
    if (getsockname(listener, (struct sockaddr *)&address, &address_len) != 0) {
        perror("getsockname"); close(listener); return 2;
    }
    char local_ip[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &address.sin_addr, local_ip, sizeof local_ip)) {
        perror("inet_ntop"); close(listener); return 2;
    }

    struct server_args args = {
        .fd = listener,
        .payload_bytes = payload_bytes,
        .send_phase = send_phase,
        .interrupt_delay_ms = interrupt_delay_ms,
        .signal_count = signal_count,
        .signal_interval_ms = signal_interval_ms,
        .response_delay_ms = response_delay_ms,
        .client_thread = pthread_self(),
        .failed = 0
    };
    pthread_t server;
    if (pthread_create(&server, NULL, serve_one, &args) != 0) {
        perror("pthread_create"); close(listener); return 2;
    }

    uint8_t *payload = malloc(payload_bytes);
    if (!payload) { close(listener); return 2; }
    memset(payload, 0xa5, payload_bytes);
    d2k_hello hello = { payload, payload_bytes, NULL, 0, 0, 0 };
    int marked = 0;
    int result = d2k_meas_once(local_ip, ntohs(address.sin_port), hello,
                               NULL, 0, 0, timeout_ms, 0, NULL, &marked);
    (void)pthread_join(server, NULL);
    if (args.failed) { fprintf(stderr, "measurement EINTR server failed\n"); return 2; }
    printf("C_RESULT:%s\n", result == D2K_MEAS_SILENT ? "REJECTED" :
           result == D2K_MEAS_PASS ? "ACCEPTED" :
           result == D2K_MEAS_UNPROVEN ? "UNPROVEN" : "ERROR");
    free(payload);
    return 0;
}
