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

#include "d2k_detect.h"

struct server_args {
    int fd;
    int repeats;
    unsigned interrupt_delay_ms;
    unsigned response_delay_ms;
    pthread_t client_thread;
    int failed;
};

static void ignore_signal(int signal_number) { (void)signal_number; }

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

static int read_all(int fd, uint8_t *bytes, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t got = recv(fd, bytes + offset, length - offset, 0);
        if (got > 0) { offset += (size_t)got; continue; }
        if (got < 0 && errno == EINTR) { continue; }
        return -1;
    }
    return 0;
}

static void pause_ms(unsigned milliseconds) {
    struct timespec delay = {
        .tv_sec = (time_t)(milliseconds / 1000u),
        .tv_nsec = (long)(milliseconds % 1000u) * 1000000L
    };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) { }
}

static int read_client_hello(int fd) {
    uint8_t header[5];
    if (read_all(fd, header, sizeof header) != 0 || header[0] != 0x16) { return -1; }
    size_t length = ((size_t)header[3] << 8) | header[4];
    uint8_t *body = malloc(length ? length : 1);
    if (!body) { return -1; }
    int result = read_all(fd, body, length);
    free(body);
    return result;
}

static void *serve_responses(void *opaque) {
    struct server_args *args = opaque;
    static const uint8_t server_hello_done[] = {
        0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00
    };
    for (int index = 0; index < args->repeats * 2; index++) {
        int client = accept(args->fd, NULL, NULL);
        if (client < 0) { args->failed = 1; break; }
        if (read_client_hello(client) != 0) {
            args->failed = 1;
            close(client);
            break;
        }
        if (index == 0) {
            pause_ms(args->interrupt_delay_ms);
            if (pthread_kill(args->client_thread, SIGUSR1) != 0) { args->failed = 1; }
            pause_ms(args->response_delay_ms - args->interrupt_delay_ms);
        }
        ssize_t sent = send(client, server_hello_done, sizeof server_hello_done,
                            MSG_NOSIGNAL);
        if (sent != (ssize_t)sizeof server_hello_done && index != 0) { args->failed = 1; }
        close(client);
    }
    close(args->fd);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) { return 2; }
    unsigned repeats = fixture_value(argv[1], "repeats");
    unsigned timeout_ms = fixture_value(argv[1], "timeout_ms");
    unsigned interrupt_delay_ms = fixture_value(argv[1], "interrupt_delay_ms");
    unsigned response_delay_ms = fixture_value(argv[1], "response_delay_ms");
    if (repeats != 3 || timeout_ms <= response_delay_ms ||
        interrupt_delay_ms >= response_delay_ms) {
        fprintf(stderr, "invalid TLS EINTR fixture\n");
        return 2;
    }

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = ignore_signal;
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
    socklen_t address_length = sizeof address;
    if (getsockname(listener, (struct sockaddr *)&address, &address_length) != 0) {
        perror("getsockname"); close(listener); return 2;
    }

    struct server_args args = {
        .fd = listener,
        .repeats = (int)repeats,
        .interrupt_delay_ms = interrupt_delay_ms,
        .response_delay_ms = response_delay_ms,
        .client_thread = pthread_self(),
        .failed = 0
    };
    pthread_t server;
    if (pthread_create(&server, NULL, serve_responses, &args) != 0) {
        perror("pthread_create"); close(listener); return 2;
    }

    d2k_opts options;
    memset(&options, 0, sizeof options);
    options.repeats = (int)repeats;
    options.timeout_ms = (int)timeout_ms;
    d2k_resp_result result;
    char port[8];
    (void)snprintf(port, sizeof port, "%u", (unsigned)ntohs(address.sin_port));
    d2k_probe_response("127.0.0.1", port, "eintr.example", &options, &result);
    (void)pthread_join(server, NULL);
    if (args.failed) { fprintf(stderr, "fixture TLS server failed\n"); return 2; }

    printf("verdict=%s target=%d control=%d\n",
           d2k_resp_name(result.verdict), result.target, result.control);
    return 0;
}
