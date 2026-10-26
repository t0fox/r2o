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

#include "d2k_voice.h"

struct server_args {
    int fd;
    unsigned repeats;
    unsigned interrupt_delay_ms;
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

static void make_response(const uint8_t *request, uint8_t response[32]) {
    static const uint8_t cookie[4] = {0x21, 0x12, 0xa4, 0x42};
    static const uint8_t address[4] = {192, 0, 2, 1};
    uint16_t port = htons((uint16_t)(3478u ^ 0x2112u));
    memset(response, 0, 32);
    response[0] = 1;
    response[1] = 1;
    response[3] = 12;
    memcpy(response + 4, cookie, sizeof cookie);
    memcpy(response + 8, request + 8, 12);
    response[21] = 0x20;
    response[23] = 8;
    response[25] = 1;
    memcpy(response + 26, &port, sizeof port);
    for (size_t i = 0; i < sizeof address; i++) {
        response[28 + i] = address[i] ^ cookie[i];
    }
}

static void *serve(void *opaque) {
    struct server_args *args = opaque;
    uint8_t requests[8][1500];
    struct sockaddr_storage peers[8];
    socklen_t peer_lengths[8];
    for (unsigned i = 0; i < args->repeats; i++) {
        struct sockaddr_storage peer;
        socklen_t peer_length = sizeof peer;
        ssize_t received = recvfrom(args->fd, requests[i], sizeof requests[i], 0,
                                    (struct sockaddr *)&peer, &peer_length);
        if (received != 20) {
            args->failed = 1;
            return NULL;
        }
        peers[i] = peer;
        peer_lengths[i] = peer_length;
    }
    pause_ms(args->interrupt_delay_ms);
    if (pthread_kill(args->client_thread, SIGUSR1) != 0) {
        args->failed = 1;
        return NULL;
    }
    if (args->response_delay_ms > args->interrupt_delay_ms) {
        pause_ms(args->response_delay_ms - args->interrupt_delay_ms);
    }
    for (unsigned i = 0; i < args->repeats; i++) {
        uint8_t response[32];
        make_response(requests[i], response);
        if (sendto(args->fd, response, sizeof response, 0,
                   (struct sockaddr *)&peers[i], peer_lengths[i]) != sizeof response) {
            args->failed = 1;
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    unsigned wait_ms = fixture_value(argv[1], "wait_ms");
    unsigned repeats = fixture_value(argv[1], "repeats");
    unsigned interrupt_delay_ms = fixture_value(argv[1], "interrupt_delay_ms");
    unsigned response_delay_ms = fixture_value(argv[1], "response_delay_ms");
    if (!wait_ms || repeats != D2K_VOICE_REPEATS ||
        interrupt_delay_ms >= response_delay_ms || response_delay_ms >= wait_ms) {
        fprintf(stderr, "invalid voice EINTR fixture\n");
        return 2;
    }

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = ignore_sigusr1;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) != 0) { perror("sigaction"); return 2; }

    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) { perror("socket"); return 2; }
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof address) != 0) {
        perror("bind"); close(server_fd); return 2;
    }
    socklen_t address_len = sizeof address;
    if (getsockname(server_fd, (struct sockaddr *)&address, &address_len) != 0) {
        perror("getsockname"); close(server_fd); return 2;
    }

    struct server_args args = {
        .fd = server_fd,
        .repeats = repeats,
        .interrupt_delay_ms = interrupt_delay_ms,
        .response_delay_ms = response_delay_ms,
        .client_thread = pthread_self(),
        .failed = 0
    };
    pthread_t server_thread;
    if (pthread_create(&server_thread, NULL, serve, &args) != 0) {
        perror("pthread_create"); close(server_fd); return 2;
    }

    d2k_voice_ask_fn ask = voice_ask_real();
    d2k_tally result = ask(htonl(INADDR_LOOPBACK), ntohs(address.sin_port),
                           NULL, 0, 0, wait_ms, 0, (int)repeats, NULL);
    (void)pthread_join(server_thread, NULL);
    close(server_fd);
    if (args.failed) {
        fprintf(stderr, "voice EINTR server failed\n");
        return 2;
    }
    printf("C_RESULT:pass=%d fail=%d errors=%d marked=%d\n",
           result.pass, result.fail, result.err, result.marked);
    return 0;
}
