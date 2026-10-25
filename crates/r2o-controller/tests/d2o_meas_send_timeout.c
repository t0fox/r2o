#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
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
    uint32_t hold_ms;
    int receive_buffer_bytes;
};

static uint64_t fixture_value(const char *path, const char *key) {
    FILE *file = fopen(path, "r");
    if (!file) { perror(path); exit(2); }
    char line[128];
    size_t key_len = strlen(key);
    while (fgets(line, sizeof line, file)) {
        if (strncmp(line, key, key_len) == 0 && line[key_len] == '=') {
            char *end = NULL;
            unsigned long long value = strtoull(line + key_len + 1, &end, 10);
            if (end == line + key_len + 1) { break; }
            fclose(file);
            return (uint64_t)value;
        }
    }
    fclose(file);
    fprintf(stderr, "fixture key missing: %s\n", key);
    exit(2);
}

static void *hold_without_reading(void *opaque) {
    struct server_args *args = opaque;
    int client = accept(args->fd, NULL, NULL);
    if (client >= 0) {
        (void)setsockopt(client, SOL_SOCKET, SO_RCVBUF,
                         &args->receive_buffer_bytes,
                         sizeof args->receive_buffer_bytes);
        struct timespec pause = {
            .tv_sec = (time_t)(args->hold_ms / 1000u),
            .tv_nsec = (long)(args->hold_ms % 1000u) * 1000000L
        };
        (void)nanosleep(&pause, NULL);
        close(client);
    }
    close(args->fd);
    free(args);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) { return 2; }
    size_t payload_bytes = (size_t)fixture_value(argv[1], "payload_bytes");
    uint32_t send_timeout_ms = (uint32_t)fixture_value(argv[1], "send_timeout_ms");
    uint32_t response_timeout_ms = (uint32_t)fixture_value(argv[1], "response_timeout_ms");
    uint32_t server_hold_ms = (uint32_t)fixture_value(argv[1], "server_hold_ms");
    int receive_buffer_bytes = (int)fixture_value(argv[1], "server_receive_buffer_bytes");
    uint32_t mark = (uint32_t)fixture_value(argv[1], "mark");
    if (payload_bytes == 0 || send_timeout_ms == 0 || send_timeout_ms % 1000u != 0 ||
        server_hold_ms <= send_timeout_ms || receive_buffer_bytes <= 0) {
        fprintf(stderr, "invalid timeout fixture\n");
        return 2;
    }

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) { perror("socket"); return 2; }
    if (setsockopt(listener, SOL_SOCKET, SO_RCVBUF,
                   &receive_buffer_bytes, sizeof receive_buffer_bytes) != 0) {
        perror("SO_RCVBUF"); close(listener); return 2;
    }
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

    struct server_args *args = malloc(sizeof *args);
    if (!args) { close(listener); return 2; }
    args->fd = listener;
    args->hold_ms = server_hold_ms;
    args->receive_buffer_bytes = receive_buffer_bytes;
    pthread_t thread;
    if (pthread_create(&thread, NULL, hold_without_reading, args) != 0) {
        perror("pthread_create"); close(listener); free(args); return 2;
    }
    (void)pthread_detach(thread);

    uint8_t *payload = malloc(payload_bytes);
    if (!payload) { return 2; }
    memset(payload, 0xa5, payload_bytes);
    d2k_hello hello = { payload, payload_bytes, NULL, 0, 0, 0 };
    d2k_send_timeout_s = send_timeout_ms / 1000u;
    int marked = 0;
    int result = d2k_meas_once("127.0.0.1", ntohs(address.sin_port), hello,
                               NULL, 0, 0, response_timeout_ms, mark,
                               NULL, &marked);
    printf("C_RESULT:%s\n", result == D2K_MEAS_ERR ? "ERROR" :
           result == D2K_MEAS_SILENT ? "SILENT" :
           result == D2K_MEAS_PASS ? "PASS" : "UNPROVEN");
    free(payload);
    return 0;
}
