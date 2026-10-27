#define _POSIX_C_SOURCE 200809L
#include "d2k_httpsearch.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    int fd;
    char first[64];
    char second[64];
} server_state;

static int read_request(int fd, char *path, size_t capacity)
{
    char request[2048];
    size_t used = 0;
    while (used < sizeof(request) - 1) {
        if (recv(fd, request + used, 1, 0) != 1) return -1;
        used++;
        request[used] = '\0';
        if (used >= 4 && !strcmp(request + used - 4, "\r\n\r\n")) break;
    }
    char method[16], parsed[1024], version[16];
    if (sscanf(request, "%15s %1023s %15s", method, parsed, version) != 3 ||
        strcmp(method, "GET") != 0 || strlen(parsed) >= capacity) return -1;
    snprintf(path, capacity, "%s", parsed);
    return 0;
}

static void *serve_keepalive(void *arg)
{
    server_state *state = arg;
    int client = accept(state->fd, NULL, NULL);
    if (client < 0) return NULL;
    struct timeval timeout = {.tv_sec = 2};
    (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    char *paths[] = {state->first, state->second};
    for (size_t i = 0; i < 2; i++) {
        if (read_request(client, paths[i], 64) != 0) break;
        const struct timespec delay = {.tv_nsec = 5000000};
        nanosleep(&delay, NULL);
        static const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        if (send(client, response, sizeof(response) - 1, 0) < 0) break;
    }
    close(client);
    return NULL;
}

int main(void)
{
    server_state state = {.fd = socket(AF_INET, SOCK_STREAM, 0)};
    if (state.fd < 0) return 2;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t address_length = sizeof(address);
    if (bind(state.fd, (struct sockaddr *)&address, address_length) != 0 ||
        listen(state.fd, 1) != 0 ||
        getsockname(state.fd, (struct sockaddr *)&address, &address_length) != 0) return 2;
    d2k_hs_probe_port = ntohs(address.sin_port);
    d2k_hs_probe_ms = 1000;
    pthread_t server;
    if (pthread_create(&server, NULL, serve_keepalive, &state) != 0) return 2;

    d2k_hs_job job = {0};
    job.fd = socket(AF_INET, SOCK_STREAM, 0);
    job.family = 4;
    job.addr[0] = 127;
    job.addr[3] = 1;
    snprintf(job.host, sizeof(job.host), "example.com");
    snprintf(job.repeat_path, sizeof(job.repeat_path), "/watch/42");
    d2k_hs_result result;
    d2k_hs_probe_run(&job, &result);
    close(job.fd);
    pthread_join(server, NULL);
    close(state.fd);

    const char *answer = result.answer == D2K_HS_REAL ? "REAL" : "OTHER";
    printf("answer=%s\ncomplete_responses=%u\nfirst=%s\nsecond=%s\n",
           answer, result.complete_responses, state.first, state.second);
    return result.answer == D2K_HS_REAL && result.complete_responses == 2 &&
           strcmp(state.first, "/") == 0 && strcmp(state.second, "/watch/42") == 0 ? 0 : 1;
}
