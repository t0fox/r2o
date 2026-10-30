#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int exchange(const d2k_panel_config *config, const char *path,
                    const char *body, char *response_body, size_t body_cap) {
    char request[4096];
    size_t request_body_len = strlen(body);
    int request_len = snprintf(
        request, sizeof request,
        "POST %s HTTP/1.1\r\nHost: localhost:8090\r\n"
        "Origin: http://localhost:8090\r\nContent-Type: application/json\r\n"
        "Content-Length: %zu\r\n\r\n%s",
        path, request_body_len, body);
    if (request_len < 0 || (size_t)request_len >= sizeof request) { return -1; }

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) { return -1; }
    size_t sent = 0;
    while (sent < (size_t)request_len) {
        ssize_t count = write(sockets[0], request + sent, (size_t)request_len - sent);
        if (count <= 0) { close(sockets[0]); close(sockets[1]); return -1; }
        sent += (size_t)count;
    }
    shutdown(sockets[0], SHUT_WR);
    (void)d2k_panel_handle_fd(sockets[1], config);
    close(sockets[1]);

    char response[8192];
    size_t received = 0;
    while (received + 1 < sizeof response) {
        ssize_t count = read(sockets[0], response + received, sizeof response - received - 1);
        if (count == 0) { break; }
        if (count < 0) { close(sockets[0]); return -1; }
        received += (size_t)count;
    }
    close(sockets[0]);
    response[received] = '\0';

    int status = 0;
    if (sscanf(response, "HTTP/1.1 %d", &status) != 1) { return -1; }
    const char *separator = strstr(response, "\r\n\r\n");
    if (!separator) { return -1; }
    const char *start = separator + 4;
    size_t response_len = received - (size_t)(start - response);
    if (response_len + 1 > body_cap) { return -1; }
    memcpy(response_body, start, response_len);
    response_body[response_len] = '\0';
    return status;
}

static void print_config(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) { exit(6); }
    char content[4096];
    size_t length = fread(content, 1, sizeof content - 1, file);
    fclose(file);
    content[length] = '\0';
    for (size_t i = 0; i < length; ++i) {
        if (content[i] == '\n') { content[i] = '|'; }
    }
    printf("config:%s\n", content);
}

int main(void) {
    const char *service = getenv("R2O_PANEL_WORKER_SERVICE");
    const char *config_path = getenv("R2O_PANEL_WORKER_CONFIG");
    if (!service || !config_path) { return 2; }
    d2k_panel_config config = {
        .config_path = config_path,
        .service_path = service,
        .control_enabled = 1,
    };
    char body[4096];
    int status = exchange(
        &config, "/api/control/stop", "",
        body, sizeof body);
    if (status < 0) { return 3; }
    printf("%d\n%s\n", status, body);
    status = exchange(
        &config, "/api/telegram/workers", "{\"domains\":[\"new.example\"]}",
        body, sizeof body);
    if (status < 0) { return 4; }
    printf("%d\n%s\n", status, body);
    print_config(config_path);
    return 0;
}
