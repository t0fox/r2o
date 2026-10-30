#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int exchange(const d2k_panel_config *config, char *body, size_t body_cap) {
    static const char request[] =
        "POST /api/control/stop HTTP/1.1\r\n"
        "Host: localhost:8090\r\n"
        "Origin: http://localhost:8090\r\n"
        "Content-Length: 0\r\n\r\n";
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) { return -1; }
    size_t sent = 0;
    while (sent < sizeof request - 1) {
        ssize_t count = write(sockets[0], request + sent, sizeof request - 1 - sent);
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
    const char *body_start = separator + 4;
    size_t body_len = received - (size_t)(body_start - response);
    if (body_len + 1 > body_cap) { return -1; }
    memcpy(body, body_start, body_len);
    body[body_len] = '\0';
    return status;
}

int main(void) {
    const char *service = getenv("R2O_PANEL_CONTROL_SERVICE");
    if (!service || !*service) { return 2; }
    d2k_panel_config config = {
        .service_path = service,
        .control_enabled = 1,
    };
    char body[4096];
    int status = exchange(&config, body, sizeof body);
    if (status < 0) { return 3; }
    printf("%d\n%s\n", status, body);
    status = exchange(&config, body, sizeof body);
    if (status < 0) { return 4; }
    printf("%d\n%s\n", status, body);
    config.service_path = "";
    status = exchange(&config, body, sizeof body);
    if (status < 0) { return 5; }
    printf("%d\n%s\n", status, body);
    return 0;
}
