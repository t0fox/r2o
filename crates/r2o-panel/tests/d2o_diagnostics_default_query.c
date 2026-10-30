#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int exchange(const d2k_panel_config *config, const char *request) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) { return 1; }
    size_t sent = 0;
    size_t request_len = strlen(request);
    while (sent < request_len) {
        ssize_t count = write(sockets[0], request + sent, request_len - sent);
        if (count <= 0) { close(sockets[0]); close(sockets[1]); return 2; }
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
        if (count < 0) { close(sockets[0]); return 3; }
        received += (size_t)count;
    }
    close(sockets[0]);
    response[received] = '\0';

    int status = 0;
    if (sscanf(response, "HTTP/1.1 %d", &status) != 1) { return 4; }
    const char *separator = strstr(response, "\r\n\r\n");
    if (!separator) { return 5; }
    printf("%d\n%s\n", status, separator + 4);
    return 0;
}

int main(void) {
    const char *dir = getenv("R2O_PANEL_DIAGNOSTICS_DIR");
    if (!dir || !*dir) { return 6; }
    d2k_panel_config config = {.diagnostics_dir = dir, .control_enabled = 1};
    static const char *requests[] = {
        "GET /api/diagnostics HTTP/1.1\r\nHost: router.local\r\n\r\n",
        "GET /api/diagnostics? HTTP/1.1\r\nHost: router.local\r\n\r\n",
    };
    for (size_t i = 0; i < sizeof requests / sizeof requests[0]; ++i) {
        if (exchange(&config, requests[i]) != 0) { return 7; }
    }
    return 0;
}
