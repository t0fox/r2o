#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    static const char *keys[] = {"Z-KEY", "A-KEY"};
    d2k_panel_config config = {
        .live_path = "/nonexistent/r2o-live.json",
        .version = "9.9.9",
        .commit = "abc123",
        .built = "2026-11-08",
        .mode = "apply",
        .panel_listen = "127.0.0.1:8090",
        .config_path = "/tmp/r2o-panel-status/config",
        .state_dir = argv[1],
        .state_dir_note = "есть",
        .unknown_keys = keys,
        .unknown_key_count = 2,
        .started_epoch = 0,
        .queue_num = 2000,
        .config_exists = 1,
        .dirty = 0,
        .control_enabled = 0,
    };
    static const char request[] =
        "GET /api/status HTTP/1.1\r\nHost: localhost:8090\r\n\r\n";
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 3;
    if (write(sockets[0], request, sizeof request - 1) !=
        (ssize_t)(sizeof request - 1)) return 4;
    if (shutdown(sockets[0], SHUT_WR) != 0) return 4;
    (void)d2k_panel_handle_fd(sockets[1], &config);
    close(sockets[1]);

    char response[131072];
    size_t used = 0;
    while (used + 1 < sizeof response) {
        ssize_t n = read(sockets[0], response + used, sizeof response - used - 1);
        if (n <= 0) break;
        used += (size_t)n;
    }
    close(sockets[0]);
    response[used] = '\0';
    char *body = strstr(response, "\r\n\r\n");
    if (!body) return 5;
    fputs(body + 4, stdout);
    return 0;
}
