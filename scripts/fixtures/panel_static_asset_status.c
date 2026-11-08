#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 2;
    static const char request[] =
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    if (write(sockets[0], request, sizeof request - 1) !=
        (ssize_t)(sizeof request - 1)) return 2;
    if (shutdown(sockets[0], SHUT_WR) != 0) return 2;

    d2k_panel_config config = {.asset_dir = argv[1]};
    (void)d2k_panel_handle_fd(sockets[1], &config);
    close(sockets[1]);

    char response[4096];
    size_t used = 0;
    while (used + 1 < sizeof response) {
        ssize_t count = read(sockets[0], response + used, sizeof response - used - 1);
        if (count <= 0) break;
        used += (size_t)count;
    }
    close(sockets[0]);
    response[used] = '\0';
    int status = 0;
    if (sscanf(response, "HTTP/1.1 %d", &status) != 1) return 1;
    char *body = strstr(response, "\r\n\r\n");
    if (!body) return 1;
    body += 4;
    size_t body_len = strlen(body);
    while (body_len && (body[body_len - 1] == '\n' || body[body_len - 1] == '\r')) {
        body[--body_len] = '\0';
    }
    printf("%d %s\n", status, body);
    return 0;
}
