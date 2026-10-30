#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    d2k_panel_config config = {
        .config_path = argv[1],
        .service_path = argv[2],
        .control_enabled = 1,
    };
    static const char request[] =
        "POST /api/control/telegram-enable HTTP/1.1\r\n"
        "Host: localhost:8090\r\n"
        "Origin: http://localhost:8090\r\n"
        "Content-Length: 0\r\n\r\n";
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 3;
    if (write(sockets[0], request, sizeof request - 1) != (ssize_t)(sizeof request - 1)) {
        close(sockets[0]);
        close(sockets[1]);
        return 4;
    }
    shutdown(sockets[0], SHUT_WR);
    (void)d2k_panel_handle_fd(sockets[1], &config);
    close(sockets[1]);

    char response[8192];
    size_t received = 0;
    while (received + 1 < sizeof response) {
        ssize_t count = read(sockets[0], response + received,
                             sizeof response - received - 1);
        if (count == 0) break;
        if (count < 0) {
            close(sockets[0]);
            return 5;
        }
        received += (size_t)count;
    }
    close(sockets[0]);
    response[received] = '\0';
    int status = 0;
    if (sscanf(response, "HTTP/1.1 %d", &status) != 1) return 6;
    char *body = strstr(response, "\r\n\r\n");
    if (!body) return 7;
    printf("%d\n%s\n", status, body + 4);
    return 0;
}
