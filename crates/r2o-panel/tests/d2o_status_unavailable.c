#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "server.c"

int main(int argc, char **argv)
{
    d2k_panel_config config = {
        .live_path = argc > 1 ? argv[1] : NULL,
        .mode = "observe",
        .panel_listen = "127.0.0.1:8090",
    };
    char response_body[65536];
    size_t used = 0;
    int sockets[2];

    if (argc != 2 || socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        return 2;
    if (api_status(sockets[0], &config, NULL) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return 3;
    }
    close(sockets[0]);
    for (;;) {
        ssize_t n;
        if (used + 1 >= sizeof response_body) {
            close(sockets[1]);
            return 4;
        }
        n = read(sockets[1], response_body + used, sizeof response_body - used - 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            close(sockets[1]);
            return 5;
        }
        if (n == 0)
            break;
        used += (size_t)n;
    }
    close(sockets[1]);
    response_body[used] = '\0';
    char *body = strstr(response_body, "\r\n\r\n");
    if (!body)
        return 6;
    fputs(body + 4, stdout);
    return 0;
}
