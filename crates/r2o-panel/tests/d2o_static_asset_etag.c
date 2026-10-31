#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <utime.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char asset[1024];
    int written = snprintf(asset, sizeof asset, "%s/index.html", argv[1]);
    if (written < 0 || (size_t)written >= sizeof asset) return 2;
    struct utimbuf times = {.actime = 1234567890, .modtime = 1234567890};
    if (utime(asset, &times) != 0) return 2;

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 2;
    static const char request[] =
        "GET / HTTP/1.1\r\nHost: localhost\r\n"
        "If-None-Match: \"1-499602d2\"\r\n\r\n";
    if (write(sockets[0], request, sizeof request - 1) != (ssize_t)(sizeof request - 1)) return 2;
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
    char *status_end = strstr(response, "\r\n");
    char *etag = strstr(response, "ETag: ");
    char *etag_end = etag ? strstr(etag, "\r\n") : NULL;
    if (!status_end || !etag || !etag_end) return 1;
    printf("%.*s\n%.*s\n", 12, response,
           (int)(etag_end - etag), etag);
    return 0;
}
