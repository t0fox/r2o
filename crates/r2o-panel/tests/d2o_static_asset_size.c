#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int write_all(int fd, const char *data, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        ssize_t count = write(fd, data + sent, length - sent);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        sent += (size_t)count;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char path[1024];
    int path_len = snprintf(path, sizeof path, "%s/index.html", argv[1]);
    if (path_len < 0 || (size_t)path_len >= sizeof path) return 2;
    int asset = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (asset < 0) return 2;
    char block[4096];
    memset(block, 'x', sizeof block);
    size_t remaining = 1024u * 1024u + 1u;
    while (remaining) {
        size_t count = remaining < sizeof block ? remaining : sizeof block;
        if (write_all(asset, block, count) != 0) {
            close(asset);
            return 2;
        }
        remaining -= count;
    }
    if (close(asset) != 0) return 2;

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 2;
    static const char request[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    if (write_all(sockets[0], request, sizeof request - 1) != 0 ||
        shutdown(sockets[0], SHUT_WR) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        return 2;
    }
    d2k_panel_config config = {.asset_dir = argv[1]};
    (void)d2k_panel_handle_fd(sockets[1], &config);
    close(sockets[1]);

    char response[1024];
    ssize_t count = read(sockets[0], response, sizeof response - 1);
    close(sockets[0]);
    if (count <= 0) return 1;
    response[count] = '\0';
    unsigned int status;
    if (sscanf(response, "HTTP/1.1 %u", &status) != 1) return 1;
    printf("HTTP/1.1 %u\n", status);
    return 0;
}
