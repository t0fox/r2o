#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    static const char prefix[] = "GET /unknown HTTP/1.1\r\nX-Padding: ";
    static const char suffix[] = "\r\n\r\n";
    const size_t padding = 20u * 1024u;
    const size_t request_len = sizeof prefix - 1 + padding + sizeof suffix - 1;
    char *request = malloc(request_len);
    if (!request) return 2;
    size_t offset = 0;
    memcpy(request + offset, prefix, sizeof prefix - 1);
    offset += sizeof prefix - 1;
    memset(request + offset, 'a', padding);
    offset += padding;
    memcpy(request + offset, suffix, sizeof suffix - 1);

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        free(request);
        return 2;
    }
    size_t sent = 0;
    while (sent < request_len) {
        ssize_t count = write(sockets[0], request + sent, request_len - sent);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            close(sockets[0]);
            close(sockets[1]);
            free(request);
            return 2;
        }
        sent += (size_t)count;
    }
    if (shutdown(sockets[0], SHUT_WR) != 0) {
        close(sockets[0]);
        close(sockets[1]);
        free(request);
        return 2;
    }
    free(request);
    d2k_panel_config config = {0};
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
