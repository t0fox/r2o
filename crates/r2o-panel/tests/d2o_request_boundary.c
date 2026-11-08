#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int run_case(size_t header_end) {
    static const char prefix[] = "GET /nope HTTP/1.1\r\nX-Pad: ";
    static const char suffix[] = "\r\n\r\n";
    const size_t prefix_len = sizeof prefix - 1;
    if (header_end < prefix_len + sizeof suffix - 1) return 2;
    const size_t padding = header_end - prefix_len - (sizeof suffix - 1);
    const size_t request_len = prefix_len + padding + sizeof suffix - 1;
    char *request = malloc(request_len);
    if (!request) return 2;
    memcpy(request, prefix, prefix_len);
    memset(request + prefix_len, 'a', padding);
    memcpy(request + prefix_len + padding, suffix, sizeof suffix - 1);

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        free(request);
        return 2;
    }
    size_t sent = 0;
    while (sent < request_len) {
        ssize_t n = write(sockets[0], request + sent, request_len - sent);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            close(sockets[0]);
            close(sockets[1]);
            free(request);
            return 2;
        }
        sent += (size_t)n;
    }
    free(request);
    if (shutdown(sockets[0], SHUT_WR) != 0) return 2;

    d2k_panel_config config = {0};
    (void)d2k_panel_handle_fd(sockets[1], &config);
    close(sockets[1]);

    char response[256];
    ssize_t count = read(sockets[0], response, sizeof response - 1);
    close(sockets[0]);
    if (count <= 0) return 1;
    response[count] = '\0';
    unsigned int status;
    if (sscanf(response, "HTTP/1.1 %u", &status) != 1) return 1;
    printf("header_end=%zu HTTP/1.1 %u\n", header_end, status);
    return 0;
}

int main(void) {
    const size_t cases[] = {32767, 32768, 32769, 32770};
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int rc = run_case(cases[i]);
        if (rc != 0) return rc;
    }
    return 0;
}
