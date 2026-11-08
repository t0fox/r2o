#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char *requests[] = {
    "GET /nope HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "GET /nope HTTP/1.0\r\n\r\n",
    "POST /nope HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    "PUT / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    "GET /nope HTTP/2.0\r\n\r\n",
    "DELETE /assets/missing.js HTTP/1.1\r\n\r\n",
    "GET /api/unknown HTTP/1.1\r\n\r\n",
    "BREW /api/status HTTP/1.1\r\n\r\n",
    "GET /api/control/heal HTTP/1.1\r\n\r\n",
};

int main(void) {
    d2k_panel_config config = {0};
    for (size_t r = 0; r < sizeof requests / sizeof requests[0]; r++) {
        int sockets[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 2;
        size_t len = strlen(requests[r]);
        if (write(sockets[0], requests[r], len) != (ssize_t)len) return 2;
        if (shutdown(sockets[0], SHUT_WR) != 0) return 2;
        (void)d2k_panel_handle_fd(sockets[1], &config);
        close(sockets[1]);

        unsigned char response[8192];
        size_t used = 0;
        while (used < sizeof response) {
            ssize_t n = read(sockets[0], response + used, sizeof response - used);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            used += (size_t)n;
        }
        close(sockets[0]);
        for (size_t i = 0; i < used; i++) printf("%02x", response[i]);
        putchar('\n');
    }
    return 0;
}
