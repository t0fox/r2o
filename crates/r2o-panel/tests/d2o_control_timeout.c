#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int exchange(const d2k_panel_config *config, const char *request,
                    char *response, size_t capacity) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return -1;
    size_t request_length = strlen(request);
    if (write(sockets[0], request, request_length) != (ssize_t)request_length) {
        close(sockets[0]);
        close(sockets[1]);
        return -1;
    }
    shutdown(sockets[0], SHUT_WR);
    (void)d2k_panel_handle_fd(sockets[1], config);
    close(sockets[1]);

    size_t received = 0;
    while (received + 1 < capacity) {
        ssize_t count = read(sockets[0], response + received, capacity - received - 1);
        if (count == 0) break;
        if (count < 0) {
            close(sockets[0]);
            return -1;
        }
        received += (size_t)count;
    }
    close(sockets[0]);
    response[received] = '\0';
    int status = 0;
    if (sscanf(response, "HTTP/1.1 %d", &status) != 1) return -1;
    return status;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    d2k_panel_config config = {
        .service_path = argv[1],
        .control_enabled = 1,
    };
    char response[65536];
    static const char start_request[] =
        "POST /api/control/stop HTTP/1.1\r\nHost: localhost:8090\r\n"
        "Origin: http://localhost:8090\r\nContent-Length: 0\r\n\r\n";
    int status = exchange(&config, start_request, response, sizeof response);
    if (status != 202) return 3;

    const struct timespec pause = {.tv_nsec = 200000000};
    (void)nanosleep(&pause, NULL);
    static const char status_request[] =
        "GET /api/status HTTP/1.1\r\nHost: localhost:8090\r\n\r\n";
    status = exchange(&config, status_request, response, sizeof response);
    if (status != 200) return 4;
    char *body = strstr(response, "\r\n\r\n");
    if (!body) return 5;
    char *state = strstr(body + 4, "\"control_state\":\"");
    if (!state) return 6;
    state += sizeof "\"control_state\":\"" - 1;
    char *end = strchr(state, '"');
    if (!end) return 7;
    *end = '\0';
    printf("%s\n", state);
    return 0;
}
