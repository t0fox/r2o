#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) return 2;
    int post = strcmp(argv[1], "post") == 0;
    if (!post && strcmp(argv[1], "get") != 0) return 2;
    if (post != (argc == 4)) return 2;
    d2k_panel_config config = {
        .config_path = argv[2],
        .service_path = post ? argv[3] : NULL,
        .control_enabled = post,
    };
    static const char get_request[] =
        "GET /api/telegram/workers HTTP/1.1\r\nHost: localhost:8090\r\n\r\n";
    static const char post_body[] =
        "{\"domains\":[\"New.Example\"],\"note\":\"Привет\"}";
    char post_request[4096];
    int request_length = (int)(sizeof get_request - 1);
    const char *request = get_request;
    if (post) {
        request_length = snprintf(
            post_request, sizeof post_request,
            "POST /api/telegram/workers HTTP/1.1\r\nHost: localhost:8090\r\n"
            "Origin: http://localhost:8090\r\nContent-Type: application/json\r\n"
            "Content-Length: %zu\r\n\r\n%s",
            strlen(post_body), post_body);
        if (request_length < 0 ||
            (size_t)request_length >= sizeof post_request) return 3;
        request = post_request;
    }
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 4;
    if (write(sockets[0], request, (size_t)request_length) != request_length) {
        close(sockets[0]);
        close(sockets[1]);
        return 5;
    }
    shutdown(sockets[0], SHUT_WR);
    (void)d2k_panel_handle_fd(sockets[1], &config);
    close(sockets[1]);

    char response[4096];
    size_t received = 0;
    while (received + 1 < sizeof response) {
        ssize_t count = read(sockets[0], response + received,
                             sizeof response - received - 1);
        if (count == 0) break;
        if (count < 0) {
            close(sockets[0]);
            return 6;
        }
        received += (size_t)count;
    }
    close(sockets[0]);
    response[received] = '\0';
    int status = 0;
    if (sscanf(response, "HTTP/1.1 %d", &status) != 1) return 7;
    char *body = strstr(response, "\r\n\r\n");
    if (!body) return 8;
    printf("%d\n%s\n", status, body + 4);
    if (!post) return 0;

    FILE *file = fopen(argv[2], "rb");
    if (!file) return 9;
    char saved[4096];
    size_t length = fread(saved, 1, sizeof saved - 1, file);
    fclose(file);
    saved[length] = '\0';
    for (size_t i = 0; i < length; ++i) {
        if (saved[i] == '\n') saved[i] = '|';
    }
    printf("config:%s\n", saved);
    return 0;
}
