#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 2;
    static const char request[] =
        "POST /api/telegram/workers HTTP/1.1\r\n"
        "Host: localhost\r\nOrigin: http://localhost\r\n"
        "Content-Type: application/json\r\nContent-Length: 00021\r\n\r\n"
        "{\"domains\":[\"x.com\"]}";
    if (write(sockets[0], request, sizeof request - 1) != (ssize_t)(sizeof request - 1)) return 2;
    if (shutdown(sockets[0], SHUT_WR) != 0) return 2;
    d2k_panel_config config = {
        .config_path = argv[1],
        .control_enabled = 1,
    };
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
    unsigned int status;
    if (sscanf(response, "HTTP/1.1 %u", &status) != 1) return 1;
    printf("HTTP/1.1 %u\n", status);

    FILE *config_file = fopen(argv[1], "rb");
    if (!config_file) return 1;
    char chunk[1024];
    size_t count;
    while ((count = fread(chunk, 1, sizeof chunk, config_file)) != 0) {
        if (fwrite(chunk, 1, count, stdout) != count) {
            fclose(config_file);
            return 1;
        }
    }
    int failed = ferror(config_file);
    fclose(config_file);
    return failed ? 1 : 0;
}
