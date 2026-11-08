#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    (void)umask(0077);
    d2k_panel_config config = {
        .config_path = argv[1],
        .service_path = argv[2],
        .control_enabled = 1,
    };
    static const char body[] = "{\"domains\":[\"New.Example\"]}";
    char request[4096];
    int length = snprintf(
        request, sizeof request,
        "POST /api/telegram/workers HTTP/1.1\r\nHost: localhost:8090\r\n"
        "Origin: http://localhost:8090\r\nContent-Type: application/json\r\n"
        "Content-Length: %zu\r\n\r\n%s",
        sizeof body - 1, body);
    if (length < 0 || (size_t)length >= sizeof request) return 3;

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 4;
    if (write(sockets[0], request, (size_t)length) != length) return 5;
    if (shutdown(sockets[0], SHUT_WR) != 0) return 5;
    (void)d2k_panel_handle_fd(sockets[1], &config);
    close(sockets[1]);
    char response[4096];
    while (read(sockets[0], response, sizeof response) > 0) {}
    close(sockets[0]);

    struct stat metadata;
    if (stat(argv[1], &metadata) != 0) return 6;
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 7;
    unsigned char saved[4096];
    size_t used = fread(saved, 1, sizeof saved, file);
    fclose(file);
    printf("mode=%04o\n", (unsigned)(metadata.st_mode & 0777));
    printf("config=");
    for (size_t i = 0; i < used; i++) printf("%02x", saved[i]);
    putchar('\n');
    return 0;
}
