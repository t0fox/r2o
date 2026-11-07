#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "server.c"

int main(int argc, char **argv)
{
    int sockets[2];
    char response[65536];
    ssize_t count;
    size_t used = 0;

    if (argc != 3) return 2;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 2;
    d2k_panel_config config = {
        .updater_path = strcmp(argv[1], "-") == 0 ? NULL : argv[1],
        .update_state_path = strcmp(argv[2], "-") == 0 ? NULL : argv[2],
    };
    if (api_update(sockets[0], &config) != 0) return 3;
    shutdown(sockets[0], SHUT_WR);
    while (used < sizeof response) {
        count = read(sockets[1], response + used, sizeof response - used);
        if (count <= 0) break;
        used += (size_t)count;
    }
    close(sockets[0]);
    close(sockets[1]);
    fwrite(response, 1, used, stdout);
    return 0;
}
