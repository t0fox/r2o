/* Сравниваем тело команды, поскольку коды R2OP заняты голосовыми командами. */
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_link.h"

static int trace(int stream, size_t len) {
    uint8_t frame[64];
    if (read(stream, frame, len) != (ssize_t)len || frame[3] != len - 4)
        return 1;
    for (size_t i = 6; i < len; ++i)
        printf("%02x", frame[i]);
    putchar('\n');
    return 0;
}

int main(void) {
    int fd[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd))
        return 1;
    uint8_t v4[4], v6[16];
    if (inet_pton(AF_INET, "192.0.2.7", v4) != 1 ||
        inet_pton(AF_INET6, "2001:db8::7", v6) != 1)
        return 2;

    const int families[] = {4, 6};
    const uint8_t *addresses[] = {v4, v6};
    for (size_t i = 0; i < 2; ++i) {
        const uint16_t port = htons(853 + (uint16_t)i);
        if (d2k_link_set_endpoint(fd[0], addresses[i], families[i], port,
                                  D2K_LINK_SHAPE_QUIC, "aabb", NULL, 0) ||
            trace(fd[1], 28) ||
            d2k_link_del_endpoint(fd[0], addresses[i], families[i], port,
                                  D2K_LINK_SHAPE_VOICE, NULL, 0) ||
            trace(fd[1], 26) ||
            d2k_link_set_endpoint(fd[0], addresses[i], families[i], 0,
                                  D2K_LINK_SHAPE_QUIC, "aabb", NULL, 0) == 0)
            return 3;
    }
    close(fd[0]);
    close(fd[1]);
    return 0;
}
