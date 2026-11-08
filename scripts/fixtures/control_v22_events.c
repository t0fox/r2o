#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_link.h"

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_hex(const char *text, uint8_t *out, size_t cap, size_t *len) {
    size_t n = strlen(text);
    if ((n & 1u) || n / 2 > cap) return -1;
    for (size_t i = 0; i < n; i += 2) {
        int hi = hex_value(text[i]);
        int lo = hex_value(text[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *len = n / 2;
    return 0;
}

static int write_all(int fd, const uint8_t *bytes, size_t len) {
    while (len) {
        ssize_t n = write(fd, bytes, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        bytes += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s FRAMES.hex\n", argv[0]);
        return 2;
    }
    FILE *fixture = fopen(argv[1], "r");
    if (!fixture) return 2;

    char wire_hex[16384];
    unsigned line = 0;
    while (fscanf(fixture, "%16383s", wire_hex) == 1) {
        line++;
        uint8_t wire[8192];
        size_t wire_len = 0;
        if (decode_hex(wire_hex, wire, sizeof wire, &wire_len) != 0) return 3;

        int fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return 4;
        if (write_all(fds[1], wire, wire_len) != 0) return 5;

        d2k_ev event;
        char err[256] = {0};
        int rc = d2k_link_next(fds[0], &event, 1000, err, sizeof err);
        close(fds[0]);
        close(fds[1]);
        if (rc != 0) {
            fprintf(stderr, "C decoder rejected line %u: %s\n", line, err);
            return 6;
        }
        switch (event.kind) {
        case D2K_EV_SUSPECT:
            printf("SUSPECT code=%u ttl=%u ref=%u tos=%u ipid=%u planned=%u shape=%u num=%u\n",
                   event.code, event.ttl, event.ref_ttl, event.tos, event.ipid,
                   event.planned, event.client_shape, event.num);
            break;
        case D2K_EV_EXCHANGE:
            printf("EXCHANGE first=%u seen=%u num=%u server_hello=%u planned=%u\n",
                   event.code, event.seen_types, event.num, event.server_hello,
                   event.planned);
            break;
        case D2K_EV_CLIENT_TCP:
            printf("CLIENT_TCP tcp_options_len=%zu\n", event.tcp_options_len);
            break;
        case D2K_EV_SHAPE:
            printf("SHAPE shape_len=%zu\n", event.shape_len);
            break;
        default:
            printf("OTHER kind=0x%04x\n", event.kind);
            break;
        }
    }
    return 0;
}
