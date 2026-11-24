#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const unsigned char payload[] = "r2o-lan-wan-acceptance-v1";
static const unsigned char query[] = {
    0xca, 0xfe, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    3, 'l', 'a', 'b', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0, 0, 1, 0, 1
};
static const unsigned char answer[] = {
    0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 198, 18, 0, 2
};

static void fail(const char *message) {
    perror(message);
    exit(1);
}

static int endpoint(const char *address, unsigned port, int type, int server) {
    struct sockaddr_storage target = {0};
    struct sockaddr_in *v4 = (struct sockaddr_in *)&target;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&target;
    socklen_t len;
    if (strchr(address, ':')) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, address, &v6->sin6_addr) != 1) exit(2);
        len = sizeof(*v6);
    } else {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        if (inet_pton(AF_INET, address, &v4->sin_addr) != 1) exit(2);
        len = sizeof(*v4);
    }
    int fd = socket(target.ss_family, type, 0);
    int one = 1;
    struct timeval timeout = {.tv_sec = 3};
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) fail("socket");
    if (server) {
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ||
            bind(fd, (struct sockaddr *)&target, len)) fail("bind");
    } else if (connect(fd, (struct sockaddr *)&target, len)) fail("connect");
    return fd;
}

static ssize_t response(const unsigned char *input, ssize_t n, unsigned char *output, int dns) {
    if (dns && n >= (ssize_t)sizeof(query) && input[4] == 0 && input[5] == 1 &&
        memcmp(input + 12, query + 12, sizeof(query) - 16) == 0) {
        memcpy(output, input, sizeof(query));
        output[2] = 0x81;
        output[3] = 0x80;
        memset(output + 6, 0, 6);
        if (memcmp(input + sizeof(query) - 4, query + sizeof(query) - 4, 4) != 0)
            return sizeof(query);
        output[7] = 1;
        memcpy(output + sizeof(query), answer, sizeof(answer));
        return sizeof(query) + sizeof(answer);
    }
    if (!dns && n == (ssize_t)sizeof(payload) && memcmp(input, payload, n) == 0) {
        memcpy(output, input, n);
        return n;
    }
    return 0;
}

static void serve(const char *address) {
    struct pollfd listeners[] = {
        {endpoint(address, 443, SOCK_STREAM, 1), POLLIN, 0},
        {endpoint(address, 443, SOCK_DGRAM, 1), POLLIN, 0},
        {endpoint(address, 53, SOCK_DGRAM, 1), POLLIN, 0},
    };
    if (listen(listeners[0].fd, 16)) fail("listen");
    while (poll(listeners, 3, -1) >= 0 || errno == EINTR) {
        for (int i = 0; i < 3; ++i) {
            if (!(listeners[i].revents & POLLIN)) continue;
            unsigned char input[256], output[256];
            int fd = listeners[i].fd;
            struct sockaddr_storage peer;
            socklen_t len = sizeof(peer);
            if (i == 0) {
                int client = accept(fd, NULL, NULL);
                if (client < 0) continue;
                struct timeval timeout = {.tv_sec = 3};
                setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                ssize_t n = recv(client, input, sizeof(payload), MSG_WAITALL);
                n = response(input, n, output, 0);
                if (n > 0) send(client, output, n, MSG_NOSIGNAL);
                close(client);
            } else {
                ssize_t n = recvfrom(fd, input, sizeof(input), 0, (struct sockaddr *)&peer, &len);
                n = response(input, n, output, i == 2);
                if (n > 0) sendto(fd, output, n, 0, (struct sockaddr *)&peer, len);
            }
        }
    }
    fail("poll");
}

static void verify(const char *address, unsigned port, int type) {
    int dns = port == 53;
    const unsigned char *request = dns ? query : payload;
    size_t len = dns ? sizeof(query) : sizeof(payload);
    unsigned char reply[256], expected[256];
    ssize_t expected_len = response(request, len, expected, dns);
    int fd = endpoint(address, port, type, 0);
    if (send(fd, request, len, MSG_NOSIGNAL) != (ssize_t)len ||
        recv(fd, reply, expected_len, type == SOCK_STREAM ? MSG_WAITALL : 0) != expected_len ||
        memcmp(reply, expected, expected_len) != 0) fail("application response");
    close(fd);
    printf("LAN_RESPONSE_PASS address=%s protocol=%s port=%u bytes=%zd\n", address,
           type == SOCK_STREAM ? "tcp" : "udp", port, expected_len);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (!strcmp(argv[1], "server")) serve(argv[2]);
    else if (!strcmp(argv[1], "client")) {
        verify(argv[2], 443, SOCK_STREAM);
        verify(argv[2], 443, SOCK_DGRAM);
        verify(argv[2], 53, SOCK_DGRAM);
    } else return 2;
    return 0;
}
