/* C-оракул qp_recv_ttl: датаграмма + TTL/hop limit из control-сообщений.
 *
 * Включает production core/quicprobe.c. Проверяются четыре наблюдаемых
 * исхода: IPv4 TTL, IPv4 без IP_RECVTTL, нулевая датаграмма, IPv6 hop limit.
 * Rust-сторона обязана напечатать тот же протокол.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "quicprobe.c"

static int bind_loopback(int family, struct sockaddr_storage *storage,
                         socklen_t *length)
{
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    memset(storage, 0, sizeof *storage);
    if (family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)storage;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        *length = sizeof *addr;
    } else {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)storage;
        addr->sin6_family = AF_INET6;
        addr->sin6_addr = in6addr_loopback;
        *length = sizeof *addr;
    }
    if (bind(fd, (const struct sockaddr *)storage, *length) != 0 ||
        getsockname(fd, (struct sockaddr *)storage, length) != 0) {
        close(fd);
        return -1;
    }
    struct timeval timeout = {1, 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    return fd;
}

static void send_payload(int family, const struct sockaddr_storage *storage,
                         socklen_t length, size_t payload)
{
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("sender socket");
        exit(1);
    }
    static const uint8_t byte = 'x';
    if (sendto(fd, &byte, payload, 0, (const struct sockaddr *)storage,
               length) != (ssize_t)payload) {
        perror("sendto");
        close(fd);
        exit(1);
    }
    close(fd);
}

static void measure(const char *name, int family, int enable, size_t payload)
{
    struct sockaddr_storage storage;
    socklen_t length = 0;
    int fd = bind_loopback(family, &storage, &length);
    if (fd < 0) {
        printf("%s|skip\n", name);
        return;
    }
    int on = 1;
    if (enable) {
        int level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
        int option = family == AF_INET ? IP_RECVTTL : IPV6_RECVHOPLIMIT;
        if (setsockopt(fd, level, option, &on, sizeof on) != 0) {
            perror("setsockopt");
            close(fd);
            exit(1);
        }
    }
    send_payload(family, &storage, length, payload);
    uint8_t buffer[16];
    uint8_t ttl = 0;
    ssize_t received = qp_recv_ttl(fd, buffer, sizeof buffer, &ttl);
    printf("%s|n=%zd|ttl=%u\n", name, received, (unsigned)ttl);
    close(fd);
}

int main(void)
{
    measure("ipv4", AF_INET, 1, 3);
    measure("ipv4_noopt", AF_INET, 0, 3);
    measure("ipv4_zero", AF_INET, 1, 0);
    measure("ipv6", AF_INET6, 1, 3);
    return 0;
}
