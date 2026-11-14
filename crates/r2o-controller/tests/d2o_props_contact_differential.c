/* C/Rust differential: d2k_props_contact_on_family_tcp_profile
 * (core/compose.c:632-753). Проверяются family 4/6, use_fd/out_fd, пустое
 * приветствие, коды -1/-3, локальные адрес/порт и факт отправки. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "compose.c"

struct server {
    int listener;
    int received;
};

static void *server_main(void *arg) {
    struct server *server = arg;
    struct pollfd pfd = {.fd = server->listener, .events = POLLIN};
    if (poll(&pfd, 1, 2000) <= 0) return NULL;
    int fd = accept(server->listener, NULL, NULL);
    if (fd < 0) return NULL;
    struct timeval tv = {0, 300000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char buffer[64];
    size_t total = 0;
    for (;;) {
        ssize_t n = recv(fd, buffer, sizeof buffer, 0);
        if (n <= 0) break;
        total += (size_t)n;
    }
    close(fd);
    server->received = (int)total;
    return NULL;
}

static int start_server(uint8_t family, struct server *server) {
    memset(server, 0, sizeof *server);
    int domain = family == 6 ? AF_INET6 : AF_INET;
    server->listener = socket(domain, SOCK_STREAM, 0);
    if (server->listener < 0) return -1;
    int one = 1;
    setsockopt(server->listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (family == 6)
        setsockopt(server->listener, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    struct sockaddr_storage address;
    socklen_t length;
    memset(&address, 0, sizeof address);
    if (family == 6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;
        v6->sin6_family = AF_INET6;
        v6->sin6_addr = in6addr_loopback;
        length = sizeof *v6;
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
        v4->sin_family = AF_INET;
        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        length = sizeof *v4;
    }
    if (bind(server->listener, (struct sockaddr *)&address, length) != 0 ||
        listen(server->listener, 1) != 0) {
        close(server->listener);
        return -1;
    }
    length = sizeof address;
    if (getsockname(server->listener, (struct sockaddr *)&address, &length) != 0) {
        close(server->listener);
        return -1;
    }
    if (family == 6)
        return ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
    return ntohs(((struct sockaddr_in *)&address)->sin_port);
}

static int first = 1;

static void emit(const char *name, int rc, uint8_t family, uint16_t local_port,
                 int out_fd, int received) {
    printf("%s{\"name\":\"%s\",\"rc\":%d,\"local_family\":%d,"
           "\"local_port_nonzero\":%s,\"returned_fd\":%s,\"received\":%d}",
           first ? "" : ",\n", name, rc, rc == 0 ? family : 0,
           rc == 0 && local_port != 0 ? "true" : "false",
           out_fd >= 0 ? "true" : "false", received);
    first = 0;
}

static void run_connected(const char *name, uint8_t family, const char *ip,
                          const char *hello_text, int use_use_fd, int want_fd) {
    struct server server;
    int port = start_server(family, &server);
    if (port < 0) {
        emit(name, -100, family, 0, -1, -1);
        return;
    }
    pthread_t thread;
    pthread_create(&thread, NULL, server_main, &server);
    d2k_hello hello = {(unsigned char *)hello_text, strlen(hello_text)};
    uint8_t local_addr[16] = {0};
    uint16_t local_port = 0;
    int out_fd = -1;
    int use_fd = -1;
    if (use_use_fd) use_fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    int rc = d2k_props_contact_on_family_tcp_profile(
        use_fd, ip, (uint16_t)port, hello, family, -1, local_addr, &local_port,
        want_fd ? &out_fd : NULL);
    pthread_join(thread, NULL);
    close(server.listener);
    if (out_fd >= 0) close(out_fd);
    emit(name, rc, family, local_port, out_fd, server.received);
}

static uint8_t current_timestamps(void) {
    FILE *f = fopen("/proc/sys/net/ipv4/tcp_timestamps", "r");
    if (!f) return 1;
    int value = 1;
    if (fscanf(f, "%d", &value) != 1) value = 1;
    fclose(f);
    return (uint8_t)value;
}

int main(void) {
    printf("{\"cases\":[\n");
    run_connected("v4_new_fd", 4, "127.0.0.1", "abc", 0, 1);
    run_connected("v4_no_fd", 4, "127.0.0.1", "abcd", 0, 0);
    run_connected("v6_no_fd", 6, "::1", "xyz", 0, 0);
    run_connected("v4_empty_hello", 4, "127.0.0.1", "", 0, 1);
    run_connected("v4_use_fd", 4, "127.0.0.1", "use", 1, 0);

    uint8_t local_addr[16] = {0};
    uint16_t local_port = 0;
    int out_fd = -1;
    d2k_hello hello = {(unsigned char *)"x", 1};
    int rc = d2k_props_contact_on_family_tcp_profile(
        -1, "127.0.0.1", 9, hello, 5, -1, local_addr, &local_port, &out_fd);
    emit("bad_family", rc, 5, 0, -1, -1);
    rc = d2k_props_contact_on_family_tcp_profile(
        -1, "fe80::1%eth0", 9, hello, 6, -1, local_addr, &local_port, &out_fd);
    emit("scoped_ipv6", rc, 6, 0, -1, -1);
    rc = d2k_props_contact_on_family_tcp_profile(
        -1, "not-an-ip", 9, hello, 4, -1, local_addr, &local_port, &out_fd);
    emit("bad_ip", rc, 4, 0, -1, -1);

    uint8_t timestamps = current_timestamps() == 1 ? 0 : 1;
    {
        struct server server;
        int port = start_server(4, &server);
        pthread_t thread;
        pthread_create(&thread, NULL, server_main, &server);
        rc = d2k_props_contact_on_family_tcp_profile(
            -1, "127.0.0.1", (uint16_t)port, hello, 4, (int8_t)timestamps,
            local_addr, &local_port, NULL);
        pthread_join(thread, NULL);
        close(server.listener);
        emit("profile_write", rc, 4, local_port, -1, server.received);
    }

    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address;
        memset(&address, 0, sizeof address);
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(fd, (struct sockaddr *)&address, sizeof address);
        socklen_t length = sizeof address;
        getsockname(fd, (struct sockaddr *)&address, &length);
        int port = ntohs(address.sin_port);
        close(fd);
        rc = d2k_props_contact_on_family_tcp_profile(
            -1, "127.0.0.1", (uint16_t)port, hello, 4, -1, local_addr,
            &local_port, NULL);
        emit("closed_port", rc, 4, 0, -1, -1);
    }
    printf("]}\n");
    return 0;
}
