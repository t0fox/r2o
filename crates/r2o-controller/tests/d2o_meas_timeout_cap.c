#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "d2k_meas.h"

static uint32_t captured_receive_timeout_ms;

int d2o_test_setsockopt(int fd, int level, int option,
                        const void *value, socklen_t length) {
    (void)fd;
    if (level == SOL_SOCKET && option == SO_RCVTIMEO &&
        length >= (socklen_t)sizeof(struct timeval)) {
        const struct timeval *timeout = value;
        captured_receive_timeout_ms = (uint32_t)timeout->tv_sec * 1000u +
                                      (uint32_t)timeout->tv_usec / 1000u;
    }
    return 0;
}

struct server {
    int fd;
    uint16_t port;
};

static void *reply_once(void *argument) {
    struct server *server = argument;
    int client = accept(server->fd, NULL, NULL);
    close(server->fd);
    if (client >= 0) {
        uint8_t request[8];
        (void)recv(client, request, sizeof request, 0);
        (void)send(client, "x", 1, 0);
        close(client);
    }
    return NULL;
}

int main(void) {
    struct server server;
    struct sockaddr_in address;
    socklen_t address_length = sizeof address;
    server.fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server.fd < 0) {
        return 1;
    }
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(server.fd, (struct sockaddr *)&address, sizeof address) < 0 ||
        listen(server.fd, 1) < 0 ||
        getsockname(server.fd, (struct sockaddr *)&address, &address_length) < 0) {
        close(server.fd);
        return 1;
    }
    server.port = ntohs(address.sin_port);
    pthread_t worker;
    if (pthread_create(&worker, NULL, reply_once, &server) != 0) {
        close(server.fd);
        return 1;
    }

    uint8_t hello_bytes[] = { 'P', 'I', 'N', 'G' };
    d2k_hello hello = { hello_bytes, sizeof hello_bytes, NULL, 0, 0, 0 };
    d2k_meas_outcome result = d2k_meas_once(
        "127.0.0.1", server.port, hello, NULL, 0, 0, 7000, 0,
        d2k_accept_any, NULL);
    pthread_join(worker, NULL);

    printf("timeout-ceiling=%u\n", captured_receive_timeout_ms);
    return result == D2K_MEAS_PASS && captured_receive_timeout_ms == 5000 ? 0 : 1;
}
