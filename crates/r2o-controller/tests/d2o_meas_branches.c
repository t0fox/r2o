/* C/Rust differential: d2k_meas_once response and local-error branches.
 *
 * Один сценарий за запуск: server-поток читает приветствие и отвечает
 * заданными байтами, закрывает соединение или сбрасывает его RST.
 */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_meas.h"

struct server_args {
    int fd;
    size_t payload_bytes;
    const uint8_t *response;
    size_t response_len;
    int reset;
    int failed;
};

static void *serve_one(void *opaque) {
    struct server_args *args = opaque;
    int client = accept(args->fd, NULL, NULL);
    if (client < 0) {
        args->failed = 1;
        close(args->fd);
        return NULL;
    }
    uint8_t bytes[8192];
    size_t received = 0;
    while (received < args->payload_bytes) {
        size_t remaining = args->payload_bytes - received;
        size_t capacity = remaining < sizeof bytes ? remaining : sizeof bytes;
        ssize_t n = recv(client, bytes, capacity, 0);
        if (n > 0) { received += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) { continue; }
        args->failed = 1;
        close(client);
        close(args->fd);
        return NULL;
    }
    if (args->response_len > 0) {
        (void)send(client, args->response, args->response_len, MSG_NOSIGNAL);
    }
    if (args->reset) {
        struct linger linger = {1, 0};
        (void)setsockopt(client, SOL_SOCKET, SO_LINGER, &linger, sizeof linger);
    }
    close(client);
    close(args->fd);
    return NULL;
}

static int start_listener(struct sockaddr_in *address) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) { perror("socket"); return -1; }
    memset(address, 0, sizeof *address);
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)address, sizeof *address) != 0 ||
        listen(listener, 1) != 0) {
        perror("bind/listen");
        close(listener);
        return -1;
    }
    socklen_t length = sizeof *address;
    if (getsockname(listener, (struct sockaddr *)address, &length) != 0) {
        perror("getsockname");
        close(listener);
        return -1;
    }
    return listener;
}

static int run_network(const char *scenario, const uint8_t *response,
                       size_t response_len, int reset, d2k_accept_fn accept) {
    struct sockaddr_in address;
    int listener = start_listener(&address);
    if (listener < 0) return 2;
    struct server_args args = {
        .fd = listener,
        .payload_bytes = 64,
        .response = response,
        .response_len = response_len,
        .reset = reset,
        .failed = 0,
    };
    pthread_t server;
    if (pthread_create(&server, NULL, serve_one, &args) != 0) {
        perror("pthread_create");
        close(listener);
        return 2;
    }
    uint8_t payload[64];
    memset(payload, 0xa5, sizeof payload);
    d2k_hello hello = { payload, sizeof payload, NULL, 0, 0, 0 };
    int marked = 0;
    int result = d2k_meas_once("127.0.0.1", ntohs(address.sin_port), hello,
                               NULL, 0, 0, 500, 0, accept, &marked);
    (void)pthread_join(server, NULL);
    if (args.failed) {
        fprintf(stderr, "%s: server failed\n", scenario);
        return 2;
    }
    printf("%s=%s\n", scenario,
           result == D2K_MEAS_ERR ? "ERROR" :
           result == D2K_MEAS_SILENT ? "SILENT" :
           result == D2K_MEAS_PASS ? "PASS" : "UNPROVEN");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const char *scenario = argv[1];
    if (strcmp(scenario, "pass-any") == 0) {
        return run_network(scenario, (const uint8_t *)"x", 1, 0, NULL);
    }
    if (strcmp(scenario, "serverhello") == 0) {
        static const uint8_t hello[] = {0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00};
        return run_network(scenario, hello, sizeof hello, 0, d2k_accept_serverhello);
    }
    if (strcmp(scenario, "bad-serverhello") == 0) {
        static const uint8_t not_hello[] = {0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00};
        return run_network(scenario, not_hello, sizeof not_hello, 0,
                           d2k_accept_serverhello);
    }
    if (strcmp(scenario, "short-response") == 0) {
        return run_network(scenario, (const uint8_t *)"x", 1, 0,
                           d2k_accept_serverhello);
    }
    if (strcmp(scenario, "closed") == 0) {
        return run_network(scenario, NULL, 0, 0, NULL);
    }
    if (strcmp(scenario, "rst") == 0) {
        return run_network(scenario, NULL, 0, 1, NULL);
    }
    if (strcmp(scenario, "connect-refused") == 0) {
        struct sockaddr_in address;
        int listener = start_listener(&address);
        if (listener < 0) return 2;
        uint16_t port = ntohs(address.sin_port);
        close(listener);
        uint8_t payload[64];
        memset(payload, 0xa5, sizeof payload);
        d2k_hello hello = { payload, sizeof payload, NULL, 0, 0, 0 };
        int marked = 0;
        int result = d2k_meas_once("127.0.0.1", port, hello, NULL, 0, 0, 500, 0,
                                   NULL, &marked);
        printf("%s=%s\n", scenario, result == D2K_MEAS_ERR ? "ERROR" : "PASS");
        return 0;
    }
    if (strcmp(scenario, "invalid-ip") == 0) {
        uint8_t payload[64];
        memset(payload, 0xa5, sizeof payload);
        d2k_hello hello = { payload, sizeof payload, NULL, 0, 0, 0 };
        int marked = 0;
        int result = d2k_meas_once("127.0.0.1%bad", 1, hello, NULL, 0, 0, 500, 0,
                                   NULL, &marked);
        printf("%s=%s\n", scenario, result == D2K_MEAS_ERR ? "ERROR" : "PASS");
        return 0;
    }
    if (strcmp(scenario, "invalid-cuts") == 0) {
        uint8_t payload[64];
        memset(payload, 0xa5, sizeof payload);
        d2k_hello hello = { payload, sizeof payload, NULL, 0, 0, 0 };
        size_t cuts[] = {0};
        int marked = 0;
        int result = d2k_meas_once("127.0.0.1", 1, hello, cuts, 1, 0, 500, 0,
                                   NULL, &marked);
        printf("%s=%s\n", scenario, result == D2K_MEAS_ERR ? "ERROR" : "PASS");
        return 0;
    }
    if (strcmp(scenario, "empty-payload") == 0) {
        d2k_hello hello = { (uint8_t *)"", 0, NULL, 0, 0, 0 };
        int marked = 0;
        int result = d2k_meas_once("127.0.0.1", 1, hello, NULL, 0, 0, 500, 0,
                                   NULL, &marked);
        printf("%s=%s\n", scenario, result == D2K_MEAS_ERR ? "ERROR" : "PASS");
        return 0;
    }
    return 2;
}
