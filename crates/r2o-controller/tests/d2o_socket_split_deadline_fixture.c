#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_detect.h"

int d2k_raw_supported(void)
{
    return 0;
}

int d2k_raw_probe_poison_family(const uint8_t *ip, uint8_t family, uint16_t port,
                                const d2k_trigger *trigger, const d2k_poison *poison,
                                int timeout_ms, uint32_t mark, const d2k_detect_stop *cancel,
                                char *error, size_t error_len)
{
    (void)ip;
    (void)family;
    (void)port;
    (void)trigger;
    (void)poison;
    (void)timeout_ms;
    (void)mark;
    (void)cancel;
    (void)error;
    (void)error_len;
    return -1;
}

#include "classify.c"

typedef struct {
    int listener;
    uint8_t bytes[16];
    size_t length;
} server_state;

static void *receive_request(void *opaque)
{
    server_state *server = opaque;
    int client = accept(server->listener, NULL, NULL);
    if (client < 0) return NULL;
    for (;;) {
        ssize_t received = recv(client, server->bytes + server->length,
                                sizeof server->bytes - server->length, 0);
        if (received <= 0) break;
        server->length += (size_t)received;
        if (server->length == sizeof server->bytes) break;
    }
    close(client);
    return NULL;
}

int main(void)
{
    server_state server = {0};
    struct sockaddr_in address = {0};
    socklen_t address_len = sizeof address;
    pthread_t thread;
    d2k_opts options = {0};
    d2k_trigger trigger = {0};
    const int cuts[] = {2};
    char port[16], error[160] = "", raw_peer[64] = "";

    server.listener = socket(AF_INET, SOCK_STREAM, 0);
    if (server.listener < 0) return 2;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(server.listener, (struct sockaddr *)&address, sizeof address) != 0 ||
        listen(server.listener, 1) != 0 ||
        getsockname(server.listener, (struct sockaddr *)&address, &address_len) != 0) {
        close(server.listener);
        return 2;
    }
    snprintf(port, sizeof port, "%u", (unsigned)ntohs(address.sin_port));
    if (pthread_create(&thread, NULL, receive_request, &server) != 0) {
        close(server.listener);
        return 2;
    }

    memcpy(trigger.payload, "ABCD", 4);
    trigger.len = 4;
    options.timeout_ms = 100;
    options.no_raw = 1;
    int rc = once_probe("127.0.0.1", port, &trigger, &options, cuts, 1,
                        250, error, sizeof error, raw_peer, sizeof raw_peer);
    pthread_join(thread, NULL);
    close(server.listener);
    if (rc != -1 || strcmp(error, "context deadline exceeded") != 0 ||
        server.length != 2 || memcmp(server.bytes, "AB", 2) != 0) {
        fprintf(stderr, "C split deadline mismatch: rc=%d error=%s bytes=%zu\n",
                rc, error, server.length);
        return 1;
    }
    printf("SOCKET_SPLIT_DEADLINE result=deadline bytes=%02x%02x\n",
           server.bytes[0], server.bytes[1]);
    return 0;
}
