#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_detect.h"

static const unsigned char server_hello_done[] = {
    0x16, 0x03, 0x03, 0x00, 0x09,
    0x02, 0x00, 0x00, 0x01, 0xaa,
    0x0e, 0x00, 0x00, 0x00
};

static void *serve(void *opaque)
{
    int listener = *(int *)opaque;
    int index;

    for (index = 0; index < 2; index++) {
        struct sockaddr_in local;
        socklen_t length = sizeof(local);
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            return (void *)1;
        }
        if (getsockname(client, (struct sockaddr *)&local, &length) != 0) {
            close(client);
            return (void *)1;
        }
        if (ntohl(local.sin_addr.s_addr) == 0x7f000002U &&
            write(client, server_hello_done, sizeof(server_hello_done)) !=
                (ssize_t)sizeof(server_hello_done)) {
            close(client);
            return (void *)1;
        }
        close(client);
    }
    return NULL;
}

int main(void)
{
    struct sockaddr_in address;
    socklen_t address_length = sizeof(address);
    d2k_opts options;
    d2k_resp_result result;
    pthread_t server;
    void *server_result = NULL;
    char port[6];
    int listener = socket(AF_INET, SOCK_STREAM, 0);

    if (listener < 0) {
        perror("socket");
        return 2;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 4) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &address_length) != 0) {
        perror("bind/listen/getsockname");
        close(listener);
        return 2;
    }
    (void)snprintf(port, sizeof(port), "%u", (unsigned)ntohs(address.sin_port));
    if (pthread_create(&server, NULL, serve, &listener) != 0) {
        perror("pthread_create");
        close(listener);
        return 2;
    }

    memset(&options, 0, sizeof(options));
    options.repeats = 1;
    options.timeout_ms = 250;
    d2k_probe_response("r2o-response-rotate.test", port, "rotate.example",
                       &options, &result);
    (void)pthread_join(server, &server_result);
    close(listener);
    if (server_result != NULL) {
        fprintf(stderr, "TLS response fixture server failed\n");
        return 2;
    }
    printf("verdict=%s target=%d control=%d\n",
           d2k_resp_name(result.verdict), result.target, result.control);
    return 0;
}
