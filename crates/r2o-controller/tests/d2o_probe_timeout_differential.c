#define _POSIX_C_SOURCE 200809L

#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "d2k_meas.h"

static int listener;

static void *answer_late(void *unused) {
    (void)unused;
    int client = accept(listener, NULL, NULL);
    if (client < 0) return NULL;
    char request[4];
    if (read(client, request, sizeof request) == (ssize_t)sizeof request) {
        const struct timespec delay = {.tv_sec = 5, .tv_nsec = 500000000};
        (void)nanosleep(&delay, NULL);
        (void)write(client, "x", 1);
    }
    close(client);
    return NULL;
}

int main(void) {
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return 2;
    const struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    if (bind(listener, (const struct sockaddr *)&address, sizeof address) != 0 ||
        listen(listener, 1) != 0) {
        perror("listen");
        return 2;
    }
    struct sockaddr_in bound;
    socklen_t bound_len = sizeof bound;
    if (getsockname(listener, (struct sockaddr *)&bound, &bound_len) != 0) return 2;

    pthread_t server;
    if (pthread_create(&server, NULL, answer_late, NULL) != 0) return 2;
    const uint8_t request[] = {'P', 'I', 'N', 'G'};
    const d2k_hello hello = {request, sizeof request, NULL, 0, 0, 0};
    const d2k_tally result = d2k_meas("127.0.0.1", ntohs(bound.sin_port), hello,
                                      NULL, 0, 0, 7000, 0,
                                      d2k_accept_any, 1);
    (void)pthread_join(server, NULL);
    close(listener);

    const int rejected = result.pass == 0 && result.fail == 1 && result.err == 0;
    printf("timeout_verdict=%s\n", rejected ? "rejected" : "other");
    return rejected ? 0 : 1;
}
