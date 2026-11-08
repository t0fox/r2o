#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int listener;

static void *serve_two(void *unused) {
    (void)unused;
    d2k_panel_config config = {0};
    for (int index = 0; index < 2; index++) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) return NULL;
        (void)d2k_panel_handle_fd(client, &config);
        close(client);
    }
    return NULL;
}

int main(void) {
    (void)d2k_panel_ignore_sigpipe();
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return 2;
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&address, sizeof address) != 0) return 2;
    if (listen(listener, 2) != 0) return 2;
    socklen_t length = sizeof address;
    if (getsockname(listener, (struct sockaddr *)&address, &length) != 0) return 2;

    pthread_t thread;
    if (pthread_create(&thread, NULL, serve_two, NULL) != 0) return 2;

    int first = socket(AF_INET, SOCK_STREAM, 0);
    if (first < 0) return 2;
    if (connect(first, (struct sockaddr *)&address, sizeof address) != 0) return 2;
    (void)write(first, "GET / HTTP/1.1\r\nHost: x\r\n", 27);
    close(first);

    int second = socket(AF_INET, SOCK_STREAM, 0);
    if (second < 0) return 2;
    if (connect(second, (struct sockaddr *)&address, sizeof address) != 0) return 2;
    const char request[] = "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n";
    if (write(second, request, sizeof request - 1) != (ssize_t)(sizeof request - 1)) return 2;
    if (shutdown(second, SHUT_WR) != 0) return 2;
    char response[256];
    ssize_t count = read(second, response, sizeof response - 1);
    close(second);
    if (count <= 0) return 1;
    response[count] = '\0';
    unsigned int status;
    if (sscanf(response, "HTTP/1.1 %u", &status) != 1) return 1;
    printf("second=%u\n", status);

    pthread_join(thread, NULL);
    close(listener);
    return 0;
}
