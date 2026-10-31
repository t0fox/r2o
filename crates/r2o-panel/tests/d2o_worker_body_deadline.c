#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    int fd;
    atomic_bool *done;
} sender_args;

static long long monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int write_all(int fd, const char *data, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        ssize_t count = write(fd, data + sent, length - sent);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        sent += (size_t)count;
    }
    return 0;
}

static void *send_partial_body(void *opaque) {
    sender_args *args = opaque;
    struct timespec delay = {.tv_sec = 3, .tv_nsec = 0};
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
    (void)write_all(args->fd, "a\"", sizeof "a\"" - 1);
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
    while (!atomic_load_explicit(args->done, memory_order_acquire))
        (void)nanosleep(&pause, NULL);
    return NULL;
}

int main(void) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 2;
    static const char first[] =
        "POST /api/telegram/workers HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Origin: http://localhost\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 8\r\n\r\n{\"";
    if (write_all(sockets[0], first, sizeof first - 1) != 0) return 2;

    atomic_bool done = ATOMIC_VAR_INIT(false);
    sender_args args = {.fd = sockets[0], .done = &done};
    pthread_t sender;
    if (pthread_create(&sender, NULL, send_partial_body, &args) != 0) return 2;

    const long long started = monotonic_ms();
    d2k_panel_config config = {.control_enabled = true, .config_path = "/dev/null"};
    (void)d2k_panel_handle_fd(sockets[1], &config);
    const long long elapsed = monotonic_ms() - started;
    atomic_store_explicit(&done, true, memory_order_release);
    (void)pthread_join(sender, NULL);
    close(sockets[1]);

    char response[1024];
    ssize_t count = read(sockets[0], response, sizeof response - 1);
    close(sockets[0]);
    if (count <= 0) return 1;
    response[count] = '\0';
    unsigned int status;
    if (sscanf(response, "HTTP/1.1 %u", &status) != 1) return 1;
    printf("HTTP/1.1 %u\n%lld\n", status, elapsed);
    return 0;
}
