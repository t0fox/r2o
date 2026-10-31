#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "server.c"

typedef struct {
    int listener;
    const char *snapshot_path;
    int failed;
} stats_server;

static int stats_write_all(int fd, const char *data, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        ssize_t count = write(fd, data + sent, length - sent);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        sent += (size_t)count;
    }
    return 0;
}

static void *serve_snapshot(void *opaque) {
    stats_server *server = opaque;
    int client = accept(server->listener, NULL, NULL);
    if (client < 0) {
        server->failed = 1;
        return NULL;
    }
    FILE *snapshot = fopen(server->snapshot_path, "rb");
    if (!snapshot) {
        server->failed = 1;
        close(client);
        return NULL;
    }
    char bytes[4096];
    for (;;) {
        size_t count = fread(bytes, 1, sizeof bytes, snapshot);
        if (count && stats_write_all(client, bytes, count) != 0) server->failed = 1;
        if (count < sizeof bytes) {
            if (ferror(snapshot)) server->failed = 1;
            break;
        }
    }
    if (fclose(snapshot) != 0) server->failed = 1;
    close(client);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3 || strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 2;
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0) return 2;
    struct sockaddr_un address;
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, argv[1], strlen(argv[1]) + 1);
    unlink(argv[1]);
    if (bind(listener, (struct sockaddr *)&address, sizeof address) != 0 || listen(listener, 1) != 0) {
        close(listener);
        return 2;
    }

    stats_server server = {.listener = listener, .snapshot_path = argv[2], .failed = 0};
    pthread_t thread;
    if (pthread_create(&thread, NULL, serve_snapshot, &server) != 0) {
        close(listener);
        unlink(argv[1]);
        return 2;
    }

    d2k_panel_config config = {.telegram_stats_path = argv[1]};
    char result[TELEGRAM_STATS_MAX];
    telegram_stats_value(&config, result);
    close(listener);
    pthread_join(thread, NULL);
    unlink(argv[1]);
    if (server.failed) return 5;
    puts(result);
    return 0;
}
