#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "d2k_detect.h"

static uint32_t observed_mark;
int fixture_setsockopt(int fd, int level, int option, const void *value, socklen_t length);
#define setsockopt fixture_setsockopt
#include "classify.c"
#undef setsockopt

int fixture_setsockopt(int fd, int level, int option, const void *value, socklen_t length)
{
#ifdef SO_MARK
    if (level == SOL_SOCKET && option == SO_MARK) {
        if (length != sizeof(observed_mark)) return -1;
        memcpy(&observed_mark, value, sizeof(observed_mark));
        return 0;
    }
#endif
    return setsockopt(fd, level, option, value, length);
}

typedef struct {
    int listener;
    const uint8_t *payload;
    size_t payload_len;
    int repeats;
    int accepted;
    int mismatch;
} server_args;

static void *serve(void *opaque)
{
    server_args *args = opaque;
    for (int i = 0; i < args->repeats; i++) {
        int client = accept(args->listener, NULL, NULL);
        uint8_t bytes[2048];
        size_t got = 0;
        if (client < 0) { args->mismatch = 1; return NULL; }
        struct timeval receive_timeout = { .tv_sec = 5 };
        if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                       &receive_timeout, sizeof(receive_timeout)) != 0) {
            args->mismatch = 1;
            close(client);
            return NULL;
        }
        while (got < args->payload_len) {
            ssize_t n = recv(client, bytes + got, sizeof(bytes) - got, 0);
            if (n <= 0) break;
            got += (size_t)n;
        }
        if (got != args->payload_len || memcmp(bytes, args->payload, args->payload_len) != 0) {
            args->mismatch = 1;
        }
        if (send(client, "OK", 2, 0) == 2) args->accepted++;
        close(client);
    }
    return NULL;
}

static int read_fixture(const char *path, char *target, size_t target_cap,
                        uint8_t *payload, size_t payload_cap, size_t *payload_len,
                        int *repeats, int *timeout_ms, int *write_gap_ms,
                        int *long_gap_ms, int *allow_loopback, uint32_t *mark)
{
    FILE *file = fopen(path, "r");
    char line[4096], hex[2048] = "", loopback[8] = "";
    if (!file) return -1;
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "target=%159s", target) == 1) continue;
        if (sscanf(line, "payload_hex=%2047s", hex) == 1) continue;
        (void)sscanf(line, "repeats=%d", repeats);
        (void)sscanf(line, "timeout_ms=%d", timeout_ms);
        (void)sscanf(line, "write_gap_ms=%d", write_gap_ms);
        (void)sscanf(line, "long_gap_ms=%d", long_gap_ms);
        if (sscanf(line, "allow_loopback=%7s", loopback) == 1)
            *allow_loopback = strcmp(loopback, "true") == 0;
        (void)sscanf(line, "mark=%u", mark);
    }
    fclose(file);
    if (strlen(target) >= target_cap) return -1;
    size_t hex_len = strlen(hex);
    if (!hex_len || (hex_len & 1) || hex_len / 2 > payload_cap) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned value;
        if (sscanf(hex + 2 * i, "%2x", &value) != 1) return -1;
        payload[i] = (uint8_t)value;
    }
    *payload_len = hex_len / 2;
    return target[0] ? 0 : -1;
}

int main(int argc, char **argv)
{
    char target[160] = "";
    uint8_t payload[1024];
    size_t payload_len = 0;
    int repeats = 0, timeout_ms = 0, write_gap_ms = 0, long_gap_ms = 0;
    int allow_loopback = 0;
    uint32_t mark = 0;
    if (argc != 2 || read_fixture(argv[1], target, sizeof(target), payload,
                                  sizeof(payload), &payload_len, &repeats,
                                  &timeout_ms, &write_gap_ms, &long_gap_ms,
                                  &allow_loopback, &mark) != 0) {
        fprintf(stderr, "invalid fixture\n");
        return 2;
    }

    char host[128];
    unsigned port;
    if (sscanf(target, "%127[^:]:%u", host, &port) != 2 || strcmp(host, "127.0.0.1"))
        return 2;
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
    struct timeval accept_timeout = { .tv_sec = 5 };
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int reuse = 1;
    if (listener < 0 || setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO,
                   &accept_timeout, sizeof(accept_timeout)) != 0 ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(listener, 8) != 0) {
        perror("fixture listener");
        return 2;
    }

    server_args server = { .listener = listener, .payload = payload,
                           .payload_len = payload_len, .repeats = repeats };
    pthread_t thread;
    if (pthread_create(&thread, NULL, serve, &server) != 0) return 2;

    d2k_trigger trigger = {0};
    memcpy(trigger.name, "test", sizeof("test"));
    memcpy(trigger.payload, payload, payload_len);
    trigger.len = payload_len;
    trigger.accept = D2K_ACCEPT_ANY;
    d2k_opts options = {0};
    options.repeats = repeats;
    options.timeout_ms = timeout_ms;
    options.write_gap_ms = write_gap_ms;
    options.long_gap_ms = long_gap_ms;
    options.allow_loopback = allow_loopback;
    options.mark = mark;
    options.no_raw = 1;

    d2k_result result;
    d2k_classify_run(target, &trigger, &options, &result);
    pthread_join(thread, NULL);
    close(listener);

    printf("%s probes=%d repeats=%d mark=%u target=%s\n",
           d2k_verdict_name(result.verdict), result.probes, result.repeats,
           observed_mark, result.target);
    return result.verdict == D2K_DV_CLEAR && result.probes == repeats &&
                   result.repeats == repeats && observed_mark == mark &&
                   server.accepted == repeats && !server.mismatch ? 0 : 1;
}
