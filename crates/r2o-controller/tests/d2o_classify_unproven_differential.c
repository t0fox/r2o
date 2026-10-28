#define _DEFAULT_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
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
    const d2k_trigger *trigger;
    const d2k_trigger *control;
    int mismatch;
    int served;
} server_args;

static void *serve(void *opaque)
{
    server_args *args = opaque;
    for (int i = 0; i < 3; i++) {
        const d2k_trigger *expected = i == 2 ? args->control : args->trigger;
        int client = accept(args->listener, NULL, NULL);
        uint8_t bytes[D2K_TRIGGER_MAX];
        size_t got = 0;
        if (client < 0) {
            args->mismatch = 1;
            return NULL;
        }
        struct timeval receive_timeout = { .tv_sec = 3 };
        if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                       &receive_timeout, sizeof(receive_timeout)) != 0) {
            args->mismatch = 1;
            close(client);
            return NULL;
        }
        while (got < expected->len) {
            ssize_t n = recv(client, bytes + got, expected->len - got, 0);
            if (n <= 0) break;
            got += (size_t)n;
        }
        if (got != expected->len || memcmp(bytes, expected->payload, expected->len) != 0)
            args->mismatch = 1;
        const char *reply = i == 2 ? "OK" : "NO";
        if (send(client, reply, 2, 0) == 2) args->served++;
        close(client);
    }
    return NULL;
}

int main(void)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = 0 };
    socklen_t address_len = sizeof(address);
    int reuse = 1;
    if (listener < 0) return 2;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 4) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &address_len) != 0) {
        perror("fixture listener");
        close(listener);
        return 2;
    }

    d2k_trigger trigger = {0};
    memcpy(trigger.name, "test", sizeof("test"));
    trigger.payload[0] = 0x01;
    trigger.payload[1] = 0x02;
    trigger.len = 2;
    trigger.accept = D2K_ACCEPT_SERVERHELLO;

    d2k_opts options = {0};
    options.repeats = 1;
    options.timeout_ms = 900;
    options.write_gap_ms = 1;
    options.allow_loopback = 1;
    options.no_raw = 1;
    memcpy(options.control.name, "control", sizeof("control"));
    memcpy(options.control.payload, "CONTROL", sizeof("CONTROL") - 1);
    options.control.len = sizeof("CONTROL") - 1;
    options.control.accept = D2K_ACCEPT_ANY;

    server_args server = { .listener = listener, .trigger = &trigger,
                           .control = &options.control };
    pthread_t thread;
    if (pthread_create(&thread, NULL, serve, &server) != 0) {
        close(listener);
        return 2;
    }

    char target[64];
    snprintf(target, sizeof(target), "127.0.0.1:%u", ntohs(address.sin_port));
    d2k_result result;
    d2k_classify_run(target, &trigger, &options, &result);
    pthread_join(thread, NULL);
    close(listener);

    printf("verdict=%s\nprobes=%d\n", d2k_verdict_name(result.verdict), result.probes);
    return result.verdict == D2K_DV_OPAQUE && result.probes == 3 &&
                   server.served == 3 && !server.mismatch && options.no_raw &&
                   options.allow_loopback ? 0 : 1;
}
