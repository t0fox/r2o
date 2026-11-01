#define _GNU_SOURCE
#include "d2k_detect.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

enum { REPEATS = 3, REQUESTS = REPEATS * 2, HELLO_CAP = 65536 };

static const unsigned char server_hello_done[] = {
    0x16, 0x03, 0x03, 0x00, 0x09,
    0x02, 0x00, 0x00, 0x01, 0xaa,
    0x0e, 0x00, 0x00, 0x00
};
static const unsigned char fatal_alert[] = {
    0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28
};

typedef struct {
    int listener;
    const char *scenario;
    int failed;
    int served;
} server_context;

static int contains(const unsigned char *bytes, size_t length, const char *needle)
{
    size_t needle_len = strlen(needle);
    size_t i;

    if (needle_len > length) return 0;
    for (i = 0; i <= length - needle_len; i++) {
        if (memcmp(bytes + i, needle, needle_len) == 0) return 1;
    }
    return 0;
}

static int read_client_hello(int fd, unsigned char *bytes, size_t capacity)
{
    size_t have = 0, need = 5;

    while (have < need) {
        ssize_t n;
        if (need > capacity) return -1;
        n = recv(fd, bytes + have, need - have, 0);
        if (n <= 0) return -1;
        have += (size_t)n;
        if (have >= 5 && need == 5) {
            need += ((size_t)bytes[3] << 8) | bytes[4];
        }
    }
    return (int)have;
}

static int send_all(int fd, const unsigned char *bytes, size_t length)
{
    size_t sent = 0;
    while (sent < length) {
        ssize_t n = send(fd, bytes + sent, length - sent, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int should_complete(const char *scenario, int target, int attempt)
{
    if (strcmp(scenario, "clear") == 0) return 1;
    if (strcmp(scenario, "blocked") == 0) return !target;
    if (strcmp(scenario, "flaky") == 0) return !target || attempt == 0;
    if (strcmp(scenario, "not_applicable") == 0) return target;
    return -1;
}

static void *serve(void *opaque)
{
    server_context *context = opaque;
    int target_attempts = 0, control_attempts = 0, i;

    for (i = 0; i < REQUESTS; i++) {
        unsigned char hello[HELLO_CAP];
        struct timeval timeout = { 2, 0 };
        struct pollfd pending = { context->listener, POLLIN, 0 };
        int ready = poll(&pending, 1, 3000);
        int client;
        int length, target, attempt, complete;

        if (ready <= 0 || (pending.revents & POLLIN) == 0) {
            context->failed = 1;
            return NULL;
        }
        client = accept(context->listener, NULL, NULL);
        if (client < 0) {
            context->failed = 1;
            return NULL;
        }
        (void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        length = read_client_hello(client, hello, sizeof(hello));
        if (length < 0) {
            context->failed = 1;
            close(client);
            return NULL;
        }
        context->served++;
        target = contains(hello, (size_t)length, "youtube.com");
        attempt = target ? target_attempts++ : control_attempts++;
        complete = should_complete(context->scenario, target, attempt);
        if (complete < 0 ||
            send_all(client,
                     complete ? server_hello_done : fatal_alert,
                     complete ? sizeof(server_hello_done) : sizeof(fatal_alert)) != 0) {
            context->failed = 1;
            close(client);
            return NULL;
        }
        close(client);
    }
    return NULL;
}

static int run_case(const char *scenario, d2k_resp_verdict expected,
                    int expected_target, int expected_control)
{
    struct sockaddr_in address;
    socklen_t address_length = sizeof(address);
    struct timeval timeout = { 2, 0 };
    d2k_opts options;
    d2k_resp_result result;
    server_context context;
    pthread_t server;
    void *server_result = NULL;
    char port[6];
    int listener = socket(AF_INET, SOCK_STREAM, 0);

    if (listener < 0) return 2;
    (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &timeout, sizeof(timeout));
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, REQUESTS) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &address_length) != 0) {
        perror("TLS response fixture bind/listen");
        close(listener);
        return 2;
    }
    (void)snprintf(port, sizeof(port), "%u", (unsigned)ntohs(address.sin_port));
    context.listener = listener;
    context.scenario = scenario;
    context.failed = 0;
    context.served = 0;
    if (pthread_create(&server, NULL, serve, &context) != 0) {
        perror("TLS response fixture pthread_create");
        close(listener);
        return 2;
    }

    d2k_opts_defaults(&options);
    options.repeats = REPEATS;
    options.timeout_ms = 500;
    d2k_probe_response("127.0.0.1", port, "youtube.com", &options, &result);

    (void)pthread_join(server, &server_result);
    close(listener);
    if (server_result != NULL || context.failed || context.served != REQUESTS) {
        fprintf(stderr, "TLS response fixture server failed for %s\n", scenario);
        return 2;
    }
    if (result.verdict != expected || result.target != expected_target ||
        result.control != expected_control) {
        fprintf(stderr, "%s expected %s %d/%d; got %s %d/%d\n",
                scenario, d2k_resp_name(expected), expected_target, expected_control,
                d2k_resp_name(result.verdict), result.target, result.control);
        return 1;
    }
    printf("%s verdict=%s target=%d control=%d probes=%d\n",
           scenario, d2k_resp_name(result.verdict), result.target, result.control,
           context.served);
    return 0;
}

int main(void)
{
    int failed = 0;
    failed |= run_case("clear", D2K_RESP_CLEAR, 3, 3);
    failed |= run_case("blocked", D2K_RESP_BLOCKED, 0, 3);
    failed |= run_case("flaky", D2K_RESP_FLAKY, 1, 3);
    failed |= run_case("not_applicable", D2K_RESP_NOT_APPLICABLE, 3, 0);
    return failed;
}
