/* C/Rust differential: d2k_ct_query_fd и d2k_ct_probe_fd на socketpair.
 *
 * Запросы ctnetlink не требуют привилегий, если подменить ядро готовыми
 * ответами: C `send`/`recv` работают на любом сокете. Проверяются коды
 * -1/0/1/2, чужие seq, ENOENT/EOPNOTSUPP и молчание. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_ctq.h"

static void be64(uint8_t out[8], uint64_t value) {
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(value >> (56 - 8 * i));
}

static size_t push_attr(uint8_t *body, size_t used, uint16_t type,
                        const uint8_t *value, size_t length) {
    uint16_t total = (uint16_t)(4 + length);
    memcpy(body + used, &total, 2);
    memcpy(body + used + 2, &type, 2);
    memcpy(body + used + 4, value, length);
    size_t aligned = (used + total + 3u) & ~(size_t)3u;
    for (size_t i = used + total; i < aligned; i++) body[i] = 0;
    return aligned;
}

static size_t counters_message(uint8_t *out, uint32_t seq, uint64_t orig,
                               uint64_t reply, int with_counters) {
    uint8_t body[128];
    size_t used = 4;
    memset(body, 0, sizeof body);
    body[0] = 2;
    if (with_counters) {
        uint8_t nested[16];
        uint8_t value[8];
        size_t nested_used = 0;
        be64(value, orig);
        nested_used = push_attr(nested, nested_used, 1, value, 8);
        used = push_attr(body, used, 9 | 0x8000, nested, nested_used);
        nested_used = 0;
        be64(value, reply);
        nested_used = push_attr(nested, nested_used, 1, value, 8);
        used = push_attr(body, used, 10 | 0x8000, nested, nested_used);
    }
    memset(out, 0, 16 + used);
    uint32_t length = (uint32_t)(16 + used);
    memcpy(out, &length, 4);
    uint16_t type = 0x0100;
    memcpy(out + 4, &type, 2);
    memcpy(out + 8, &seq, 4);
    memcpy(out + 16, body, used);
    return length;
}

static size_t error_message(uint8_t *out, uint32_t seq, int32_t errno_value) {
    uint32_t length = 20;
    memset(out, 0, length);
    memcpy(out, &length, 4);
    uint16_t type = 2;
    memcpy(out + 4, &type, 2);
    memcpy(out + 8, &seq, 4);
    memcpy(out + 16, &errno_value, 4);
    return length;
}

static void send_datagram(int fd, const uint8_t *bytes, size_t length) {
    if (send(fd, bytes, length, 0) != (ssize_t)length) {
        fprintf(stderr, "socketpair send: %s\n", strerror(errno));
        _exit(2);
    }
}

static void pair(int fds[2]) {
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) {
        perror("socketpair");
        _exit(2);
    }
}

static void query_case(const char *name, const uint8_t *first, size_t first_len,
                       const uint8_t *second, size_t second_len) {
    int fds[2];
    pair(fds);
    send_datagram(fds[1], first, first_len);
    if (second) {
        send_datagram(fds[1], second, second_len);
    }
    d2k_ct_tuple tuple;
    memset(&tuple, 0, sizeof tuple);
    tuple.family = 4;
    tuple.proto = 17;
    uint64_t orig = 0;
    uint64_t reply = 0;
    int rc = d2k_ct_query_fd(fds[0], 7, &tuple, &orig, &reply);
    printf("query %s rc=%d", name, rc);
    if (rc == 0) {
        printf(" orig=%llu reply=%llu", (unsigned long long)orig,
               (unsigned long long)reply);
    }
    printf("\n");
    close(fds[0]);
    close(fds[1]);
}

static void probe_case(const char *name, const uint8_t *first, size_t first_len,
                       const uint8_t *second, size_t second_len) {
    int fds[2];
    pair(fds);
    if (first) {
        send_datagram(fds[1], first, first_len);
    }
    if (second) {
        send_datagram(fds[1], second, second_len);
    }
    int rc = d2k_ct_probe_fd(fds[0], 7, 50);
    printf("probe %s rc=%d\n", name, rc);
    close(fds[0]);
    close(fds[1]);
}

int main(void) {
    uint8_t first[256];
    uint8_t second[256];
    size_t first_len;
    size_t second_len;

    first_len = counters_message(first, 7, 22, 25, 1);
    query_case("valid", first, first_len, NULL, 0);
    first_len = counters_message(first, 7, 0, 0, 0);
    query_case("no_counters", first, first_len, NULL, 0);
    first_len = error_message(first, 7, -ENOENT);
    query_case("reply", first, first_len, NULL, 0);
    first_len = error_message(first, 7, 0);
    query_case("ack", first, first_len, NULL, 0);
    first_len = counters_message(first, 99, 1, 1, 1);
    second_len = counters_message(second, 7, 22, 25, 1);
    query_case("wrong_seq_then_valid", first, first_len, second, second_len);

    first_len = error_message(first, 7, -ENOENT);
    probe_case("enoent", first, first_len, NULL, 0);
    first_len = counters_message(first, 7, 22, 25, 1);
    probe_case("ok", first, first_len, NULL, 0);
    first_len = error_message(first, 7, -EOPNOTSUPP);
    probe_case("unsupported", first, first_len, NULL, 0);
    probe_case("silent", NULL, 0, NULL, 0);
    first_len = counters_message(first, 99, 1, 1, 1);
    second_len = error_message(second, 7, -ENOENT);
    probe_case("foreign_then_ok", first, first_len, second, second_len);
    return 0;
}
