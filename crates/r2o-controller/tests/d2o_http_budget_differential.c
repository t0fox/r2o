/* C-оракул budget_tcp (core/verify.c, current main 7a5fab9).
 *
 * budget_tcp статическая: verify.c включается как TU, ненужные функции
 * отбрасываются --gc-sections. read/write/packets/peer_spoke подменяются
 * детерминированными заглушками.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "verify.c"

typedef struct {
    const char *bytes;
    size_t len;
    size_t offset;
    int timeout;
} mock_reader;

static long mock_read(void *opaque, uint8_t *out, size_t cap, int wait_ms,
                      char *err, size_t errcap)
{
    (void)wait_ms;
    mock_reader *reader = opaque;
    if (reader->timeout) {
        struct timespec delay = {0, 30 * 1000 * 1000};
        nanosleep(&delay, NULL);
        snprintf(err, errcap, "HTTP read timeout");
        return -1;
    }
    if (reader->offset == reader->len) {
        snprintf(err, errcap, "HTTP read timeout");
        return -1;
    }
    size_t count = reader->len - reader->offset;
    if (count > cap) count = cap;
    memcpy(out, reader->bytes + reader->offset, count);
    reader->offset += count;
    return (long)count;
}

static int mock_write(void *opaque, const uint8_t *buf, size_t len,
                      char *err, size_t errcap)
{
    (void)opaque;
    (void)buf;
    (void)len;
    (void)err;
    (void)errcap;
    return 0;
}

typedef struct {
    long values[8];
    size_t count;
    size_t index;
    int peer_spoke;
} mock_io;

static long mock_packets(void *opaque)
{
    mock_io *io = opaque;
    if (io->index < io->count) { return io->values[io->index++]; }
    return io->values[io->count - 1];
}

static int mock_peer_spoke(void *opaque)
{
    return ((mock_io *)opaque)->peer_spoke;
}

static void run_case(const char *name, const char *response, size_t response_len,
                     long packets0, long packets1, int conn_close, int timeout,
                     int peer_spoke, unsigned budget, int deadline_ms)
{
    static const char request[] = "GET / HTTP/1.1\r\n\r\n";
    mock_reader reader = {.bytes = response, .len = response_len, .timeout = timeout};
    mock_io io = {
        .values = {packets0, packets1},
        .count = 2,
        .index = 0,
        .peer_spoke = peer_spoke,
    };
    budget_io hooks = {
        .packets = mock_packets,
        .peer_spoke = mock_peer_spoke,
        .ctx = &io,
    };
    d2k_ver_result result;
    memset(&result, 0, sizeof result);
    budget_tcp(mock_read, mock_write, &reader, &hooks, request, sizeof request - 1,
               deadline_ms, budget, conn_close, &result);
    printf("case=%s budget=%d\n", name, (int)result.budget);
}

int main(void)
{
    static const char ok[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
    static const char close[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    static const char partial[] = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab";

    run_case("passed", ok, sizeof ok - 1, 4, 12, 0, 0, 0, 5, 80);
    run_case("conn-close", close, sizeof close - 1, 4, 4, 0, 0, 0, 5, 80);
    run_case("not-growing", ok, sizeof ok - 1, 4, 4, 0, 0, 0, 5, 80);
    run_case("peer-spoke", partial, sizeof partial - 1, 4, 4, 0, 0, 1, 5, 80);
    run_case("silent", partial, sizeof partial - 1, 4, 4, 0, 1, 0, 5, 20);
    return 0;
}
