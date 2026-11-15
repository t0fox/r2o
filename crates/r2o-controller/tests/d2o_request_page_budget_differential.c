/* C oracle request_page_budget: verify.c + mock read/write/budget_io. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "verify.c"

typedef struct {
    const char *parts[4];
    size_t lengths[4];
    int count;
    int index;
    size_t offset;
    int timeout;
    int eof;
} mock_stream;

static long mock_read(void *opaque, uint8_t *out, size_t cap, int wait_ms,
                      char *err, size_t errcap)
{
    (void)wait_ms;
    mock_stream *stream = opaque;
    if (stream->timeout) {
        snprintf(err, errcap, "HTTP read timeout");
        return -1;
    }
    while (stream->index < stream->count && stream->offset >= stream->lengths[stream->index]) {
        stream->index++;
        stream->offset = 0;
    }
    if (stream->index >= stream->count) {
        if (stream->eof) return 0;
        snprintf(err, errcap, "HTTP read timeout");
        return -1;
    }
    size_t n = stream->lengths[stream->index] - stream->offset;
    if (n > cap) n = cap;
    memcpy(out, stream->parts[stream->index] + stream->offset, n);
    stream->offset += n;
    return (long)n;
}

static int mock_write(void *opaque, const uint8_t *buf, size_t len,
                      char *err, size_t errcap)
{
    (void)opaque; (void)buf; (void)len; (void)err; (void)errcap;
    return 0;
}

typedef struct { long values[8]; size_t count; size_t index; int peer_spoke; } mock_io;

static long mock_packets(void *opaque)
{
    mock_io *io = opaque;
    if (io->count == 0) return 0;
    if (io->index < io->count) return io->values[io->index++];
    return io->values[io->count - 1];
}

static int mock_peer_spoke(void *opaque) { return ((mock_io *)opaque)->peer_spoke; }

static void run_case(const char *name, const char **parts, const size_t *lengths,
                     int count, unsigned budget, long p0, long p1,
                     int timeout, int eof, int peer_spoke)
{
    mock_stream stream;
    memset(&stream, 0, sizeof stream);
    stream.count = count;
    for (int i = 0; i < count; i++) {
        stream.parts[i] = parts[i];
        stream.lengths[i] = lengths[i];
    }
    stream.timeout = timeout;
    stream.eof = eof;
    mock_io io = { .count = 2, .index = 0, .peer_spoke = peer_spoke };
    io.values[0] = p0;
    io.values[1] = p1;
    budget_io hooks = { .packets = mock_packets, .peer_spoke = mock_peer_spoke, .ctx = &io };
    d2k_ver_result result;
    char err[160] = "";
    memset(&result, 0, sizeof result);
    request_page_budget(mock_read, mock_write, &stream, "budget.example", 0, "/",
                        80, 0, &hooks, budget, &result, err, sizeof err);
    printf("request|%s|level=%d|status=%d|complete=%d|budget=%d|location=%s|reason=%s\n",
           name, (int)result.level, result.status, result.body_complete,
           (int)result.budget, result.location, result.reason);
}

int main(void)
{
    static const char ok[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
    static const char redirect_same[] =
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n";
    static const char redirect_external[] =
        "HTTP/1.1 302 Found\r\nLocation: https://other.example/x\r\nContent-Length: 0\r\n\r\n";
    static const char challenge[] =
        "HTTP/1.1 403 Forbidden\r\ncf-mitigated: challenge\r\nContent-Length: 0\r\n\r\n";
    static const char denied[] = "HTTP/1.1 451 Unavailable\r\nContent-Length: 0\r\n\r\n";
    static const char short_body[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab";
    static const char close_body[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

    {
        const char *parts[] = {redirect_same, ok};
        size_t lengths[] = {sizeof redirect_same - 1, sizeof ok - 1};
        run_case("same-origin", parts, lengths, 2, 0, 0, 0, 0, 0, 0);
    }
    {
        const char *parts[] = {redirect_external};
        size_t lengths[] = {sizeof redirect_external - 1};
        run_case("external-redirect", parts, lengths, 1, 0, 0, 0, 0, 0, 0);
    }
    {
        const char *parts[] = {challenge};
        size_t lengths[] = {sizeof challenge - 1};
        run_case("challenge", parts, lengths, 1, 0, 0, 0, 0, 0, 0);
    }
    {
        const char *parts[] = {denied};
        size_t lengths[] = {sizeof denied - 1};
        run_case("denied-451", parts, lengths, 1, 0, 0, 0, 0, 0, 0);
    }
    {
        const char *parts[] = {ok};
        size_t lengths[] = {sizeof ok - 1};
        run_case("complete-2xx", parts, lengths, 1, 0, 0, 0, 0, 0, 0);
    }
    {
        const char *parts[] = {short_body};
        size_t lengths[] = {sizeof short_body - 1};
        run_case("short-body", parts, lengths, 1, 0, 0, 0, 0, 1, 0);
    }
    {
        const char *parts[] = {ok, ok, ok};
        size_t lengths[] = {sizeof ok - 1, sizeof ok - 1, sizeof ok - 1};
        run_case("keepalive-pass", parts, lengths, 3, 3, 2, 6, 0, 0, 0);
    }
    {
        const char *parts[] = {close_body};
        size_t lengths[] = {sizeof close_body - 1};
        run_case("conn-close", parts, lengths, 1, 3, 2, 2, 0, 0, 0);
    }
    {
        const char *parts[] = {short_body};
        size_t lengths[] = {sizeof short_body - 1};
        run_case("silence", parts, lengths, 1, 3, 2, 2, 1, 0, 0);
    }
    return 0;
}
