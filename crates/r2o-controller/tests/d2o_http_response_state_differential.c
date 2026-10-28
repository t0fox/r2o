#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_httpsearch.h"
#include "d2k_verify.h"

typedef struct {
    const uint8_t *input;
    size_t input_len;
    size_t offset;
    uint8_t received[8192];
    size_t received_len;
} fixture_reader;

static long fixture_read(void *opaque, uint8_t *out, size_t capacity, int wait_ms,
                         char *err, size_t errcap)
{
    fixture_reader *reader = opaque;
    (void)wait_ms;
    if (reader->offset == reader->input_len) {
        snprintf(err, errcap, "HTTP read timeout");
        return -1;
    }
    size_t count = reader->input_len - reader->offset;
    if (count > capacity) count = capacity;
    if (count > sizeof(reader->received) - reader->received_len)
        count = sizeof(reader->received) - reader->received_len;
    if (!count) {
        snprintf(err, errcap, "fixture response exceeds capture limit");
        return -1;
    }
    memcpy(out, reader->input + reader->offset, count);
    memcpy(reader->received + reader->received_len, out, count);
    reader->offset += count;
    reader->received_len += count;
    return (long)count;
}

static const char *answer_name(d2k_hs_answer answer)
{
    switch (answer) {
    case D2K_HS_INJECTED: return "injected";
    case D2K_HS_GARBAGE: return "garbage";
    case D2K_HS_CUT: return "cut";
    case D2K_HS_SILENT: return "silent";
    case D2K_HS_CLOSED: return "closed";
    default: return "other";
    }
}

static d2k_hs_answer classify_response(const char *host, const uint8_t *input,
                                       size_t input_len, int *complete)
{
    fixture_reader reader = { .input = input, .input_len = input_len };
    d2k_http_read_result response;
    char err[160] = "";
    d2k_http_read_response(fixture_read, &reader, 10, &response, err, sizeof(err));
    *complete = response.complete;
    if (!reader.received_len)
        return strstr(err, "timeout") ? D2K_HS_SILENT : D2K_HS_CLOSED;

    d2k_hs_answer answer = d2k_hs_judge(host, (const char *)reader.received,
                                        reader.received_len, 98000, 99000);
    if (response.reply.outcome == D2K_HTTP_BLOCKED)
        answer = D2K_HS_INJECTED;
    if (answer != D2K_HS_REAL) return answer;
    if (!response.complete) return D2K_HS_CUT;
    return answer;
}

int main(void)
{
    static const uint8_t portal[] =
        "HTTP/1.1 302 Moved Temporarily\r\n"
        "Location: http://lawfilter.ertelecom.ru/\r\n"
        "Content-Length: 100\r\n\r\nshort";
    static const uint8_t partial_head[] =
        "HTTP/1.1 302 Moved Temporarily\r\n"
        "Location: http://lawfilter.ertelecom.ru";
    int portal_complete = 1, partial_complete = 1;
    d2k_hs_answer portal_answer = classify_response(
        "rutracker.org", portal, sizeof(portal) - 1, &portal_complete);
    d2k_hs_answer partial_answer = classify_response(
        "rutracker.org", partial_head, sizeof(partial_head) - 1, &partial_complete);

    printf("portal_truncated=%s\npartial_header_timeout=%s\n",
           answer_name(portal_answer), answer_name(partial_answer));
    return portal_answer == D2K_HS_INJECTED && !portal_complete &&
                   partial_answer == D2K_HS_GARBAGE && !partial_complete ? 0 : 1;
}
