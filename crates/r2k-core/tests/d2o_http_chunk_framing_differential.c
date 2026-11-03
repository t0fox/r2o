#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_verify.h"

typedef struct {
    const uint8_t *input;
    size_t input_len;
    size_t offset;
} fixture_reader;

typedef struct {
    const char *name;
    const uint8_t *input;
    size_t input_len;
    int expected_status;
    int expected_complete;
    uint64_t expected_body_bytes;
} test_case;

static long fixture_read(void *opaque, uint8_t *out, size_t capacity, int wait_ms,
                         char *err, size_t errcap)
{
    fixture_reader *reader = opaque;
    (void)wait_ms;
    if (reader->offset == reader->input_len) {
        snprintf(err, errcap, "fixture exhausted");
        return 0;
    }
    size_t count = reader->input_len - reader->offset;
    if (count > capacity) count = capacity;
    memcpy(out, reader->input + reader->offset, count);
    reader->offset += count;
    return (long)count;
}

int main(void)
{
    static const char prefix[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;";
    static const char suffix[] = "\r\nx\r\n0\r\n\r\n";
    uint8_t line_at_limit[256], line_over_limit[256];
    const size_t prefix_len = sizeof(prefix) - 1;
    const size_t suffix_len = sizeof(suffix) - 1;
    memcpy(line_at_limit, prefix, prefix_len);
    memset(line_at_limit + prefix_len, 'a', 125);
    memcpy(line_at_limit + prefix_len + 125, suffix, suffix_len);
    line_at_limit[prefix_len + 125 + suffix_len] = 0;
    memcpy(line_over_limit, prefix, prefix_len);
    memset(line_over_limit + prefix_len, 'a', 126);
    memcpy(line_over_limit + prefix_len + 126, suffix, suffix_len);
    line_over_limit[prefix_len + 126 + suffix_len] = 0;

    static const uint8_t extension[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "1;foo=\"unterminated\r\nx\r\n0\r\n\r\n";
    static const uint8_t trailer[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "0\r\nnot-a-field\r\n\r\n";
    static const uint8_t colonless_header[] =
        "HTTP/1.1 200 OK\r\nMalformed Header\r\nContent-Length: 1\r\n\r\nx";
    static const uint8_t control_extension[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "1;foo=\001\r\nx\r\n0\r\n\r\n";
    static const uint8_t control_chunk_size[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "1\001\r\nx\r\n0\r\n\r\n";
    static const uint8_t buffered_bytes_after_frame[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nextra";
    static const uint8_t control_header_value[] =
        "HTTP/1.1 200 OK\r\nX: foo\001bar\r\nContent-Length: 0\r\n\r\n";
    static const uint8_t control_trailer[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "0\r\nX: foo\001bar\r\n\r\n";
    static const uint8_t nul_first_trailer[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "0\r\n\000ignored\r\n";
    static const uint8_t bodyless_204_buffered[] =
        "HTTP/1.1 204 No Content\r\nContent-Length: 4\r\n\r\nbody";
    static const uint8_t bodyless_304_buffered[] =
        "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\nnot-a-chunk";
    const test_case cases[] = {
        { "extension_suffix", extension, sizeof(extension) - 1, 200, 1, 1 },
        { "trailer_without_colon", trailer, sizeof(trailer) - 1, 200, 1, 0 },
        { "colonless_header", colonless_header, sizeof(colonless_header) - 1, 200, 1, 1 },
        { "control_extension", control_extension, sizeof(control_extension) - 1, 200, 1, 1 },
        { "control_chunk_size", control_chunk_size, sizeof(control_chunk_size) - 1, 200, 0, 0 },
        { "buffered_bytes_after_frame", buffered_bytes_after_frame,
          sizeof(buffered_bytes_after_frame) - 1, 200, 1, 0 },
        { "control_header_value", control_header_value, sizeof(control_header_value) - 1,
          200, 1, 0 },
        { "control_trailer", control_trailer, sizeof(control_trailer) - 1, 200, 1, 0 },
        { "nul_first_trailer", nul_first_trailer, sizeof(nul_first_trailer) - 1, 200, 1, 0 },
        { "bodyless_204_buffered", bodyless_204_buffered,
          sizeof(bodyless_204_buffered) - 1, 204, 1, 0 },
        { "bodyless_304_buffered", bodyless_304_buffered,
          sizeof(bodyless_304_buffered) - 1, 304, 1, 0 },
        { "chunk_line_at_limit", line_at_limit, prefix_len + 125 + suffix_len, 200, 1, 1 },
        { "chunk_line_over_limit", line_over_limit, prefix_len + 126 + suffix_len, 200, 0, 0 },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        fixture_reader reader = {
            .input = cases[i].input,
            .input_len = cases[i].input_len,
        };
        d2k_http_read_result response;
        char err[160] = "";
        d2k_http_read_response(fixture_read, &reader, 1000, &response, err, sizeof(err));
        printf("%s status=%d complete=%d body_bytes=%llu\n", cases[i].name,
               response.status, response.complete,
               (unsigned long long)response.body_bytes);
        if (response.status != cases[i].expected_status ||
            response.complete != cases[i].expected_complete ||
            response.body_bytes != cases[i].expected_body_bytes) {
            fprintf(stderr, "%s differs in C fixture: %s\n", cases[i].name, err);
            return 1;
        }
    }
    return 0;
}
