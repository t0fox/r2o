/* C/Rust differential: d2k_http_response_feed framing (a378). */
#include <stdio.h>
#include <string.h>

#include "d2k_http_response.h"

typedef struct {
    const char *name;
    const unsigned char *bytes;
    size_t len;
} case_t;

#define CASE(name, lit) { name, (const unsigned char *)(lit), sizeof(lit) - 1 }

int main(void) {
    static const case_t cases[] = {
        CASE("extension_suffix", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;foo=\"unterminated\r\nx\r\n0\r\n\r\n"),
        CASE("trailer_without_colon", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nnot-a-field\r\n\r\n"),
        CASE("colonless_header", "HTTP/1.1 200 OK\r\nMalformed Header\r\nContent-Length: 1\r\n\r\nx"),
        CASE("control_extension", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;foo=\x01\r\nx\r\n0\r\n\r\n"),
        CASE("control_chunk_size", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\x01\r\nx\r\n0\r\n\r\n"),
        CASE("buffered_bytes_after_frame", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nextra"),
        CASE("control_header_value", "HTTP/1.1 200 OK\r\nX: foo\x01" "bar\r\nContent-Length: 0\r\n\r\n"),
        CASE("bare_lf_header_value", "HTTP/1.1 200 OK\r\nX: foo\nbar\r\nContent-Length: 0\r\n\r\n"),
        CASE("bare_cr_header_value", "HTTP/1.1 200 OK\r\nX: foo\rbar\r\nContent-Length: 0\r\n\r\n"),
        CASE("bare_lf_swallows_next_header", "HTTP/1.1 200 OK\r\nX: x\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"),
        CASE("control_trailer", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: foo\x01" "bar\r\n\r\n"),
        CASE("nul_first_trailer", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\0ignored\r\n"),
        CASE("bodyless_204_buffered", "HTTP/1.1 204 No Content\r\nContent-Length: 4\r\n\r\nbody"),
        CASE("bodyless_304_buffered", "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\nnot-a-chunk"),
        CASE("status12", "HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n"),
        CASE("duplicate_cl", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 01\r\n\r\nx"),
        CASE("chunk_bare_space", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1 \r\nx\r\n0\r\n\r\n"),
        CASE("chunk_ext_ok", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;foo=\"bar\"\r\nx\r\n0\r\n\r\n"),
        CASE("chunk_ows_ext_ok", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1 ;foo\r\nx\r\n0\r\n\r\n"),
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        d2k_http_response response;
        memset(&response, 0, sizeof response);
        d2k_http_response_feed(&response, cases[i].bytes, cases[i].len, 0);
        printf("%s status=%u complete=%d body_bytes=%llu invalid=%d\n",
               cases[i].name, response.status, response.complete,
               (unsigned long long)response.body_bytes, response.invalid);
    }
    return 0;
}
