/* C/Rust differential: request_feed (datapath/http80.c:342-347). */
#include <stdio.h>
#include <string.h>

#include "http80.c"

static void dump(const char *label, const flow *f) {
    printf("%s client_next=%u next_known=%u next=%u end=%u hd=%u invalid=%u past=%u\n",
           label, f->client_next, f->next_known, f->request.next, f->request.end,
           f->request.header_done, f->request.invalid, f->request.past_end);
}

int main(void) {
    flow f;
    memset(&f, 0, sizeof f);
    d2k_http_request_stream_init(&f.request, 1000);
    request_feed(&f, 1000, (const uint8_t *)"GET / HTTP/1.1\r\nHost: ex",
                 strlen("GET / HTTP/1.1\r\nHost: ex"));
    dump("split1", &f);
    request_feed(&f, f.request.next,
                 (const uint8_t *)"ample.com\r\nContent-Length: 3\r\n\r\n",
                 strlen("ample.com\r\nContent-Length: 3\r\n\r\n"));
    dump("split2", &f);
    request_feed(&f, f.request.next, (const uint8_t *)"abcd", strlen("abcd"));
    dump("body", &f);

    memset(&f, 0, sizeof f);
    d2k_http_request_stream_init(&f.request, 2000);
    request_feed(&f, 2000,
                 (const uint8_t *)"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
                 strlen("GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"));
    dump("te", &f);

    memset(&f, 0, sizeof f);
    d2k_http_request_stream_init(&f.request, 3000);
    request_feed(&f, 3000, (const uint8_t *)"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
                 strlen("GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
    dump("first", &f);
    request_feed(&f, 2999, (const uint8_t *)"x", strlen("x"));
    dump("old", &f);
    request_feed(&f, f.request.next + 3, (const uint8_t *)"y", strlen("y"));
    dump("gap", &f);
    return 0;
}
