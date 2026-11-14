/* C/Rust differential: d2k_http_request_stream (a378). */
#include <stdio.h>
#include <string.h>

#include "d2k_http_request_stream.h"

static void dump(const char *label, const d2k_http_request_stream *s) {
    printf("%s start=%u next=%u head=%u end=%u length=%llu invalid=%u hd=%u past=%u\n",
           label, s->start, s->next, s->head_len, s->end,
           (unsigned long long)s->length, s->invalid, s->header_done, s->past_end);
}

static void feed(d2k_http_request_stream *s, uint32_t seq, const char *text) {
    d2k_http_request_stream_feed(s, seq, (const uint8_t *)text, strlen(text));
}

int main(void) {
    {
        d2k_http_request_stream s;
        d2k_http_request_stream_init(&s, 1000);
        feed(&s, 1000, "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\n");
        dump("simple", &s);
        feed(&s, s.next, "abcd");
        dump("past_end", &s);
    }
    {
        d2k_http_request_stream s;
        d2k_http_request_stream_init(&s, 2000);
        feed(&s, 2000, "GET / HTTP/1.1\r\nHost: ex");
        dump("split1", &s);
        feed(&s, s.next, "ample.com\r\nContent-Length: 0\r\n\r\n");
        dump("split2", &s);
    }
    {
        d2k_http_request_stream s;
        d2k_http_request_stream_init(&s, 3000);
        feed(&s, 3000, "GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
        dump("no_host", &s);
    }
    {
        d2k_http_request_stream s;
        d2k_http_request_stream_init(&s, 4000);
        feed(&s, 4000, "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n");
        dump("two_hosts", &s);
    }
    {
        d2k_http_request_stream s;
        d2k_http_request_stream_init(&s, 5000);
        feed(&s, 5000, "GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n");
        dump("te", &s);
    }
    {
        d2k_http_request_stream s;
        d2k_http_request_stream_init(&s, 6000);
        feed(&s, 6000, "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: h2c\r\n\r\n");
        dump("upgrade", &s);
    }
    {
        d2k_http_request_stream s;
        d2k_http_request_stream_init(&s, 7000);
        feed(&s, 7000, "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n");
        dump("duplicate_cl", &s);
    }
    {
        d2k_http_request_stream s;
        d2k_http_request_stream_init(&s, 8000);
        feed(&s, 8000, "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1x\r\n\r\n");
        dump("bad_cl", &s);
    }
    {
        d2k_http_request_stream s;
        d2k_http_request_stream_init(&s, 9000);
        feed(&s, 9000, "GET / HTTP/1.1\r\nHost: a\r\nX: \x01\r\n\r\n");
        dump("control", &s);
    }
    {
        d2k_http_request_stream s;
        d2k_http_request_stream_init(&s, 10000);
        feed(&s, 10000, "GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        uint32_t old = s.start;
        feed(&s, old, "0123456789");
        dump("old_repeat", &s);
        feed(&s, s.next + 5, "x");
        dump("gap", &s);
    }
    return 0;
}
