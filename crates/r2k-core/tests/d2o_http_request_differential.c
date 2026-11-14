/* C/Rust differential: d2k_http_request (datapath/http80.c:551-632). */
#include <stdio.h>
#include <string.h>

#include "d2k_http80.h"

static void run(const char *name, const char *text) {
    d2k_http_req request;
    memset(&request, 0, sizeof request);
    int rc = d2k_http_request((const uint8_t *)text, strlen(text), &request);
    if (!rc) {
        request.head_len = 0;
        request.end_known = 0;
        request.end = 0;
    }
    printf("%s rc=%d host=", name, rc);
    if (rc) {
        for (size_t i = 0; i < request.host_len; i++)
            printf("%02x", (unsigned char)text[request.host_off + i]);
    }
    printf(" head=%zu end_known=%d end=%zu\n",
           request.head_len, request.end_known, request.end);
}

int main(void) {
    run("simple", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    run("partial", "GET / HTTP/1.1\r\nHost: example.com\r\nX");
    run("host80", "GET / HTTP/1.1\r\nHost: example.com:80\r\n\r\n");
    run("host8080", "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n");
    run("no_host", "GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
    run("two_hosts", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n");
    run("trailing_dot", "GET / HTTP/1.1\r\nHost: example.com.\r\n\r\n");
    run("ipv4", "GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n");
    run("lower_method", "get / HTTP/1.1\r\nHost: a\r\n\r\n");
    run("absolute", "GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n");
    run("bad_label", "GET / HTTP/1.1\r\nHost: -bad\r\n\r\n");
    run("te", "GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n");
    run("duplicate_cl", "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n");
    run("cl", "GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n");
    run("no_crlf", "GET / HTTP/1.1\r\nHost: a\r\n");
    run("hash", "GET /a#b HTTP/1.1\r\nHost: a\r\n\r\n");
    run("empty_host", "GET / HTTP/1.1\r\nHost:\r\n\r\n");
    run("host_ws", "GET / HTTP/1.1\r\nHost:   \r\n\r\n");
    run("host_tab", "GET / HTTP/1.1\r\nHost:\ta\t\r\n\r\n");
    run("multi_colon", "GET / HTTP/1.1\r\nHost: a:80:80\r\n\r\n");
    run("dot_only", "GET / HTTP/1.1\r\nHost: .\r\n\r\n");
    run("numeric_last", "GET / HTTP/1.1\r\nHost: a.123\r\n\r\n");
    run("upper_host", "GET / HTTP/1.1\r\nHOST: EXAMPLE.COM\r\n\r\n");
    run("method20", "ABCDEFGHIJKLMNOPQRST / HTTP/1.1\r\nHost: a\r\n\r\n");
    run("method21", "ABCDEFGHIJKLMNOPQRSTU / HTTP/1.1\r\nHost: a\r\n\r\n");
    run("tab_header", "GET / HTTP/1.1\r\nX: a\tb\r\nHost: a\r\n\r\n");
    run("http10", "GET / HTTP/1.0\r\nHost: a\r\n\r\n");
    run("http12", "GET / HTTP/1.2\r\nHost: a\r\n\r\n");
    run("host_underscore", "GET / HTTP/1.1\r\nHost: a_b\r\n\r\n");
    run("lone_lf", "GET / HTTP/1.1\nHost: a\n\n");
    run("target_ctl", "GET /a\001b HTTP/1.1\r\nHost: a\r\n\r\n");
    {
        static char long_target[2300];
        memcpy(long_target, "GET /", 5);
        memset(long_target + 5, 'a', 2100);
        memcpy(long_target + 2105, " HTTP/1.1\r\nHost: a\r\n\r\n", 24);
        run("long_target", long_target);
    }
    return 0;
}
