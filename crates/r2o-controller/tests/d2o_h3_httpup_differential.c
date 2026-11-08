/* CL14: C-оракул HTTP/3 helpers и httpup-логики. */
#define _POSIX_C_SOURCE 200809L
#include "d2k_h3.h"
#include "d2k_httpup.h"

#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", bytes[i]);
    }
}

static void print_response_hex(const char *response, size_t length) {
    const char *product = "X-D2K-HTTP-Upgrade";
    const char *normalized = "X-UPGRADE";
    size_t product_len = strlen(product);
    size_t normalized_len = strlen(normalized);
    for (size_t i = 0; i < length;) {
        if (i + product_len <= length && memcmp(response + i, product, product_len) == 0) {
            for (size_t j = 0; j < normalized_len; j++) {
                printf("%02x", (unsigned char)normalized[j]);
            }
            i += product_len;
        } else {
            printf("%02x", (unsigned char)response[i]);
            i++;
        }
    }
}

static void h3_status_case(const char *name, const uint8_t *bytes, size_t length) {
    int status = 0;
    int rc = d2k_h3_status(bytes, length, &status);
    printf("h3status %s rc=%d st=%d\n", name, rc, rc == 0 ? status : 0);
}

int main(void) {
    uint8_t output[512];
    size_t length;

    static const size_t caps[] = { 0, 2, 3, 16 };
    for (size_t i = 0; i < sizeof caps / sizeof caps[0]; i++) {
        size_t cap = caps[i];
        length = d2k_h3_control(output, cap);
        printf("h3control cap=%zu n=%zu hex=", cap, length);
        print_hex(output, length);
        printf("\n");
    }

    static const struct {
        const char *name;
        const char *host;
        const char *path;
        size_t cap;
    } requests[] = {
        { "root", "example.com", "/", 512 },
        { "nonroot", "example.com", "/big.css", 512 },
        { "empty-path", "example.com", "", 512 },
        { "empty-host", "", "/", 512 },
        { "cap-1", "example.com", "/", 1 },
        { "cap-5", "example.com", "/", 5 },
        { "cap-20", "example.com", "/", 20 },
    };
    for (size_t i = 0; i < sizeof requests / sizeof requests[0]; i++) {
        length = d2k_h3_request(requests[i].host, requests[i].path, output, requests[i].cap);
        printf("h3req %s n=%zu hex=", requests[i].name, length);
        print_hex(output, length);
        printf("\n");
    }
    {
        char long_host[257];
        memset(long_host, 'a', 255);
        long_host[255] = '\0';
        length = d2k_h3_request(long_host, "/", output, sizeof output);
        printf("h3req long-host n=%zu hex=", length);
        print_hex(output, length);
        printf("\n");
        memset(long_host, 'a', 256);
        long_host[256] = '\0';
        length = d2k_h3_request(long_host, "/", output, sizeof output);
        printf("h3req long-host-256 n=%zu hex=", length);
        print_hex(output, length);
        printf("\n");
    }

    h3_status_case("static24", (const uint8_t[]){ 0x01, 0x03, 0x00, 0x00, 0xd8 }, 5);
    h3_status_case("static25", (const uint8_t[]){ 0x01, 0x03, 0x00, 0x00, 0xd9 }, 5);
    h3_status_case("static28", (const uint8_t[]){ 0x01, 0x03, 0x00, 0x00, 0xdc }, 5);
    h3_status_case("static63", (const uint8_t[]){ 0x01, 0x04, 0x00, 0x00, 0xff, 0x00 }, 6);
    h3_status_case("static71", (const uint8_t[]){ 0x01, 0x04, 0x00, 0x00, 0xff, 0x08 }, 6);
    h3_status_case("huff404", (const uint8_t[]){ 0x01, 0x08, 0x00, 0x00, 0x5f, 0x0c, 0x83, 0x68, 0x0d, 0x7f }, 10);
    h3_status_case("plain201", (const uint8_t[]){ 0x01, 0x08, 0x00, 0x00, 0x5f, 0x0c, 0x03, '2', '0', '1' }, 10);
    h3_status_case("unknown-frame", (const uint8_t[]){ 0x21, 0x02, 0xaa, 0xbb, 0x01, 0x03, 0x00, 0x00, 0xd9 }, 9);
    h3_status_case("truncated", (const uint8_t[]){ 0x01, 0x10, 0x00, 0x00 }, 4);
    h3_status_case("literal-name", (const uint8_t[]){ 0x01, 0x09, 0x00, 0x00, 0x23, 'x', '-', 'a', 0x01, '1', 0xd9 }, 11);
    h3_status_case("post-base", (const uint8_t[]){ 0x01, 0x07, 0x00, 0x00, 0x11, 0x02, 0x01, '1', 0xd9 }, 9);

    static const struct { uint8_t value[3]; size_t length; int status; } literals[] = {
        { { 0x64, 0x01 }, 2, 301 },
        { { 0x6c, 0x0c, 0xff }, 3, 503 },
        { { 0x10, 0x01 }, 2, 200 },
    };
    for (size_t i = 0; i < sizeof literals / sizeof literals[0]; i++) {
        uint8_t frame[16];
        size_t used = 0;
        frame[used++] = 0x01;
        size_t length_at = used++;
        frame[used++] = 0x00;
        frame[used++] = 0x00;
        frame[used++] = 0x5f;
        frame[used++] = 24 - 15;
        frame[used++] = (uint8_t)(0x80 | literals[i].length);
        memcpy(frame + used, literals[i].value, literals[i].length);
        used += literals[i].length;
        frame[length_at] = (uint8_t)(used - 2);
        char name[32];
        snprintf(name, sizeof name, "literal-%d", literals[i].status);
        h3_status_case(name, frame, used);
    }

    static const struct { const char *name; const char *text; } http_requests[] = {
        { "safe-get", "GET /forum/index.php?q=1 HTTP/1.1\r\nHost: RuTracker.org:80\r\nConnection: close\r\n\r\n" },
        { "post", "POST /login HTTP/1.1\r\nHost: rutracker.org\r\n\r\n" },
        { "no-host", "GET / HTTP/1.1\r\nConnection: close\r\n\r\n" },
        { "absolute", "GET http://rutracker.org/ HTTP/1.1\r\nHost: rutracker.org\r\n\r\n" },
        { "body", "GET / HTTP/1.1\r\nHost: rutracker.org\r\nContent-Length: 1\r\n\r\nx" },
        { "unframed-tail", "GET / HTTP/1.1\r\nHost: rutracker.org\r\n\r\nx" },
        { "http10", "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n" },
        { "head", "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n" },
    };
    for (size_t i = 0; i < sizeof http_requests / sizeof http_requests[0]; i++) {
        int safe = d2k_httpup_request_safe(http_requests[i].text, strlen(http_requests[i].text));
        printf("httpup %s safe=%d\n", http_requests[i].name, safe);
    }
    {
        char host[256], target[2048];
        const char *request = "GET /forum/index.php?q=1 HTTP/1.1\r\nHost: RuTracker.org:80\r\n\r\n";
        int ok = d2k_httpup_request_target(request, strlen(request), host, sizeof host,
                                           target, sizeof target);
        printf("httpup target safe-get ok=%d host=", ok);
        if (ok) print_hex((const uint8_t *)host, strlen(host));
        printf(" target=");
        if (ok) print_hex((const uint8_t *)target, strlen(target));
        printf("\n");
    }

    static const char *portal_request =
        "GET /forum/index.php?q=1 HTTP/1.1\r\nHost: RuTracker.org:80\r\n\r\n";
    static const struct { const char *name; const char *response; size_t length; } responses[] = {
        { "portal", "HTTP/1.1 302 Found\r\nLocation: http://lawfilter.ertelecom.ru/deny?id=7\r\nContent-Length: 0\r\n\r\n", 0 },
        { "megafon", "HTTP/1.1 302 Found\r\nLocation: https://m.megafonpro.ru/rkn-auth?channel=2m\r\nContent-Length: 0\r\n\r\n", 0 },
        { "rt", "HTTP/1.1 302 Found\r\nLocation: http://warning.rt.ru/\r\nContent-Length: 0\r\n\r\n", 0 },
        { "beeline", "HTTP/1.1 302 Found\r\nLocation: http://warn.beeline.ru/\r\nContent-Length: 0\r\n\r\n", 0 },
        { "megafon-deny", "HTTP/1.1 302 Found\r\nLocation: http://deny.megafon.ru/blocked\r\nContent-Length: 0\r\n\r\n", 0 },
        { "blackhole", "HTTP/1.1 302 Found\r\nLocation: http://blackhole.svyaztelecom.ru/\r\nContent-Length: 0\r\n\r\n", 0 },
        { "ordinary", "HTTP/1.1 302 Found\r\nLocation: https://login.example.net/continue\r\nContent-Length: 0\r\n\r\n", 0 },
        { "same-host", "HTTP/1.1 302 Found\r\nLocation: https://rutracker.org/forum/\r\nContent-Length: 0\r\n\r\n", 0 },
        { "deceptive", "HTTP/1.1 302 Found\r\nLocation: https://unblocked.example/continue\r\nContent-Length: 0\r\n\r\n", 0 },
        { "not-redirect", "HTTP/1.1 200 OK\r\nLocation: https://lawfilter.example/\r\nContent-Length: 0\r\n\r\n", 0 },
        { "rkn-path", "HTTP/1.1 302 Found\r\nLocation: http://isp.example.org/rkn-landing/rkn?id=1\r\nContent-Length: 0\r\n\r\n", 0 },
    };
    for (size_t i = 0; i < sizeof responses / sizeof responses[0]; i++) {
        char response[4096];
        size_t response_length = responses[i].length;
        if (response_length == 0) response_length = strlen(responses[i].response);
        int ok = d2k_httpup_portal_response(portal_request, strlen(portal_request),
                                             responses[i].response, response_length,
                                             response, sizeof response);
        printf("httpup response %s ok=%d hex=", responses[i].name, ok);
        if (ok) print_response_hex(response, strlen(response));
        printf("\n");
    }
    {
        char portal[256];
        const char *response =
            "HTTP/1.1 302 Found\r\nLocation: http://lawfilter.ertelecom.ru/deny?id=7\r\n\r\n";
        int ok = d2k_httpup_portal_location("rutracker.org", response, strlen(response),
                                            portal, sizeof portal);
        printf("httpup location ok=%d hex=", ok);
        if (ok) print_hex((const uint8_t *)portal, strlen(portal));
        printf("\n");
    }
    {
        char response[4096];
        size_t length = d2k_httpup_redirect_https("rutracker.org", "/forum/index.php?q=1",
                                                   response, sizeof response);
        printf("httpup redirect n=%zu hex=", length);
        if (length) print_response_hex(response, length);
        printf("\n");
    }
    return 0;
}
