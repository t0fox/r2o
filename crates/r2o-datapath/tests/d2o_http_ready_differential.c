/* C-оракул: http_ready (datapath/hold.c:93-100) — tri-state готовности
 * HTTP-головы. hold.c включается целиком: функция статическая; неиспользуемые
 * секции выбрасываются --gc-sections. */
#include "hold.c"

#include <stdio.h>
#include <string.h>

static void run(const char *name, const uint8_t *bytes, size_t n, size_t high) {
    printf("%s rc=%d\n", name, http_ready(bytes, n, high));
}

int main(void) {
    static const uint8_t valid[] = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    static const uint8_t no_blank[] = "GET / HTTP/1.1\r\nHost: a\r\n";
    static const uint8_t host_partial[] = "GET / HTTP/1.1\r\nHost: a";
    static const uint8_t no_host[] = "GET / HTTP/1.1\r\nX: y\r\n\r\n";
    static const uint8_t hash[] = "GET /a#b HTTP/1.1\r\nHost: a\r\n\r\n";
    static const uint8_t bad_target[] = "GET /a\x01b HTTP/1.1\r\nHost: a\r\n\r\n";
    static uint8_t long_target[2300];
    static uint8_t garbage[4096];

    run("A valid-full", valid, sizeof valid - 1, sizeof valid - 1);
    run("B no-blank", no_blank, sizeof no_blank - 1, sizeof no_blank - 1);
    run("C host-partial", host_partial, sizeof host_partial - 1,
        sizeof host_partial - 1);
    run("D n-less-high", valid, sizeof valid - 1, sizeof valid - 1 + 1);
    run("E no-host-full", no_host, sizeof no_host - 1, sizeof no_host - 1);
    run("F no-host-partial", no_host, sizeof no_host - 1, sizeof no_host - 1 + 3);
    run("G hash", hash, sizeof hash - 1, sizeof hash - 1);
    run("H bad-target", bad_target, sizeof bad_target - 1,
        sizeof bad_target - 1);

    memcpy(long_target, "GET /", 5);
    memset(long_target + 5, 'a', 2100);
    memcpy(long_target + 2105, " HTTP/1.1\r\nHost: a\r\n\r\n", 22);
    run("I long-target", long_target, 2127, 2127);

    memset(garbage, 'G', sizeof garbage);
    run("J buffer-full", garbage, sizeof garbage, sizeof garbage);
    return 0;
}
