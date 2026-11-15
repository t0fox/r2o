/* C production live I/O: raw_dial → raw_send → raw_read_payload → raw_close
 * на реальном loopback-сокете в netns. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "raw.c"

int64_t d2k_now_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

int d2k_detect_stopped(const d2k_detect_stop *cancel)
{
    (void)cancel;
    return 0;
}

void d2k_sleep_ms(int ms) { (void)ms; }

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s FAMILY ADDRESS PORT TIMEOUT_MS\n", argv[0]);
        return 2;
    }
    uint8_t family = (uint8_t)atoi(argv[1]);
    uint8_t address[16] = {0};
    if (inet_pton(family == 6 ? AF_INET6 : AF_INET, argv[2], address) != 1) {
        fprintf(stderr, "bad address: %s\n", argv[2]);
        return 2;
    }
    int timeout = atoi(argv[4]);
    raw_conn connection;
    char err[160] = "";
    int rc = raw_dial(&connection, address, family, (uint16_t)atoi(argv[3]),
                      timeout, 0, NULL, 1, err, sizeof err);
    if (rc != 0) {
        printf("io|dial=%d|err=%s\n", rc, err);
        return 0;
    }
    printf("io|dial=0|");
    d2k_poison none;
    memset(&none, 0, sizeof none);
    const uint8_t payload[] = "hello";
    if (raw_send(&connection, payload, sizeof payload - 1, TCP_PSH | TCP_ACK,
                 &none) != 0) {
        printf("send=-1|err=%s\n", strerror(errno));
        raw_close(&connection);
        return 0;
    }
    connection.seq += (uint32_t)(sizeof payload - 1);
    printf("send=0|");
    uint8_t response[4096];
    size_t response_len = 0;
    rc = raw_read_payload(&connection, timeout, NULL, response,
                          sizeof response, &response_len);
    printf("read=%d|len=%zu|data=", rc, response_len);
    for (size_t i = 0; i < response_len && i < 32; i++) {
        if (response[i] >= 0x20 && response[i] < 0x7f) putchar(response[i]);
        else printf("\\x%02x", response[i]);
    }
    putchar('\n');
    raw_close(&connection);
    printf("close=0\n");
    return 0;
}
