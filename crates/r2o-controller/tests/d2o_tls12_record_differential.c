#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static ssize_t mock_send(int fd, const void *buf, size_t length, int flags);
static int mock_poll(struct pollfd *fds, nfds_t nfds, int timeout);
#define send mock_send
#define poll mock_poll
#include "tls12.c"
#undef send
#undef poll

static ssize_t mock_send(int fd, const void *buf, size_t length, int flags) {
    (void)fd;
    (void)flags;
    (void)buf;
    return (ssize_t)length;
}

static int mock_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    (void)fds;
    (void)nfds;
    (void)timeout;
    return 1;
}

static void print_hex(const uint8_t *bytes, size_t length) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        putchar(digits[bytes[i] >> 4]);
        putchar(digits[bytes[i] & 0x0f]);
    }
}

int main(void) {
    d2k_tls12 tls;
    memset(&tls, 0, sizeof tls);
    tls.fd = 42;
    static const uint8_t salt[4] = {0xa1, 0xb2, 0xc3, 0xd4};
    static const uint8_t key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    memcpy(tls.c_salt, salt, sizeof salt);
    memcpy(tls.c_key, key, sizeof key);
    tls.c_seq = 1;
    char err[160] = "";
    if (send_sealed(&tls, 23, (const uint8_t *)"hello", 5, err, sizeof err) != 0) {
        printf("sealed|-|err=%s\n", err);
        return 0;
    }
    printf("sealed|");
    print_hex(tls.wire, 5 + 8 + 5 + 16);
    printf("|seq=%llu\n", (unsigned long long)tls.c_seq);
    return 0;
}
