/* C-оракул production tls13.c read_exact/write_all.
 *
 * Включает production core/tls13.c с -ffunction-sections/-data-sections и
 * mock recv/send/poll; криптография и handshake-функции выброшены
 * --gc-sections. Печатает коды/errno/байты для C/Rust diff.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define recv mock_recv
#define send mock_send
#define poll mock_poll
static ssize_t mock_recv(int fd, void *buf, size_t cap, int flags);
static ssize_t mock_send(int fd, const void *buf, size_t length, int flags);
static int mock_poll(struct pollfd *fds, nfds_t nfds, int timeout);
#include "tls13.c"
#undef recv
#undef send
#undef poll

#define MAX_EVENTS 16
#define MAX_BYTES 64

typedef struct {
    ssize_t value;
    int error;
    const uint8_t *data;
    size_t length;
} mock_event;

static mock_event recv_events[MAX_EVENTS];
static size_t recv_count, recv_index;
static mock_event send_events[MAX_EVENTS];
static size_t send_count, send_index;
static int poll_events[MAX_EVENTS];
static int poll_errors[MAX_EVENTS];
static size_t poll_count, poll_index;

static uint8_t sent_bytes[MAX_BYTES];
static size_t sent_length;

static void reset_mock(void)
{
    memset(recv_events, 0, sizeof recv_events);
    memset(send_events, 0, sizeof send_events);
    memset(poll_events, 0, sizeof poll_events);
    memset(poll_errors, 0, sizeof poll_errors);
    recv_count = recv_index = 0;
    send_count = send_index = 0;
    poll_count = poll_index = 0;
    sent_length = 0;
}

static void add_recv(ssize_t value, int error, const uint8_t *data, size_t length)
{
    recv_events[recv_count++] = (mock_event){value, error, data, length};
}

static void add_send(ssize_t value, int error)
{
    send_events[send_count++] = (mock_event){value, error, NULL, 0};
}

static void add_poll(int value, int error)
{
    poll_events[poll_count] = value;
    poll_errors[poll_count] = error;
    poll_count++;
}

static ssize_t mock_recv(int fd, void *buf, size_t cap, int flags)
{
    (void)fd;
    (void)flags;
    if (recv_index >= recv_count) {
        errno = EAGAIN;
        return -1;
    }
    mock_event event = recv_events[recv_index++];
    if (event.value < 0) {
        errno = event.error;
        return -1;
    }
    size_t n = (size_t)event.value;
    if (n > cap) n = cap;
    if (n > event.length) n = event.length;
    if (n && event.data) memcpy(buf, event.data, n);
    return (ssize_t)n;
}

static ssize_t mock_send(int fd, const void *buf, size_t length, int flags)
{
    (void)fd;
    (void)flags;
    if (send_index >= send_count) {
        errno = EAGAIN;
        return -1;
    }
    mock_event event = send_events[send_index++];
    if (event.value < 0) {
        errno = event.error;
        return -1;
    }
    if (event.value == 0) errno = 0;
    size_t n = (size_t)event.value;
    if (n > length) n = length;
    if (n) {
        if (sent_length + n > sizeof sent_bytes) return -1;
        memcpy(sent_bytes + sent_length, buf, n);
        sent_length += n;
    }
    return (ssize_t)n;
}

static int mock_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    (void)fds;
    (void)nfds;
    (void)timeout;
    if (poll_index >= poll_count) return 1;
    int value = poll_events[poll_index];
    if (value < 0) errno = poll_errors[poll_index];
    poll_index++;
    return value;
}

static void print_hex(const uint8_t *bytes, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        putchar(digits[bytes[i] >> 4]);
        putchar(digits[bytes[i] & 0x0f]);
    }
}

static void report(const char *name, int rc, const char *err,
                   const d2k_tls *tls, const uint8_t *buf, size_t length)
{
    printf("io|%s|rc=%d|err=%s|rx=%llu|missing=%u|buf=", name, rc, err,
           (unsigned long long)tls->rx_wire_bytes, tls->rx_record_missing);
    print_hex(buf, length);
    printf("|sent=");
    print_hex(sent_bytes, sent_length);
    putchar('\n');
}

static d2k_tls make_tls(void)
{
    d2k_tls tls;
    memset(&tls, 0, sizeof tls);
    tls.fd = 42;
    return tls;
}

static void run_read(const char *name, size_t length, int body, int64_t deadline_ms)
{
    d2k_tls tls = make_tls();
    uint8_t buf[MAX_BYTES];
    memset(buf, 0, sizeof buf);
    char err[160] = "";
    int rc = read_exact(&tls, buf, length, body, deadline_ms, err, sizeof err);
    report(name, rc, err, &tls, buf, length);
}

static void run_write(const char *name, size_t length)
{
    d2k_tls tls = make_tls();
    uint8_t buf[MAX_BYTES];
    for (size_t i = 0; i < length; i++) buf[i] = (uint8_t)(0xa0 + i);
    char err[160] = "";
    int rc = write_all(tls.fd, buf, length, err, sizeof err);
    report(name, rc, err, &tls, buf, length);
}

int main(void)
{
    static const uint8_t data[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    int64_t deadline = now_ms() + 1000;

    reset_mock();
    add_poll(1, 0);
    add_recv(4, 0, data, 4);
    run_read("read-full", 4, 0, deadline);

    reset_mock();
    add_poll(1, 0);
    add_recv(2, 0, data, 2);
    add_poll(1, 0);
    add_recv(2, 0, data + 2, 2);
    run_read("read-short", 4, 0, deadline);

    reset_mock();
    add_poll(-1, EINTR);
    add_poll(1, 0);
    add_recv(4, 0, data, 4);
    run_read("read-eintr", 4, 0, deadline);

    reset_mock();
    add_poll(1, 0);
    add_recv(-1, EAGAIN, NULL, 0);
    add_poll(1, 0);
    add_recv(4, 0, data, 4);
    run_read("read-eagain", 4, 0, deadline);

    reset_mock();
    add_poll(1, 0);
    add_recv(0, 0, NULL, 0);
    run_read("read-eof", 4, 0, deadline);

    reset_mock();
    add_poll(1, 0);
    add_recv(-1, EIO, NULL, 0);
    run_read("read-error", 4, 0, deadline);

    reset_mock();
    run_read("read-deadline", 4, 0, now_ms());

    reset_mock();
    add_send(4, 0);
    run_write("write-full", 4);

    reset_mock();
    add_send(1, 0);
    add_send(3, 0);
    run_write("write-short", 4);

    reset_mock();
    add_send(-1, EINTR);
    add_send(4, 0);
    run_write("write-eintr", 4);

    reset_mock();
    add_send(-1, EAGAIN);
    add_send(4, 0);
    run_write("write-eagain", 4);

    reset_mock();
    add_send(-1, EIO);
    run_write("write-error", 4);

    reset_mock();
    add_send(0, 0);
    run_write("write-zero", 4);

    return 0;
}
