/* C-оракул raw_recv/raw_read_payload/raw_close/raw_send/raw_handshake.
 * Сокеты, sendto/recvfrom/close заменены детерминированными очередями. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

static ssize_t raw_test_sendto(int, const void *, size_t, int,
                               const struct sockaddr *, socklen_t);
static ssize_t raw_test_recvfrom(int, void *, size_t, int,
                                 struct sockaddr *, socklen_t *);
static int raw_test_close(int);

#define sendto raw_test_sendto
#define recvfrom raw_test_recvfrom
#define close raw_test_close
#include "raw.c"
#undef sendto
#undef recvfrom
#undef close

static int64_t test_now;
int64_t d2k_now_ms(void) { return test_now++; }
int d2k_detect_stopped(const d2k_detect_stop *cancel)
{
    (void)cancel;
    return 0;
}
void d2k_sleep_ms(int ms) { (void)ms; }

static uint8_t recv_bytes[8][512];
static size_t recv_lens[8];
static int recv_errnos[8];
static int recv_peer6[8];
static int recv_count, recv_index;
static uint8_t mock_peer[16];
static int mock_family = 4;

static int send_short = -1;
static int send_errno;
static int send_fail;
static int send_calls;
static uint32_t sent_seq[16];
static size_t sent_payload[16];
static int sent_count;

static int close_fds[8];
static int close_count;

static void reset_recv(void)
{
    recv_count = recv_index = 0;
    memset(recv_lens, 0, sizeof recv_lens);
}

static void queue_packet(const uint8_t *bytes, size_t len, int peer6)
{
    memcpy(recv_bytes[recv_count], bytes, len);
    recv_lens[recv_count] = len;
    recv_errnos[recv_count] = 0;
    recv_peer6[recv_count] = peer6;
    recv_count++;
}

static void queue_error(int errno_value)
{
    recv_lens[recv_count] = 0;
    recv_errnos[recv_count] = errno_value;
    recv_peer6[recv_count] = 0;
    recv_count++;
}

ssize_t raw_test_recvfrom(int fd, void *buf, size_t len, int flags,
                          struct sockaddr *addr, socklen_t *alen)
{
    (void)fd;
    (void)flags;
    if (recv_index >= recv_count) {
        errno = EAGAIN;
        return -1;
    }
    int i = recv_index++;
    if (recv_errnos[i]) {
        errno = recv_errnos[i];
        return -1;
    }
    size_t n = recv_lens[i] < len ? recv_lens[i] : len;
    memcpy(buf, recv_bytes[i], n);
    if (addr && alen && *alen >= sizeof(struct sockaddr_in6)) {
        if (recv_peer6[i]) {
            struct sockaddr_in6 peer;
            memset(&peer, 0, sizeof peer);
            peer.sin6_family = AF_INET6;
            memcpy(&peer.sin6_addr, mock_peer, 16);
            memcpy(addr, &peer, sizeof peer);
            *alen = sizeof peer;
        } else {
            struct sockaddr_in peer;
            memset(&peer, 0, sizeof peer);
            peer.sin_family = AF_INET;
            memcpy(addr, &peer, sizeof peer);
            *alen = sizeof peer;
        }
    }
    return (ssize_t)n;
}

static void record_packet(const uint8_t *buf, size_t len)
{
    size_t ip = mock_family == 6 ? 40 : 20;
    if (len < ip + 20) return;
    const uint8_t *tcp = buf + ip;
    size_t header = (size_t)(tcp[12] >> 4) * 4;
    if (header < 20 || ip + header > len) return;
    sent_seq[sent_count] = rd32(tcp + 4);
    sent_payload[sent_count] = len - ip - header;
    sent_count++;
}

ssize_t raw_test_sendto(int fd, const void *buf, size_t len, int flags,
                        const struct sockaddr *addr, socklen_t alen)
{
    (void)fd;
    (void)flags;
    (void)addr;
    (void)alen;
    send_calls++;
    if (send_fail) {
        errno = send_errno;
        return -1;
    }
    record_packet(buf, len);
    if (send_short >= 0) return (ssize_t)send_short;
    return (ssize_t)len;
}

static int raw_test_close(int fd)
{
    if (close_count < 8) close_fds[close_count++] = fd;
    return 0;
}

static raw_conn make_conn(uint8_t family)
{
    raw_conn c;
    memset(&c, 0, sizeof c);
    c.family = family;
    c.send_fd = 10;
    c.recv_fd = 11;
    c.sport = 40000;
    c.dport = 443;
    c.seq = 1000;
    c.ack = 0;
    c.buffers = malloc(sizeof(*c.buffers));
    if (!c.buffers) exit(2);
    if (family == 6) {
        static const uint8_t src[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 1};
        static const uint8_t dst[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 7};
        memcpy(c.src, src, 16);
        memcpy(c.dst, dst, 16);
        memcpy(mock_peer, dst, 16);
    } else {
        static const uint8_t src[4] = {192, 0, 2, 1};
        static const uint8_t dst[4] = {198, 51, 100, 7};
        memcpy(c.src, src, 4);
        memcpy(c.dst, dst, 4);
    }
    mock_family = family;
    return c;
}

static size_t inbound(raw_conn *c, uint8_t *out, uint32_t seq, uint8_t flags,
                      const uint8_t *payload, size_t plen,
                      const uint8_t *options, size_t optlen)
{
    d2k_poison none;
    memset(&none, 0, sizeof none);
    size_t n = build_ip_tcp(out, 512, c->family, c->dst, c->src,
                            c->dport, c->sport, seq, c->seq, flags,
                            payload, plen, &none, options, optlen);
    return n;
}

static void recv_case(const char *name, raw_conn *c)
{
    uint8_t flags = 0;
    uint32_t seq = 0, ack = 0;
    const uint8_t *payload = NULL;
    size_t plen = 0;
    int rc = raw_recv(c, &flags, &seq, &ack, &payload, &plen,
                      d2k_now_ms() + 100000, NULL);
    if (rc == -1) {
        printf("recv|%s|wait\n", name);
    } else if (rc == -2) {
        printf("recv|%s|error\n", name);
    } else {
        printf("recv|%s|0|flags=%u|seq=%u|ack=%u|payload=%.*s\n", name,
               (unsigned)flags, (unsigned)seq, (unsigned)ack, (int)plen,
               (const char *)payload);
    }
}

static void read_case(const char *name, raw_conn *c, int timeout_ms)
{
    uint8_t out[64];
    size_t outlen = 0;
    int rc = raw_read_payload(c, timeout_ms, NULL, out, sizeof out, &outlen);
    if (rc == -1) {
        printf("read|%s|-1|\n", name);
    } else if (rc == -2) {
        printf("read|%s|-2|\n", name);
    } else {
        printf("read|%s|0|%.*s\n", name, (int)outlen, (const char *)out);
    }
}

static void handshake_case(const char *name, raw_conn *c, int timeout_ms)
{
    char err[160] = "";
    test_now = 0;
    int rc = raw_handshake(c, timeout_ms, NULL, err, sizeof err);
    if (rc == 0) {
        printf("hs|%s|ok|ts=%d\n", name, c->tcp_options_len);
        return;
    }
    printf("hs|%s|%d|err=%s\n", name, rc, err);
}

static void free_conn(raw_conn *c)
{
    free(c->buffers);
    c->buffers = NULL;
}

int main(void)
{
    uint8_t packet[512];
    static const uint8_t ts[] = {1, 1, 8, 10, 0, 0, 0x23, 0x28, 0, 0, 0, 1};
    d2k_raw_set_segment_max(1400);

    {
        raw_conn c = make_conn(4);
        reset_recv();
        size_t n = inbound(&c, packet, 1001, TCP_ACK, (const uint8_t *)"abc", 3, NULL, 0);
        queue_packet(packet, n, 0);
        recv_case("valid", &c);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        reset_recv();
        size_t n = inbound(&c, packet, 1001, TCP_RST, NULL, 0, NULL, 0);
        queue_packet(packet, n, 0);
        recv_case("rst", &c);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        reset_recv();
        d2k_poison none;
        memset(&none, 0, sizeof none);
        size_t n = build_ip_tcp(packet, sizeof packet, 4,
                                (const uint8_t *)"\xcb\x00\x71\x09", c.src,
                                443, c.sport, 1001, c.seq, TCP_ACK,
                                (const uint8_t *)"noise", 5, &none, NULL, 0);
        queue_packet(packet, n, 0);
        n = inbound(&c, packet, 1001, TCP_ACK, (const uint8_t *)"abc", 3, NULL, 0);
        queue_packet(packet, n, 0);
        recv_case("noise", &c);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        reset_recv();
        uint8_t short_packet[10] = {0};
        queue_packet(short_packet, sizeof short_packet, 0);
        size_t n = inbound(&c, packet, 1001, TCP_ACK, (const uint8_t *)"abc", 3, NULL, 0);
        queue_packet(packet, n, 0);
        recv_case("short", &c);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        reset_recv();
        queue_error(EAGAIN);
        recv_case("eagain", &c);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        reset_recv();
        queue_error(EINTR);
        recv_case("eintr", &c);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        reset_recv();
        queue_error(EIO);
        recv_case("error", &c);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        reset_recv();
        queue_error(ECONNRESET);
        recv_case("pollerr", &c);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(6);
        reset_recv();
        size_t n = inbound(&c, packet, 1001, TCP_ACK, (const uint8_t *)"abc", 3, NULL, 0);
        queue_packet(packet + 40, n - 40, 1);
        recv_case("v6", &c);
        free_conn(&c);
    }

    {
        raw_conn c = make_conn(4);
        c.ack = 1001;
        reset_recv();
        size_t n = inbound(&c, packet, 1001, TCP_ACK, (const uint8_t *)"abc", 3, NULL, 0);
        queue_packet(packet, n, 0);
        read_case("data", &c, 20);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        c.ack = 1001;
        reset_recv();
        size_t n = inbound(&c, packet, 1001, TCP_RST, NULL, 0, NULL, 0);
        queue_packet(packet, n, 0);
        read_case("rst", &c, 20);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        c.ack = 1001;
        reset_recv();
        test_now = 0;
        read_case("silence", &c, 2);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        c.ack = 1001;
        reset_recv();
        size_t n = inbound(&c, packet, 2441, TCP_ACK, (const uint8_t *)"later", 5, NULL, 0);
        queue_packet(packet, n, 0);
        n = inbound(&c, packet, 1001, TCP_ACK, (const uint8_t *)"start", 5, NULL, 0);
        queue_packet(packet, n, 0);
        read_case("ahead", &c, 20);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        c.ack = 1001;
        reset_recv();
        size_t n = inbound(&c, packet, 999, TCP_ACK, (const uint8_t *)"xxabc", 5, NULL, 0);
        queue_packet(packet, n, 0);
        read_case("overlap", &c, 20);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        c.ack = 1001;
        reset_recv();
        queue_error(EIO);
        read_case("error", &c, 20);
        free_conn(&c);
    }

    {
        raw_conn c = make_conn(4);
        close_count = 0;
        c.rule_up = 0;
        raw_close(&c);
        printf("close|order=%s%s|cleared=%d|fds=%d\n",
               close_count > 0 && close_fds[0] == 10 ? "send" : "",
               close_count > 1 && close_fds[1] == 11 ? ",recv" : "",
               c.buffers == NULL, c.send_fd < 0 && c.recv_fd < 0);
    }

    {
        struct {
            const char *name;
            int family;
            size_t size;
            int short_rc;
            int error;
            int errno_value;
        } cases[] = {
            {"small", 4, 10, -1, 0, 0},
            {"split", 4, 2900, -1, 0, 0},
            {"zero", 4, 0, -1, 0, 0},
            {"enobufs", 4, 20, -1, 1, ENOBUFS},
            {"emsgsize", 4, 20, -1, 1, EMSGSIZE},
            {"eintr", 4, 20, -1, 1, EINTR},
            {"short4", 4, 20, 10, 0, 0},
            {"short6", 6, 20, 10, 0, 0},
        };
        uint8_t payload[3000];
        memset(payload, 0x5a, sizeof payload);
        d2k_poison none;
        memset(&none, 0, sizeof none);
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            raw_conn c = make_conn((uint8_t)cases[i].family);
            sent_count = 0;
            send_calls = 0;
            send_fail = cases[i].error;
            send_errno = cases[i].errno_value;
            send_short = cases[i].short_rc;
            int rc = raw_send(&c, payload, cases[i].size,
                              TCP_PSH | TCP_ACK, &none);
            printf("send|%s|%d|", cases[i].name, rc);
            if (rc == 0) {
                printf("segs=");
                for (int k = 0; k < sent_count; k++) {
                    if (k) printf(",");
                    printf("%u:%zu", (unsigned)(sent_seq[k] - 1000),
                           sent_payload[k]);
                }
            } else if (cases[i].error) {
                printf("errno=%d|segs=", cases[i].errno_value);
            } else {
                printf("errno=short|segs=");
            }
            printf("\n");
            free_conn(&c);
        }
    }

    {
        raw_conn c = make_conn(4);
        reset_recv();
        size_t n = inbound(&c, packet, 7000, TCP_SYN | TCP_ACK, NULL, 0, ts, sizeof ts);
        c.seq = 1000;
        /* SYN-ACK подтверждает наш SYN: ack = seq + 1. */
        wr32(packet + 20 + 8, c.seq + 1);
        packet[20 + 16] = packet[20 + 17] = 0;
        wr16(packet + 20 + 16, tcp_checksum(c.dst, c.src, packet + 20, n - 20));
        queue_packet(packet, n, 0);
        send_fail = 0;
        send_short = -1;
        sent_count = 0;
        handshake_case("v4-success", &c, 50);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        reset_recv();
        size_t n = inbound(&c, packet, 7000, TCP_RST, NULL, 0, NULL, 0);
        queue_packet(packet, n, 0);
        send_fail = 0;
        send_short = -1;
        handshake_case("v4-rst", &c, 50);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        reset_recv();
        send_fail = 1;
        send_errno = ECONNREFUSED;
        send_short = -1;
        handshake_case("refused", &c, 50);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        reset_recv();
        send_fail = 0;
        send_short = -1;
        handshake_case("timeout", &c, 2);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(6);
        reset_recv();
        size_t n = inbound(&c, packet, 7000, TCP_SYN | TCP_ACK, NULL, 0, ts, sizeof ts);
        wr32(packet + 40 + 8, c.seq + 1);
        packet[40 + 16] = packet[40 + 17] = 0;
        wr16(packet + 40 + 16, tcp_checksum_family(6, c.dst, c.src, packet + 40, n - 40));
        queue_packet(packet + 40, n - 40, 1);
        send_fail = 0;
        send_short = -1;
        handshake_case("v6-success", &c, 50);
        free_conn(&c);
    }
    {
        raw_conn c = make_conn(4);
        reset_recv();
        size_t n = inbound(&c, packet, 7000, TCP_SYN | TCP_ACK, NULL, 0, NULL, 0);
        wr32(packet + 20 + 8, c.seq + 1);
        packet[20 + 16] = packet[20 + 17] = 0;
        wr16(packet + 20 + 16, tcp_checksum(c.dst, c.src, packet + 20, n - 20));
        queue_packet(packet, n, 0);
        send_fail = 0;
        send_short = -1;
        handshake_case("no-ts", &c, 50);
        free_conn(&c);
    }
    return 0;
}
