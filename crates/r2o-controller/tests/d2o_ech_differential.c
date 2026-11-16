/* C-оракул ECH-контрактов core/tls13.c и core/verify.c.
 *
 * Включает production tls13.c (d2k_tls_connect_ech, d2k_tls_ech_accepted) и
 * линкует production verify.o (d2k_verify_probe_ech_on,
 * d2k_verify_probe_ech_origin_on). Сеть заменена loopback-стендом, а HTTPS-RR
 * для origin_on отдаёт локальный UDP-DNS на 127.0.0.1:53; поэтому скрипт
 * запускает фикстуру в `unshare -rmn` с подменённым /etc/resolv.conf.
 *
 * Печатает только поля/коды/reason, которые сравниваются с Rust.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "tls13.c"

#include "d2k_crypto.h"
#include "d2k_hello.h"
#include "d2k_tls13core.h"
#include "d2k_verify.h"

static void fixture_put16(uint8_t *p, unsigned value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static unsigned fixture_rd16(const uint8_t *p) {
    return ((unsigned)p[0] << 8) | p[1];
}

static int unhex(const char *s, uint8_t *out, size_t cap, size_t *len) {
    size_t n = strlen(s);
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v = 0;
        for (size_t j = 0; j < 2; j++) {
            unsigned char c = (unsigned char)s[2 * i + j];
            unsigned d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else return -1;
            v = v * 16 + d;
        }
        out[i] = (uint8_t)v;
    }
    *len = n / 2;
    return 0;
}

static int fd_open(int fd) {
    return fcntl(fd, F_GETFD) >= 0;
}

static const char *fd_state(int fd) {
    return fd >= 0 && fd_open(fd) ? "open" : "closed";
}

static void print_outcome(const char *label, const d2k_ver_result *r) {
    printf("%s level=%d name=%d ech=%d status=%d complete=%d body=%llu fd=%s reason=%s\n",
           label, r->level, r->name_ok, r->ech_accepted, (int)r->status,
           r->body_complete ? 1 : 0, (unsigned long long)r->body_bytes,
           fd_state(r->fd), r->reason);
}

static void print_reason_prefix(const char *label, const d2k_ver_result *r) {
    char prefix[64];
    size_t n = 0;
    while (r->reason[n] && r->reason[n] != ':' && n + 1 < sizeof prefix) {
        prefix[n] = r->reason[n];
        n++;
    }
    prefix[n] = 0;
    printf("%s level=%d name=%d ech=%d status=%d complete=%d body=%llu fd=%s reason=%s\n",
           label, r->level, r->name_ok, r->ech_accepted, (int)r->status,
           r->body_complete ? 1 : 0, (unsigned long long)r->body_bytes,
           fd_state(r->fd), prefix);
}

static int new_bound_fd(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int new_fake_fd(void) {
    return dup(STDOUT_FILENO);
}

struct tls_stand {
    int lfd;
    uint16_t port;
    pthread_t thread;
};

static void *tls_stand_run(void *context) {
    struct tls_stand *stand = context;
    int client = accept(stand->lfd, NULL, NULL);
    if (client < 0) return NULL;
    struct timeval timeout = {2, 0};
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    uint8_t bytes[4096];
    (void)recv(client, bytes, sizeof bytes, 0);
    close(client);
    return NULL;
}

static int tls_stand_start(struct tls_stand *stand) {
    memset(stand, 0, sizeof *stand);
    stand->lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (stand->lfd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof a;
    if (bind(stand->lfd, (struct sockaddr *)&a, sizeof a) != 0 ||
        listen(stand->lfd, 1) != 0 ||
        getsockname(stand->lfd, (struct sockaddr *)&a, &length) != 0) {
        close(stand->lfd);
        return -1;
    }
    stand->port = ntohs(a.sin_port);
    return pthread_create(&stand->thread, NULL, tls_stand_run, stand);
}

static void tls_stand_stop(struct tls_stand *stand) {
    pthread_join(stand->thread, NULL);
    close(stand->lfd);
}

struct dns_stand {
    int fd;
    const uint8_t *config;
    size_t config_len;
    pthread_t thread;
};

static void *dns_stand_run(void *context) {
    struct dns_stand *stand = context;
    uint8_t query[512];
    uint8_t reply[2048];
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof peer;
    ssize_t query_len = recvfrom(stand->fd, query, sizeof query, 0,
                                 (struct sockaddr *)&peer, &peer_len);
    if (query_len < 12) return NULL;
    memcpy(reply, query, (size_t)query_len);
    reply[2] = 0x81;
    reply[3] = 0x80;
    reply[6] = 0;
    reply[7] = 1;
    memset(reply + 8, 0, 4);
    size_t p = (size_t)query_len;
    reply[p++] = 0xc0;
    reply[p++] = 0x0c;
    fixture_put16(reply + p, 65);
    p += 2;
    fixture_put16(reply + p, 1);
    p += 2;
    fixture_put16(reply + p, 60);
    p += 4;
    size_t rdata_len_at = p;
    p += 2;
    fixture_put16(reply + p, 1);
    p += 2;
    reply[p++] = 0;
    fixture_put16(reply + p, 5);
    p += 2;
    fixture_put16(reply + p, (unsigned)stand->config_len);
    p += 2;
    memcpy(reply + p, stand->config, stand->config_len);
    p += stand->config_len;
    fixture_put16(reply + rdata_len_at, (unsigned)(p - rdata_len_at - 2));
    sendto(stand->fd, reply, p, 0, (struct sockaddr *)&peer, peer_len);
    return NULL;
}

static int dns_stand_start(struct dns_stand *stand, const uint8_t *config,
                           size_t config_len) {
    memset(stand, 0, sizeof *stand);
    stand->config = config;
    stand->config_len = config_len;
    stand->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (stand->fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(53);
    if (bind(stand->fd, (struct sockaddr *)&a, sizeof a) != 0) {
        close(stand->fd);
        return -1;
    }
    return pthread_create(&stand->thread, NULL, dns_stand_run, stand);
}

static void dns_stand_stop(struct dns_stand *stand) {
    pthread_join(stand->thread, NULL);
    close(stand->fd);
}

struct capture_stand {
    int fd;
    uint8_t bytes[8192];
    size_t length;
    pthread_t thread;
};

static void *capture_run(void *context) {
    struct capture_stand *stand = context;
    struct timeval timeout = {2, 0};
    setsockopt(stand->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    while (stand->length < sizeof stand->bytes) {
        ssize_t n = recv(stand->fd, stand->bytes + stand->length,
                         sizeof stand->bytes - stand->length, 0);
        if (n <= 0) break;
        stand->length += (size_t)n;
        if (stand->length >= 5 && fixture_rd16(stand->bytes + 3) + 5 <= stand->length) break;
    }
    close(stand->fd);
    return NULL;
}

static int hello_extension(const uint8_t *hello, size_t length, unsigned wanted,
                           const uint8_t **data, size_t *data_len) {
    if (length < 4 + 2 + 32 + 1) return -1;
    size_t p = 4 + 2 + 32;
    if (p >= length) return -1;
    size_t sid = hello[p++];
    if (p + sid + 2 > length) return -1;
    p += sid;
    if (p + 2 > length) return -1;
    size_t ciphers = fixture_rd16(hello + p);
    p += 2;
    if (p + ciphers + 1 > length) return -1;
    p += ciphers;
    size_t compression = hello[p++];
    if (p + compression + 2 > length) return -1;
    p += compression;
    size_t extensions = fixture_rd16(hello + p);
    p += 2;
    size_t end = p + extensions;
    if (end > length) return -1;
    while (p + 4 <= end) {
        unsigned kind = fixture_rd16(hello + p);
        size_t size = fixture_rd16(hello + p + 2);
        p += 4;
        if (p + size > end) return -1;
        if (kind == wanted) {
            *data = hello + p;
            *data_len = size;
            return 0;
        }
        p += size;
    }
    return -1;
}

static void print_hello(const uint8_t *record, size_t length) {
    const uint8_t *body = record + 5;
    size_t body_len = length - 5;
    const uint8_t *data = NULL;
    size_t data_len = 0;
    char alpn[128] = "";
    if (hello_extension(body, body_len, 0x0010, &data, &data_len) == 0 &&
        data_len >= 3) {
        size_t list_len = fixture_rd16(data);
        size_t at = 2;
        while (at + 1 <= 2 + list_len && at + 1 + data[at] <= data_len) {
            size_t n = data[at];
            if (n && n + 1 < sizeof alpn) {
                memcpy(alpn, data + at + 1, n);
                alpn[n] = 0;
            }
            break;
        }
    }
    size_t sni_off = 0, sni_len = 0;
    const char *sni = "";
    char sni_buf[256] = "";
    if (d2k_hello_sni(record, length, &sni_off, &sni_len) == 0 && sni_len < sizeof sni_buf) {
        memcpy(sni_buf, record + sni_off, sni_len);
        sni_buf[sni_len] = 0;
        sni = sni_buf;
    }
    uint8_t config_id = 0;
    int ech = d2k_hello_ech_offer(record, length, &config_id);
    char ciphers[128] = "";
    size_t cipher_at = 4 + 2 + 32;
    size_t sid = body[cipher_at];
    cipher_at += 1 + sid;
    size_t cipher_bytes = fixture_rd16(body + cipher_at);
    cipher_at += 2;
    for (size_t i = 0; i + 1 < cipher_bytes; i += 2) {
        char item[16];
        snprintf(item, sizeof item, "%s%04x", i ? "," : "", fixture_rd16(body + cipher_at + i));
        strncat(ciphers, item, sizeof ciphers - strlen(ciphers) - 1);
    }
    char groups[128] = "";
    if (hello_extension(body, body_len, 0x000a, &data, &data_len) == 0 && data_len >= 2) {
        size_t n = fixture_rd16(data);
        for (size_t i = 2; i + 1 < 2 + n && i + 1 < data_len; i += 2) {
            char item[16];
            snprintf(item, sizeof item, "%s%04x", i > 2 ? "," : "", fixture_rd16(data + i));
            strncat(groups, item, sizeof groups - strlen(groups) - 1);
        }
    }
    char keyshare[128] = "";
    if (hello_extension(body, body_len, 0x0033, &data, &data_len) == 0 && data_len >= 2) {
        size_t list = fixture_rd16(data);
        size_t at = 2;
        size_t end = 2 + list;
        if (end > data_len) end = data_len;
        while (at + 4 <= end) {
            char item[16];
            snprintf(item, sizeof item, "%s%04x", at > 2 ? "," : "", fixture_rd16(data + at));
            strncat(keyshare, item, sizeof keyshare - strlen(keyshare) - 1);
            at += 4 + fixture_rd16(data + at + 2);
        }
    }
    int tls13 = d2k_hello_shape(record, length) == D2K_SHAPE_MODERN;
    int tls12 = 0;
    if (hello_extension(body, body_len, 0x002b, &data, &data_len) == 0 && data_len >= 1) {
        size_t n = data[0];
        for (size_t i = 1; i + 1 < 1 + n && i + 1 < data_len; i += 2) {
            if (fixture_rd16(data + i) == 0x0303) tls12 = 1;
        }
    }
    printf("hello tls13=%d tls12=%d alpn=%s sni=%s ech=%d ech_id=%u cipher=%s groups=%s keyshare=%s\n",
           tls13, tls12, alpn, sni, ech, (unsigned)config_id, ciphers, groups, keyshare);
}

int main(void) {
    const char *hex =
        "0045fe0d004137002000200d1bbf3935b6317f6bc0a07894ba03bb3c32dc86758dcf67fef797a98360c97b0004000100010012636c6f7564666c6172652d6563682e636f6d0000";
    uint8_t list[1024];
    size_t list_len = 0;
    if (unhex(hex, list, sizeof list, &list_len)) return 2;
    d2k_ech_config config;
    if (d2k_ech_config_parse(list, list_len, &config)) return 2;
    d2k_ver_result r;

    int fake = new_fake_fd();
    if (fake < 0) return 2;
    r = d2k_verify_probe_ech_on(fake, "127.0.0.1", 9, "echo.test", NULL,
                                1000, 0, 0, NULL);
    print_outcome("guard config_null", &r);

    fake = new_fake_fd();
    if (fake < 0) return 2;
    r = d2k_verify_probe_ech_on(fake, "127.0.0.1", 9, NULL, &config,
                                1000, 0, 0, NULL);
    print_outcome("guard origin_null", &r);

    fake = new_fake_fd();
    if (fake < 0) return 2;
    r = d2k_verify_probe_ech_on(fake, "127.0.0.1", 9, "", &config,
                                1000, 0, 0, NULL);
    print_outcome("guard origin_empty", &r);

    fake = new_fake_fd();
    if (fake < 0) return 2;
    r = d2k_verify_probe_ech_on(fake, "127.0.0.1", 9, "echo.test", &config,
                                1000, 0, 0, "/../escape.css");
    print_outcome("guard path", &r);

    fake = new_fake_fd();
    if (fake < 0) return 2;
    r = d2k_verify_probe_ech_on(fake, "127.0.0.1", 9, "bad host", &config,
                                1000, 0, 0, NULL);
    print_outcome("guard host", &r);

    fake = new_fake_fd();
    if (fake < 0) return 2;
    r = d2k_verify_probe_ech_origin_on(fake, "127.0.0.1", 9, NULL, "origin.example",
                                       1000, 0, 0, NULL);
    print_outcome("origin outer_null", &r);

    fake = new_fake_fd();
    if (fake < 0) return 2;
    r = d2k_verify_probe_ech_origin_on(fake, "127.0.0.1", 9, "cloudflare-ech.com", NULL,
                                       1000, 0, 0, NULL);
    print_outcome("origin origin_null", &r);

    struct dns_stand dns;
    if (dns_stand_start(&dns, list, list_len) != 0) {
        fprintf(stderr, "не удалось поднять DNS-стенд на 127.0.0.1:53\n");
        return 2;
    }
    fake = new_fake_fd();
    if (fake < 0) return 2;
    r = d2k_verify_probe_ech_origin_on(fake, "127.0.0.1", 9, "other.example",
                                       "origin.example", 1000, 0, 0, NULL);
    dns_stand_stop(&dns);
    print_outcome("origin mismatch", &r);

    struct tls_stand tls;
    if (tls_stand_start(&tls) != 0) return 2;
    r = d2k_verify_probe_ech_on(-1, "127.0.0.1", tls.port, "echo.test", &config,
                                1000, 0, 0, NULL);
    tls_stand_stop(&tls);
    print_reason_prefix("ech use_fd_none_tls", &r);
    if (r.fd >= 0) close(r.fd);

    int closed_port = socket(AF_INET, SOCK_STREAM, 0);
    if (closed_port < 0) return 2;
    struct sockaddr_in closed_addr;
    memset(&closed_addr, 0, sizeof closed_addr);
    closed_addr.sin_family = AF_INET;
    closed_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t closed_len = sizeof closed_addr;
    if (bind(closed_port, (struct sockaddr *)&closed_addr, sizeof closed_addr) != 0 ||
        getsockname(closed_port, (struct sockaddr *)&closed_addr, &closed_len) != 0) {
        close(closed_port);
        return 2;
    }
    close(closed_port);
    r = d2k_verify_probe_ech_on(-1, "127.0.0.1", ntohs(closed_addr.sin_port),
                                "echo.test", &config, 1000, 0, 0, NULL);
    print_outcome("ech use_fd_none_refused", &r);

    if (tls_stand_start(&tls) != 0) return 2;
    int bound = new_bound_fd();
    if (bound < 0) return 2;
    r = d2k_verify_probe_ech_on(bound, "127.0.0.1", tls.port, "echo.test", &config,
                                1000, 0, 0, NULL);
    tls_stand_stop(&tls);
    print_reason_prefix("ech use_fd_bound", &r);
    if (r.fd >= 0) close(r.fd);

    if (dns_stand_start(&dns, list, list_len) != 0) return 2;
    if (tls_stand_start(&tls) != 0) return 2;
    bound = new_bound_fd();
    if (bound < 0) return 2;
    r = d2k_verify_probe_ech_origin_on(bound, "127.0.0.1", tls.port,
                                       "cloudflare-ech.com", "origin.example",
                                       1000, 0, 0, NULL);
    dns_stand_stop(&dns);
    tls_stand_stop(&tls);
    print_reason_prefix("origin use_fd_bound", &r);
    if (r.fd >= 0) close(r.fd);

    d2k_tls *tls_session = NULL;
    char error[160] = "";
    int rc = d2k_tls_connect_ech(-1, "", &config, 1000, 0, &tls_session,
                                 error, sizeof error);
    printf("tls origin_empty code=%d reason=%s\n", rc, error);

    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 2;
    struct capture_stand capture;
    memset(&capture, 0, sizeof capture);
    capture.fd = pair[1];
    if (pthread_create(&capture.thread, NULL, capture_run, &capture) != 0) return 2;
    rc = d2k_tls_connect_ech(pair[0], "echo.test", &config, 1000, 0,
                             &tls_session, error, sizeof error);
    pthread_join(capture.thread, NULL);
    close(pair[0]);
    print_hello(capture.bytes, capture.length);

    d2k_tls echo = {0};
    d2k_tls no_echo = {0};
    no_echo.ech_accepted = 0;
    echo.ech_accepted = 1;
    printf("accepted null=%d off=%d on=%d\n",
           d2k_tls_ech_accepted(NULL), d2k_tls_ech_accepted(&no_echo),
           d2k_tls_ech_accepted(&echo));
    return 0;
}
