/* control_v22_legacy_events — C-стенд без NFQUEUE для S15.
 *
 * Поднимает настоящий управляющий сокет с production d2k_ctlsrv_command и
 * d2k_session, но пакеты собирает по stdin. После каждого пакета вызывает
 * d2k_ctlsrv_pump, поэтому R2O-контроллер получает реальные HELLO/SUSPECT/
 * EXCHANGE, а не синтетические кадры.
 *
 * stdin: hello <имя> | reply <тип> | rst | rst-same | quit
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "d2k_ctl.h"
#include "d2k_ctlsrv.h"

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static size_t build_hello(uint8_t *out, const char *sni) {
    uint8_t body[512];
    size_t b = 0;
    body[b++] = 0x03;
    body[b++] = 0x03;
    for (int i = 0; i < 32; i++) {
        body[b++] = (uint8_t)i;
    }
    body[b++] = 0;
    body[b++] = 0x00;
    body[b++] = 0x02;
    body[b++] = 0x13;
    body[b++] = 0x01;
    body[b++] = 0x01;
    body[b++] = 0x00;

    size_t nl = strlen(sni);
    uint8_t ext[320];
    size_t e = 0;
    ext[e++] = 0x00;
    ext[e++] = 0x00;
    ext[e++] = 0x00;
    ext[e++] = (uint8_t)(5 + nl);
    ext[e++] = 0x00;
    ext[e++] = (uint8_t)(3 + nl);
    ext[e++] = 0x00;
    ext[e++] = 0x00;
    ext[e++] = (uint8_t)nl;
    memcpy(ext + e, sni, nl);
    e += nl;
    body[b++] = 0x00;
    body[b++] = (uint8_t)e;
    memcpy(body + b, ext, e);
    b += e;

    size_t o = 0;
    out[o++] = 0x16;
    out[o++] = 0x03;
    out[o++] = 0x01;
    out[o++] = (uint8_t)((b + 4) >> 8);
    out[o++] = (uint8_t)(b + 4);
    out[o++] = 0x01;
    out[o++] = 0x00;
    out[o++] = (uint8_t)(b >> 8);
    out[o++] = (uint8_t)b;
    memcpy(out + o, body, b);
    o += b;
    return o;
}

static size_t build_pkt(uint8_t *o, int reverse, uint16_t port, uint8_t flags,
                        uint8_t ttl, const uint8_t *pay, size_t paylen) {
    size_t total = 20 + 20 + paylen;
    memset(o, 0, total);
    o[0] = 0x45;
    wr16(o + 2, (uint16_t)total);
    o[8] = ttl;
    o[9] = 6;
    uint8_t lan[4] = {192, 168, 1, 67}, wan[4] = {93, 184, 216, 34};
    memcpy(o + 12, reverse ? wan : lan, 4);
    memcpy(o + 16, reverse ? lan : wan, 4);
    wr16(o + 20, reverse ? 443 : port);
    wr16(o + 22, reverse ? port : 443);
    wr32(o + 24, 1000);
    wr32(o + 28, 2000);
    o[32] = 0x50;
    o[33] = flags;
    wr16(o + 34, 64240);
    if (paylen) {
        memcpy(o + 40, pay, paylen);
    }
    return total;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc != 2) {
        fprintf(stderr, "использование: %s <сокет>\n", argv[0]);
        return 2;
    }
    char err[200];
    d2k_ctl *ctl = d2k_ctl_open(argv[1], err, sizeof err);
    if (!ctl) {
        fprintf(stderr, "сокет: %s\n", err);
        return 1;
    }
    d2k_session *sess = d2k_session_new(64, 128);
    if (!sess) {
        return 1;
    }
    d2k_ctlsrv cx;
    memset(&cx, 0, sizeof cx);
    cx.sess = sess;
    cx.ctl = ctl;
    d2k_ctl_set_disconnect_hook(ctl, d2k_ctlsrv_peer_closed, &cx);
    cx.send_limits = D2K_RAW_CANT_IPID | D2K_RAW_CANT_IPSUM;

    uint64_t now = 1000;
    uint16_t port = 40000;
    uint64_t seen = 0;
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("готов\n");

    for (;;) {
        struct pollfd p[3];
        nfds_t n = 0;
        p[n].fd = 0;
        p[n].events = POLLIN;
        p[n].revents = 0;
        n++;
        p[n].fd = d2k_ctl_listen_fd(ctl);
        p[n].events = POLLIN;
        p[n].revents = 0;
        n++;
        int peer = d2k_ctl_peer_fd(ctl);
        nfds_t ip = (nfds_t)-1;
        if (peer >= 0) {
            p[n].fd = peer;
            p[n].events = POLLIN;
            p[n].revents = 0;
            ip = n;
            n++;
        }
        if (poll(p, n, 200) < 0 && errno != EINTR) {
            break;
        }
        if (p[1].revents & POLLIN) {
            d2k_ctl_accept(ctl);
            d2k_ctlsrv_greet(ctl, 0u);
            d2k_ctl_flush(ctl);
        }
        if (ip != (nfds_t)-1 && (p[ip].revents & (POLLIN | POLLHUP))) {
            cx.now_ns = now++;
            d2k_ctl_poll(ctl, d2k_ctlsrv_command, &cx);
            d2k_ctl_flush(ctl);
        }
        if (p[0].revents & (POLLIN | POLLHUP)) {
            char line[512];
            if (!fgets(line, sizeof line, stdin)) {
                break;
            }
            line[strcspn(line, "\r\n")] = '\0';
            uint8_t pkt[2048], buf[4096];
            d2k_result r;
            memset(&r, 0, sizeof r);
            if (strncmp(line, "hello ", 6) == 0) {
                uint8_t hello[1024];
                size_t hl = build_hello(hello, line + 6);
                port++;
                size_t sz = build_pkt(pkt, 0, port, 0x02, 64, NULL, 0);
                d2k_session_packet(sess, pkt, sz, now++, buf, sizeof buf, &r);
                sz = build_pkt(pkt, 1, port, 0x12, 124, NULL, 0);
                d2k_session_packet(sess, pkt, sz, now++, buf, sizeof buf, &r);
                sz = build_pkt(pkt, 0, port, 0x18, 64, hello, hl);
                d2k_session_packet(sess, pkt, sz, now++, buf, sizeof buf, &r);
                printf("hello %s\n", line + 6);
            } else if (strncmp(line, "reply ", 6) == 0) {
                uint8_t rec[64];
                memset(rec, 0, sizeof rec);
                rec[0] = (uint8_t)atoi(line + 6);
                rec[1] = 0x03;
                rec[2] = 0x03;
                rec[3] = 0x00;
                rec[4] = 0x2A;
                if (rec[0] == 0x16) {
                    rec[5] = 0x02;
                    rec[6] = 0x00;
                    rec[7] = 0x00;
                    rec[8] = 0x26;
                }
                size_t sz = build_pkt(pkt, 1, port, 0x18, 124, rec, sizeof rec);
                d2k_session_packet(sess, pkt, sz, now++, buf, sizeof buf, &r);
                printf("reply %u\n", (unsigned)rec[0]);
            } else if (strcmp(line, "rst") == 0 || strcmp(line, "rst-same") == 0) {
                uint8_t ttl = strcmp(line, "rst-same") == 0 ? 124 : 127;
                size_t sz = build_pkt(pkt, 1, port, 0x14, ttl, NULL, 0);
                d2k_session_packet(sess, pkt, sz, now++, buf, sizeof buf, &r);
                printf("rst ttl=%u\n", (unsigned)ttl);
            } else if (strcmp(line, "quit") == 0) {
                break;
            }
            d2k_ctlsrv_pump(ctl, sess, &seen);
            d2k_ctl_flush(ctl);
        }
        d2k_ctlsrv_pump(ctl, sess, &seen);
        d2k_ctl_flush(ctl);
    }
    return 0;
}
