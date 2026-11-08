/* D17: C-оракул HTTP/80 replacement: PASS/REPLACE/DROP и portal/injection. */
#define _POSIX_C_SOURCE 200809L
#include "d2k_http80.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MS 1000000ull
#define F_FIN 0x01
#define F_SYN 0x02
#define F_PSH 0x08
#define F_ACK 0x10
#define CISN 1000u
#define SISN 5000000u

typedef struct {
    int v6;
    uint8_t client[16], server[16];
    uint16_t cport, sport;
} flow;

static uint8_t b[4096], out[2048], rst[128];
static d2k_http80_res r;

static void wr16(uint8_t *p, unsigned v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static size_t packet(const flow *f, int to_server, uint8_t flags, uint32_t seq,
                     uint32_t ack, const char *payload, uint8_t *o) {
    size_t length = payload ? strlen(payload) : 0;
    size_t ip = f->v6 ? 40 : 20;
    size_t total = ip + 20 + length;
    memset(o, 0, total);
    const uint8_t *source = to_server ? f->client : f->server;
    const uint8_t *destination = to_server ? f->server : f->client;
    if (f->v6) {
        o[0] = 0x60;
        wr16(o + 4, (unsigned)(20 + length));
        o[6] = 6;
        o[7] = 55;
        memcpy(o + 8, source, 16);
        memcpy(o + 24, destination, 16);
    } else {
        o[0] = 0x45;
        wr16(o + 2, (unsigned)total);
        wr16(o + 4, 0x1234);
        o[8] = 55;
        o[9] = 6;
        memcpy(o + 12, source, 4);
        memcpy(o + 16, destination, 4);
    }
    uint8_t *tcp = o + ip;
    wr16(tcp, to_server ? f->cport : f->sport);
    wr16(tcp + 2, to_server ? f->sport : f->cport);
    wr32(tcp + 4, seq);
    wr32(tcp + 8, ack);
    tcp[12] = 0x50;
    tcp[13] = flags;
    wr16(tcp + 14, 64240);
    if (length) memcpy(tcp + 20, payload, length);
    return total;
}

static flow flow4(uint16_t client_port) {
    flow f;
    memset(&f, 0, sizeof f);
    const uint8_t client[4] = { 192, 168, 1, 117 };
    const uint8_t server[4] = { 195, 82, 146, 214 };
    memcpy(f.client, client, 4);
    memcpy(f.server, server, 4);
    f.cport = client_port;
    f.sport = 80;
    return f;
}

static const char GET[] =
    "GET /forum/index.php HTTP/1.1\r\nHost: RuTracker.org:80\r\n"
    "User-Agent: test\r\nAccept: */*\r\n\r\n";
static const char INJECT[] =
    "HTTP/1.1 302 Moved Temporarily\r\nLocation: http://lawfilter.ertelecom.ru\r\n"
    "Connection: close\r\nContent-Length: 13\r\n\r\nlawfilter.ru\n";

static void open_flow(d2k_http80 *h, const flow *f, uint64_t t0) {
    size_t n = packet(f, 1, F_SYN, CISN, 0, NULL, b);
    d2k_http80_packet(h, b, n, t0, 0, out, sizeof out, rst, sizeof rst, &r);
    n = packet(f, 0, F_SYN | F_ACK, SISN, CISN + 1, NULL, b);
    d2k_http80_packet(h, b, n, t0 + 98 * MS, 0, out, sizeof out, rst, sizeof rst, &r);
    n = packet(f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    d2k_http80_packet(h, b, n, t0 + 99 * MS, 0, out, sizeof out, rst, sizeof rst, &r);
}

static void feed_inject(d2k_http80 *h, const flow *f, uint64_t now) {
    size_t n = packet(f, 0, F_ACK | F_PSH | F_FIN, SISN + 1,
                      CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    d2k_http80_packet(h, b, n, now, 0, out, sizeof out, rst, sizeof rst, &r);
}

static const char *action_name(int action) {
    switch (action) {
    case D2K_HTTP80_PASS: return "pass";
    case D2K_HTTP80_REPLACE: return "replace";
    case D2K_HTTP80_DROP: return "drop";
    default: return "other";
    }
}

static void print_result(const char *label) {
    printf("D17 %s action=%s portal=%d\n", label, action_name(r.action), r.injection);
}

typedef struct {
    int fail_verdict, payload_calls, accept_calls, rst_calls;
    size_t payload_len;
} fake_io;

static int io_payload(void *ctx, const uint8_t *packet, size_t length) {
    (void)packet;
    (void)length;
    fake_io *io = ctx;
    io->payload_calls++;
    io->payload_len = length;
    return io->fail_verdict ? -1 : 0;
}

static int io_accept(void *ctx) {
    ((fake_io *)ctx)->accept_calls++;
    return 0;
}

static int io_rst(void *ctx, const uint8_t *packet, size_t length) {
    (void)packet;
    (void)length;
    ((fake_io *)ctx)->rst_calls++;
    return 0;
}

int main(void) {
    const uint64_t T = 5000 * MS;

    {
        d2k_http80 *h = d2k_http80_new();
        flow f = flow4(51000);
        open_flow(h, &f, T);
        feed_inject(h, &f, T + 99 * MS + 700000ull);
        print_result("no-https");
        d2k_http80_free(h);
    }

    d2k_http80 *h = d2k_http80_new();
    flow f = flow4(51500);
    d2k_http80_set_https(h, "rutracker.org.", 14, T + 3600 * 1000 * MS);
    open_flow(h, &f, T);
    feed_inject(h, &f, T + 99 * MS + 700000ull);
    print_result("https");
    d2k_http80_res https_result = r;

    {
        d2k_http80 *slow = d2k_http80_new();
        flow slow_flow = flow4(52000);
        open_flow(slow, &slow_flow, T);
        feed_inject(slow, &slow_flow, T + 99 * MS + 120 * MS);
        print_result("slow");
        d2k_http80_free(slow);
    }

    {
        d2k_http80 *duplicate = d2k_http80_new();
        flow duplicate_flow = flow4(52500);
        open_flow(duplicate, &duplicate_flow, T);
        feed_inject(duplicate, &duplicate_flow, T + 99 * MS + 700000ull);
        feed_inject(duplicate, &duplicate_flow, T + 99 * MS + 900000ull);
        print_result("duplicate");
        d2k_http80_free(duplicate);
    }

    {
        d2k_http80_res keep = https_result;
        fake_io io = { 0, 0, 0, 0, 0 };
        d2k_http80_io callbacks = { io_payload, io_accept, io_rst, &io };
        d2k_http80_swap(h, &keep, out, rst, &callbacks);
        size_t n = packet(&f, 0, F_ACK | F_PSH,
                          SISN + 1 + (uint32_t)strlen(INJECT),
                          CISN + 1 + (uint32_t)strlen(GET), "late", b);
        d2k_http80_packet(h, b, n, T + 99 * MS + 120 * MS, 0, out, sizeof out,
                          rst, sizeof rst, &r);
        printf("D17 post-server action=%s\n", action_name(r.action));
        n = packet(&f, 1, F_ACK, CISN + 1 + (uint32_t)strlen(GET),
                   SISN + 1 + (uint32_t)strlen(INJECT), NULL, b);
        d2k_http80_packet(h, b, n, T + 99 * MS + 121 * MS, 0, out, sizeof out,
                          rst, sizeof rst, &r);
        printf("D17 post-client action=%s\n", action_name(r.action));
    }
    d2k_http80_free(h);
    return 0;
}
