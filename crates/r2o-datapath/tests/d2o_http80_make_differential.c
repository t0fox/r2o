/* C/Rust differential: d2k_http80_make eviction (datapath/http80.c:217-236). */
#include <stdio.h>
#include <string.h>

#include "d2k_http80.h"

#define MS 1000000ull
#define F_FIN 0x01
#define F_SYN 0x02
#define F_PSH 0x08
#define F_ACK 0x10
#define CISN 1000u
#define SISN 5000000u

typedef struct {
    uint8_t client[4], server[4];
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
    size_t total = 20 + 20 + length;
    memset(o, 0, total);
    const uint8_t *source = to_server ? f->client : f->server;
    const uint8_t *destination = to_server ? f->server : f->client;
    o[0] = 0x45;
    wr16(o + 2, (unsigned)total);
    wr16(o + 4, 0x1234);
    o[8] = 55;
    o[9] = 6;
    memcpy(o + 12, source, 4);
    memcpy(o + 16, destination, 4);
    uint8_t *tcp = o + 20;
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
static void open_flow(d2k_http80 *h, const flow *f, uint64_t t0) {
    size_t n = packet(f, 1, F_SYN, CISN, 0, NULL, b);
    d2k_http80_packet(h, b, n, t0, 0, out, sizeof out, rst, sizeof rst, &r);
    n = packet(f, 0, F_SYN | F_ACK, SISN, CISN + 1, NULL, b);
    d2k_http80_packet(h, b, n, t0 + 98 * MS, 0, out, sizeof out, rst, sizeof rst, &r);
    n = packet(f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    d2k_http80_packet(h, b, n, t0 + 99 * MS, 0, out, sizeof out, rst, sizeof rst, &r);
}

int main(void) {
    const uint64_t T = 5000 * MS;
    d2k_http80 *h = d2k_http80_new();
    for (unsigned index = 0; index < 129; index++) {
        flow f = flow4((uint16_t)(40000 + index));
        open_flow(h, &f, T);
    }
    d2k_http80_stats stats = d2k_http80_get_stats(h);
    printf("make evicted=%llu requests=%llu\n",
           (unsigned long long)stats.evicted,
           (unsigned long long)stats.requests);
    d2k_http80_free(h);
    return 0;
}
