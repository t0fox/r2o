/* C-оракул: точные байты 307-замены и RST из d2k_http80_packet (a378),
 * IPv4 и IPv6. */
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

static void print_hex(const char *label, const uint8_t *bytes, size_t length) {
    printf("%s ", label);
    for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
    printf("\n");
}

static const char GET[] =
    "GET /forum/index.php HTTP/1.1\r\nHost: RuTracker.org:80\r\n"
    "User-Agent: test\r\nAccept: */*\r\n\r\n";
static const char INJECT[] =
    "HTTP/1.1 302 Moved Temporarily\r\nLocation: http://lawfilter.ertelecom.ru\r\n"
    "Connection: close\r\nContent-Length: 13\r\n\r\nlawfilter.ru\n";

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

static flow flow6(uint16_t client_port) {
    flow f;
    memset(&f, 0, sizeof f);
    f.v6 = 1;
    f.client[0] = 0x20; f.client[1] = 0x01; f.client[15] = 0x17;
    f.server[0] = 0x20; f.server[1] = 0x01; f.server[15] = 0xd6;
    f.cport = client_port;
    f.sport = 80;
    return f;
}

static void run(const char *suffix, flow *f) {
    const uint64_t T = 5000 * MS;
    char label[32];
    d2k_http80 *h = d2k_http80_new();
    d2k_http80_set_https(h, "rutracker.org.", 14, T + 3600 * 1000 * MS);

    size_t n = packet(f, 1, F_SYN, CISN, 0, NULL, b);
    d2k_http80_packet(h, b, n, T, 0, out, sizeof out, rst, sizeof rst, &r);
    n = packet(f, 0, F_SYN | F_ACK, SISN, CISN + 1, NULL, b);
    d2k_http80_packet(h, b, n, T + 98 * MS, 0, out, sizeof out, rst, sizeof rst, &r);
    n = packet(f, 1, F_ACK | F_PSH, CISN + 1, SISN + 1, GET, b);
    d2k_http80_packet(h, b, n, T + 99 * MS, 0, out, sizeof out, rst, sizeof rst, &r);

    n = packet(f, 0, F_ACK | F_PSH | F_FIN, SISN + 1,
               CISN + 1 + (uint32_t)strlen(GET), INJECT, b);
    snprintf(label, sizeof label, "input%s", suffix);
    print_hex(label, b, n);
    d2k_http80_packet(h, b, n, T + 99 * MS + 700000ull, 0, out, sizeof out,
                      rst, sizeof rst, &r);
    printf("action%s=%s\n", suffix,
           r.action == D2K_HTTP80_REPLACE ? "replace" : "other");
    snprintf(label, sizeof label, "out%s", suffix);
    print_hex(label, out, r.len);
    snprintf(label, sizeof label, "rst%s", suffix);
    print_hex(label, rst, r.rst_len);
    d2k_http80_free(h);
}

int main(void) {
    flow f4 = flow4(51500);
    run("", &f4);
    flow f6 = flow6(51600);
    run("6", &f6);
    return 0;
}
