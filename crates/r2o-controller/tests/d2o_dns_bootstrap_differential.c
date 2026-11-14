/* C/Rust differential: DNS bootstrap (current main runtime/d2k_dns_config.c).
 * Без аргументов — encode/skip/response vectors.
 * --loopback — UDP/53 сервер на 127.0.0.1: A/AAAA/timeout (запускать в
 * unshare -Urn, где можно занять порт 53). */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_dns_config.c"

static void hex(FILE *f, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) fprintf(f, "%02x", data[i]);
}

static void vectors(void) {
    const char *names[] = {
        "Example.COM", "a-b.example", "", "a..b", ".a", "a_b", "a b",
        "abcdefghijklmnopqrstuvwxyz.ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    };
    printf("{\"encode\":[");
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        uint8_t out[256] = {0};
        size_t used = 0;
        int ok = dns_name_encode(names[i], out, sizeof out, &used);
        printf("%s{\"name\":\"%s\",\"ok\":%s,\"hex\":\"", i ? "," : "",
               names[i], ok ? "true" : "false");
        if (ok) hex(stdout, out, used);
        printf("\"}");
    }
    printf("],\"skip\":[");
    const struct { const char *hexbytes; size_t len; } skips[] = {
        {"036f6e650374776f007461696c", 11},
        {"036f6e65c00600", 7},
        {"c000", 2},
        {"c0ff", 2},
    };
    for (size_t i = 0; i < sizeof skips / sizeof skips[0]; i++) {
        uint8_t packet[64];
        size_t len = 0;
        for (size_t j = 0; j < skips[i].len; j++) {
            unsigned value;
            sscanf(skips[i].hexbytes + 2 * j, "%2x", &value);
            packet[j] = (uint8_t)value;
            len++;
        }
        size_t offset = 0;
        int ok = dns_skip_name(packet, len, &offset);
        printf("%s{\"case\":%zu,\"ok\":%s,\"offset\":%zu}", i ? "," : "", i,
               ok ? "true" : "false", offset);
    }
    printf("],\"response\":[");

    uint8_t qname[256];
    size_t qname_len = 0;
    dns_name_encode("bootstrap.example", qname, sizeof qname, &qname_len);
    uint8_t base[256];
    size_t base_len = 0;
    uint16_t id = 0x1234;
    base[base_len++] = (uint8_t)(id >> 8);
    base[base_len++] = (uint8_t)id;
    base[base_len++] = 0x81;
    base[base_len++] = 0x80;
    base[base_len++] = 0;
    base[base_len++] = 1;
    base[base_len++] = 0;
    base[base_len++] = 1;
    for (int i = 0; i < 4; i++) base[base_len++] = 0;
    memcpy(base + base_len, qname, qname_len);
    base_len += qname_len;
    base[base_len++] = 0;
    base[base_len++] = 1;
    base[base_len++] = 0;
    base[base_len++] = 1;

    const struct {
        const char *name;
        uint16_t qtype;
        int tc;
        int rcode;
        uint16_t klass;
        int wrong_id;
        uint8_t address[16];
        size_t address_len;
    } cases[] = {
        {"a", 1, 0, 0, 1, 0, {203, 0, 113, 7}, 4},
        {"aaaa", 28, 0, 0, 1, 0,
         {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}, 16},
        {"wrong_id", 1, 0, 0, 1, 1, {203, 0, 113, 7}, 4},
        {"tc", 1, 1, 0, 1, 0, {203, 0, 113, 7}, 4},
        {"rcode", 1, 0, 3, 1, 0, {203, 0, 113, 7}, 4},
        {"class3", 1, 0, 0, 3, 0, {203, 0, 113, 7}, 4},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        uint8_t packet[256];
        size_t len = base_len;
        memcpy(packet, base, len);
        packet[3] = (uint8_t)(0x80 | (cases[i].tc ? 2 : 0) | cases[i].rcode);
        size_t qtype_at = 12 + qname_len;
        packet[qtype_at] = (uint8_t)(cases[i].qtype >> 8);
        packet[qtype_at + 1] = (uint8_t)cases[i].qtype;
        packet[qtype_at + 2] = (uint8_t)(cases[i].klass >> 8);
        packet[qtype_at + 3] = (uint8_t)cases[i].klass;
        packet[len++] = 0xc0;
        packet[len++] = 0x0c;
        packet[len++] = (uint8_t)(cases[i].qtype >> 8);
        packet[len++] = (uint8_t)cases[i].qtype;
        packet[len++] = 0;
        packet[len++] = 1;
        for (int j = 0; j < 4; j++) packet[len++] = 0;
        packet[len++] = (uint8_t)(cases[i].address_len >> 8);
        packet[len++] = (uint8_t)cases[i].address_len;
        memcpy(packet + len, cases[i].address, cases[i].address_len);
        len += cases[i].address_len;
        char ip[64] = "";
        int ok = dns_response_address(packet, len, cases[i].wrong_id ? id + 1 : id,
                                      qname, qname_len, cases[i].qtype, ip,
                                      sizeof ip);
        printf("%s{\"case\":\"%s\",\"ok\":%s,\"ip\":\"%s\"}", i ? "," : "",
               cases[i].name, ok ? "true" : "false", ip);
    }
    printf("]}\n");
}

struct loopback {
    int server;
    int a_count;
    int aaaa_count;
};

static void *loopback_main(void *arg) {
    struct loopback *loop = arg;
    for (int i = 0; i < 3; i++) {
        uint8_t request[1024], response[1024];
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof peer;
        ssize_t got = recvfrom(loop->server, request, sizeof request, 0,
                               (struct sockaddr *)&peer, &peer_len);
        if (got < 13) break;
        uint8_t qname[256];
        size_t qname_len = 0;
        dns_name_encode("bootstrap.example", qname, sizeof qname, &qname_len);
        uint16_t qtype = (uint16_t)(request[12 + qname_len] << 8 |
                                    request[12 + qname_len + 1]);
        size_t len = 0;
        response[len++] = request[0];
        response[len++] = request[1];
        response[len++] = 0x81;
        response[len++] = 0x80;
        response[len++] = 0;
        response[len++] = 1;
        response[len++] = 0;
        response[len++] = 1;
        for (int j = 0; j < 4; j++) response[len++] = 0;
        memcpy(response + len, request + 12, qname_len + 4);
        len += qname_len + 4;
        response[len++] = 0xc0;
        response[len++] = 0x0c;
        response[len++] = (uint8_t)(qtype >> 8);
        response[len++] = (uint8_t)qtype;
        response[len++] = 0;
        response[len++] = 1;
        for (int j = 0; j < 4; j++) response[len++] = 0;
        if (qtype == 1) {
            loop->a_count++;
            response[len++] = 0;
            response[len++] = 4;
            uint8_t address[4] = {203, 0, 113, 7};
            memcpy(response + len, address, 4);
            len += 4;
        } else {
            loop->aaaa_count++;
            response[len++] = 0;
            response[len++] = 16;
            uint8_t address[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0, 7};
            memcpy(response + len, address, 16);
            len += 16;
        }
        ssize_t sent = sendto(loop->server, response, len, 0, (struct sockaddr *)&peer, peer_len);
        (void)sent;
    }
    return NULL;
}

static void loopback(void) {
    struct loopback loop;
    memset(&loop, 0, sizeof loop);
    loop.server = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_port = htons(53);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(loop.server, (struct sockaddr *)&address, sizeof address) != 0) {
        perror("bind 53");
        exit(1);
    }
    pthread_t thread;
    pthread_create(&thread, NULL, loopback_main, &loop);
    char ip[64] = "";
    int a = d2k_dns_resolve_bootstrap("bootstrap.example", "127.0.0.1", 0, ip, sizeof ip);
    printf("a %d %s\n", a, ip);
    ip[0] = '\0';
    int literal = d2k_dns_resolve_bootstrap("203.0.113.9", "127.0.0.1", 0, ip, sizeof ip);
    printf("literal %d %s\n", literal, ip);
    ip[0] = '\0';
    int bad = d2k_dns_resolve_bootstrap("bootstrap.example", "not-an-ip", 0, ip, sizeof ip);
    printf("bad %d %s\n", bad, ip);
    pthread_cancel(thread);
    pthread_join(thread, NULL);
    close(loop.server);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--loopback") == 0) {
        loopback();
        return 0;
    }
    vectors();
    return 0;
}
