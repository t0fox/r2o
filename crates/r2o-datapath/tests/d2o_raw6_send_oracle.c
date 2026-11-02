#define _DEFAULT_SOURCE 1
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "d2k_ipfrag.h"
#include "d2k_raw.h"
#include "d2k_wire.h"

static void print_hex(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
    putchar('\n');
}

static int packet_key_matches(const uint8_t *got, size_t got_len,
                              const uint8_t *want, size_t want_len) {
    if (got_len < 40 || want_len < 40 || got[0] >> 4 != 6 ||
        memcmp(got + 8, want + 8, 32) != 0 || got[6] != want[6]) {
        return 0;
    }
    if (want[6] == IPPROTO_UDP) {
        return got_len >= 48 && want_len >= 48 &&
               memcmp(got + 40, want + 40, 4) == 0;
    }
    if (want[6] == 44) {
        return got_len >= 48 && want_len >= 48 &&
               memcmp(got + 44, want + 44, 4) == 0;
    }
    return 0;
}

static ssize_t capture_packet(int fd, const uint8_t *want, size_t want_len,
                             uint8_t *got, size_t got_cap) {
    for (int attempt = 0; attempt < 20; attempt++) {
        struct pollfd ready = {.fd=fd, .events=POLLIN};
        if (poll(&ready, 1, 100) <= 0) continue;
        struct sockaddr_ll from;
        socklen_t from_len = sizeof from;
        ssize_t len = recvfrom(fd, got, got_cap, 0,
                               (struct sockaddr *)&from, &from_len);
        if (len < 0) return -1;
        if (from.sll_pkttype != PACKET_OUTGOING ||
            !packet_key_matches(got, (size_t)len, want, want_len)) {
            continue;
        }
        return len;
    }
    errno = ETIMEDOUT;
    return -1;
}

static int receive_body(int fd, const uint8_t body[64]) {
    struct pollfd ready = {.fd=fd, .events=POLLIN};
    if (poll(&ready, 1, 1000) != 1) return -1;
    uint8_t got[256];
    ssize_t len = recv(fd, got, sizeof got, 0);
    return len == 64 && memcmp(got, body, 64) == 0 ? 0 : -1;
}

static int send_capture(d2k_raw *raw, int capture, const char *label,
                        const uint8_t *packet, size_t packet_len) {
    char error[256] = {0};
    if (d2k_raw_prepare(raw, packet, packet_len, error, sizeof error) != 0 ||
        d2k_raw_send(raw, packet, packet_len, error, sizeof error) != 0) {
        fprintf(stderr, "D2O raw send %s: %s\n", label, error);
        return -1;
    }
    uint8_t frame[2048];
    ssize_t len = capture_packet(capture, packet, packet_len, frame, sizeof frame);
    if (len < 0) {
        fprintf(stderr, "D2O capture %s: %s\n", label, strerror(errno));
        return -1;
    }
    if ((size_t)len != packet_len || memcmp(frame, packet, packet_len) != 0) {
        fprintf(stderr, "D2O captured wire packet differs for %s\n", label);
        return -1;
    }
    printf("PACKET %s ", label);
    print_hex(frame, (size_t)len);
    return 0;
}

int main(void) {
    int receive = socket(AF_INET6, SOCK_DGRAM, 0);
    if (receive < 0) { perror("socket UDP6"); return 1; }
    struct sockaddr_in6 local = {
        .sin6_family=AF_INET6,
        .sin6_addr=IN6ADDR_LOOPBACK_INIT,
    };
    if (bind(receive, (struct sockaddr *)&local, sizeof local) != 0) {
        perror("bind UDP6"); close(receive); return 1;
    }
    socklen_t local_len = sizeof local;
    if (getsockname(receive, (struct sockaddr *)&local, &local_len) != 0) {
        perror("getsockname UDP6"); close(receive); return 1;
    }

    int capture = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    if (capture < 0) { perror("socket AF_PACKET"); close(receive); return 1; }
    struct sockaddr_ll link = {
        .sll_family=AF_PACKET,
        .sll_protocol=htons(ETH_P_ALL),
        .sll_ifindex=(int)if_nametoindex("lo"),
    };
    if (link.sll_ifindex == 0 ||
        bind(capture, (struct sockaddr *)&link, sizeof link) != 0) {
        perror("bind AF_PACKET lo"); close(capture); close(receive); return 1;
    }

    char error[256] = {0};
    d2k_raw *raw = d2k_raw_open(0xd200, "lo", error, sizeof error);
    if (!raw) {
        fprintf(stderr, "D2O raw open: %s\n", error);
        close(capture); close(receive); return 1;
    }

    const uint8_t body[64] = "native IPv6 raw packet";
    d2k_conn connection = {
        .src_port=htons(54322),
        .dst_port=local.sin6_port,
        .family=6,
        .ttl=48,
    };
    connection.src_ip6[15] = 1;
    connection.dst_ip6[15] = 1;
    d2k_emit emission = {.bytes=body, .len=sizeof body};
    uint8_t packet[1024];
    size_t packet_len = d2k_wire_build_udp(&connection, &emission,
                                           packet, sizeof packet);
    if (packet_len == 0) {
        fprintf(stderr, "D2O did not build the IPv6 UDP packet\n");
        d2k_raw_close(raw); close(capture); close(receive); return 1;
    }
    printf("PORT %u\n", (unsigned)ntohs(local.sin6_port));
    if (send_capture(raw, capture, "base", packet, packet_len) != 0 ||
        receive_body(receive, body) != 0) {
        fprintf(stderr, "D2O base IPv6 UDP delivery failed\n");
        d2k_raw_close(raw); close(capture); close(receive); return 1;
    }
    puts("DELIVERED base");

    for (int shape = 1; shape <= 4; shape++) {
        d2k_ipfrag_plan plan;
        if (d2k_ipfrag_shape(shape, &plan) != 0) {
            fprintf(stderr, "D2O missing IPv6 fragment shape %d\n", shape);
            d2k_raw_close(raw); close(capture); close(receive); return 1;
        }
        d2k_ipfrag_span spans[3];
        size_t count = d2k_udpfrag6_build_ex(
            connection.src_ip6, connection.dst_ip6,
            ntohs(connection.src_port), ntohs(connection.dst_port),
            body, sizeof body, &plan, 0x12345000u + (unsigned)shape,
            48, 0, 0, packet, sizeof packet, spans);
        size_t expected_count = shape <= 2 ? 2u : 3u;
        if (count != expected_count) {
            fprintf(stderr, "D2O IPv6 fragment shape %d returned %zu packets\n",
                    shape, count);
            d2k_raw_close(raw); close(capture); close(receive); return 1;
        }
        for (size_t i = 0; i < count; i++) {
            char label[32];
            snprintf(label, sizeof label, "shape%d_%zu", shape, i);
            if (send_capture(raw, capture, label,
                             packet + spans[i].off, spans[i].len) != 0) {
                d2k_raw_close(raw); close(capture); close(receive); return 1;
            }
        }
        if (shape <= 2) {
            if (receive_body(receive, body) != 0) {
                fprintf(stderr, "D2O IPv6 shape %d did not reassemble\n", shape);
                d2k_raw_close(raw); close(capture); close(receive); return 1;
            }
            printf("DELIVERED shape%d\n", shape);
        }
    }

    d2k_raw_close(raw);
    close(capture);
    close(receive);
    return 0;
}
