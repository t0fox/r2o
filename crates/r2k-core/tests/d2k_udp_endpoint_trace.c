/* Сравниваем тело команды, поскольку коды R2OP заняты голосовыми командами. */
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "d2k_crypto.h"
#include "d2k_dns_message.h"
#include "d2k_link.h"

static int trace(int stream, size_t len) {
    uint8_t frame[128];
    if (read(stream, frame, len) != (ssize_t)len || frame[3] != len - 4)
        return 1;
    for (size_t i = 6; i < len; ++i)
        printf("%02x", frame[i]);
    putchar('\n');
    return 0;
}

int main(void) {
    int fd[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd))
        return 1;
    uint8_t v4[4], v6[16];
    if (inet_pton(AF_INET, "192.0.2.7", v4) != 1 ||
        inet_pton(AF_INET6, "2001:db8::7", v6) != 1)
        return 2;

    const int families[] = {4, 6};
    const uint8_t *addresses[] = {v4, v6};
    uint8_t token[16];
    memset(token, 0x5a, sizeof token);
    uint8_t question[272];
    const size_t question_size = d2k_dns_question("example.com", 1, 0x1234,
                                                  question, sizeof question);
    if (!question_size || d2k_dns_question_valid(question, question_size) != 0)
        return 3;
    uint8_t digest[32];
    d2k_sha256(question, question_size, digest);
    uint8_t tcp[274], tcp_digest[32];
    tcp[0] = (uint8_t)(question_size >> 8);
    tcp[1] = (uint8_t)question_size;
    memcpy(tcp + 2, question, question_size);
    d2k_sha256(tcp, question_size + 2, tcp_digest);
    for (size_t i = 0; i < 2; ++i) {
        const uint16_t port = htons(853 + (uint16_t)i);
        if (d2k_link_set_endpoint(fd[0], addresses[i], families[i], port,
                                  D2K_LINK_SHAPE_QUIC, "aabb", NULL, 0) ||
            trace(fd[1], 28) ||
            d2k_link_del_endpoint(fd[0], addresses[i], families[i], port,
                                  D2K_LINK_SHAPE_VOICE, NULL, 0) ||
            trace(fd[1], 26) ||
            d2k_link_set_endpoint_bound(fd[0], addresses[i], families[i], port,
                                        D2K_LINK_SHAPE_VOICE, "aabb", token, NULL, 0) ||
            trace(fd[1], 44) ||
            d2k_link_set_dns_probe(fd[0], addresses[i], htons(52001), addresses[i], port,
                                   17, families[i], token, 1000, "aabb",
                                   (uint16_t)question_size, digest, NULL, 0) ||
            trace(fd[1], 100) ||
            d2k_link_set_dns_endpoint(fd[0], addresses[i], families[i], port,
                                      (uint16_t)question_size, "aabb", token, NULL, 0) ||
            trace(fd[1], 46) ||
            d2k_link_set_dns_probe(fd[0], addresses[i], htons(52001), addresses[i], port,
                                   6, families[i], token, 1000, "aabb",
                                   (uint16_t)(question_size + 2), tcp_digest, NULL, 0) ||
            trace(fd[1], 100) ||
            d2k_link_del_addr_probe_family(fd[0], addresses[i], htons(52001), addresses[i], port,
                                           6, families[i], token, NULL, 0) ||
            trace(fd[1], 60) ||
            d2k_link_set_dns_endpoint(fd[0], addresses[i], families[i], port,
                                      (uint16_t)(question_size + 2), "aabb", token, NULL, 0) ||
            trace(fd[1], 46) ||
            d2k_link_set_endpoint(fd[0], addresses[i], families[i], 0,
                                  D2K_LINK_SHAPE_QUIC, "aabb", NULL, 0) == 0)
            return 4;
    }
    close(fd[0]);
    close(fd[1]);
    return 0;
}
