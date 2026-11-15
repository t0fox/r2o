/* C-оракул d2k_udp_plan_send с реальным connected UDP-сокетом.
 *
 * Включает production udpruntime.c; fragment prepare/send подменяются
 * seam'ами, ordinary send/getsockopt/setsockopt/nanosleep перехватывает
 * udp_plan_send_shim.c (LD_PRELOAD). TLV плана пишется для Rust-стороны.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_udpruntime.h"
#include "udpruntime.c"

static const uint8_t payload[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};

static void print_hex(FILE *file, const uint8_t *bytes, size_t length) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        fputc(digits[bytes[i] >> 4], file);
        fputc(digits[bytes[i] & 0x0f], file);
    }
}

static void write_build_trace(int fd, const char *text, int family) {
    const char *path = getenv("R2O_UDP_PLAN_BUILD_OUT");
    if (!path || !*path) {
        return;
    }
    struct sockaddr_storage local;
    struct sockaddr_storage peer;
    socklen_t local_len = sizeof local;
    socklen_t peer_len = sizeof peer;
    if (getsockname(fd, (struct sockaddr *)&local, &local_len) != 0 ||
        getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0) {
        return;
    }
    d2k_conn context;
    memset(&context, 0, sizeof context);
    context.family = (family == AF_INET) ? 4 : 6;
    context.ttl = 47;
    if (family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)&local;
        const struct sockaddr_in *z = (const struct sockaddr_in *)&peer;
        context.src_ip = a->sin_addr.s_addr;
        context.dst_ip = z->sin_addr.s_addr;
        context.src_port = a->sin_port;
        context.dst_port = z->sin_port;
    } else {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)&local;
        const struct sockaddr_in6 *z = (const struct sockaddr_in6 *)&peer;
        memcpy(context.src_ip6, &a->sin6_addr, 16);
        memcpy(context.dst_ip6, &z->sin6_addr, 16);
        context.src_port = a->sin6_port;
        context.dst_port = z->sin6_port;
    }
    d2k_udp_batch batch;
    memset(&batch, 0, sizeof batch);
    FILE *file = fopen(path, "w");
    if (!file) {
        return;
    }
    if (d2k_udp_plan_build(text, &context, 0x12345678u, payload,
                           sizeof payload, &batch) != 0) {
        fputs("batch rc=-1\n", file);
        fclose(file);
        return;
    }
    fprintf(file, "batch rc=0 n=%zu used=%zu\n", batch.n, batch.used);
    for (size_t i = 0; i < batch.n; i++) {
        fprintf(file, "%zu frag=%d delay=%u len=%zu hex=", i,
                batch.v[i].fragment, batch.v[i].delay_us, batch.v[i].len);
        print_hex(file, batch.bytes + batch.v[i].off, batch.v[i].len);
        fputc('\n', file);
    }
    fclose(file);
    d2k_udp_batch_free(&batch);
}

static int scenario_is(const char *name) {
    const char *scenario = getenv("R2O_UDP_SEND_SCENARIO");
    return scenario && strcmp(scenario, name) == 0;
}

static void log_hex(const char *prefix, const uint8_t *bytes, size_t length,
                    uint32_t mark) {
    const char *path = getenv("R2O_UDP_SEND_SHIM_LOG");
    if (!path || !*path) {
        return;
    }
    FILE *file = fopen(path, "a");
    if (!file) {
        return;
    }
    fprintf(file, "%s len=%zu hex=", prefix, length);
    for (size_t i = 0; i < length; i++) {
        fprintf(file, "%02x", bytes[i]);
    }
    if (mark) {
        fprintf(file, " mark=%u", mark);
    }
    fputc('\n', file);
    fclose(file);
}

static int seam_prepare(udp_raw_sink *sink, const uint8_t *packet, size_t length,
                        uint32_t mark) {
    (void)sink;
    log_hex("prepare", packet, length, mark);
    if (scenario_is("prepare_error")) {
        return -1;
    }
    return 0;
}

static int seam_send(udp_raw_sink *sink, const uint8_t *packet, size_t length,
                     uint32_t mark) {
    (void)sink;
    log_hex("raw_send", packet, length, mark);
    if (scenario_is("raw_send_error")) {
        return -1;
    }
    return 0;
}

static uint32_t seam_fragment_id(void) {
    return 0x12345678u;
}

static int receiver_fd = -1;

static int bind_fixed(int fd, int family, uint16_t port) {
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (family == AF_INET) {
        struct sockaddr_in address;
        memset(&address, 0, sizeof address);
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        return bind(fd, (struct sockaddr *)&address, sizeof address);
    }
    struct sockaddr_in6 address;
    memset(&address, 0, sizeof address);
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_loopback;
    address.sin6_port = htons(port);
    return bind(fd, (struct sockaddr *)&address, sizeof address);
}

static int connected_socket(int family) {
    int receiver = socket(family, SOCK_DGRAM, 0);
    int sender = socket(family, SOCK_DGRAM, 0);
    if (receiver < 0 || sender < 0) {
        return -1;
    }
    if (bind_fixed(receiver, family, 40001) != 0 ||
        bind_fixed(sender, family, 40000) != 0) {
        return -1;
    }
    if (family == AF_INET) {
        struct sockaddr_in address;
        memset(&address, 0, sizeof address);
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(40001);
        if (connect(sender, (struct sockaddr *)&address, sizeof address) != 0) {
            return -1;
        }
    } else {
        struct sockaddr_in6 address;
        memset(&address, 0, sizeof address);
        address.sin6_family = AF_INET6;
        address.sin6_addr = in6addr_loopback;
        address.sin6_port = htons(40001);
        if (connect(sender, (struct sockaddr *)&address, sizeof address) != 0) {
            return -1;
        }
    }
    receiver_fd = receiver;
    return sender;
}

int main(void) {
    const char *text = getenv("R2O_UDP_PLAN_TEXT");
    const char *family_text = getenv("R2O_UDP_PLAN_FAMILY");
    const char *tlv_path = getenv("R2O_UDP_PLAN_TLV_OUT");
    if (!text || !family_text || !tlv_path) {
        return 2;
    }
    int family = atoi(family_text) == 6 ? AF_INET6 : AF_INET;

    uint8_t tlv[65536];
    size_t tlv_len = 0;
    char error[256] = {0};
    if (d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tlv_len, error,
                             sizeof error) != 0) {
        printf("send rc=2\n");
        return 0;
    }
    FILE *out = fopen(tlv_path, "wb");
    if (!out || fwrite(tlv, 1, tlv_len, out) != tlv_len) {
        return 2;
    }
    fclose(out);

    int fd = connected_socket(family);
    if (fd < 0) {
        perror("connected_socket");
        return 2;
    }
    udp_prepare_io = seam_prepare;
    udp_send_io = seam_send;
    udp_fragment_id_io = seam_fragment_id;
    write_build_trace(fd, text, family);
    int rc = d2k_udp_plan_send(fd, text, payload, sizeof payload, 46);
    printf("send rc=%d\n", rc);
    close(fd);
    if (receiver_fd >= 0) {
        close(receiver_fd);
    }
    return 0;
}
