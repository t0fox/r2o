#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_link.h"

static int failures;

static void to_hex(const uint8_t *bytes, size_t length, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        out[2 * i] = digits[bytes[i] >> 4];
        out[2 * i + 1] = digits[bytes[i] & 0x0f];
    }
    out[2 * length] = '\0';
}

static int read_frame(int fd, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t have = 0;
    while (have < 4) {
        ssize_t got = recv(fd, out + have, 4 - have, 0);
        if (got <= 0) return -1;
        have += (size_t)got;
    }
    uint32_t body = ((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) |
                    ((uint32_t)out[2] << 8) | (uint32_t)out[3];
    size_t total = 4 + (size_t)body;
    if (total > cap) return -1;
    while (have < total) {
        ssize_t got = recv(fd, out + have, total - have, 0);
        if (got <= 0) return -1;
        have += (size_t)got;
    }
    *out_len = total;
    return 0;
}

static void check_case(const char *label, int rc, const uint8_t *frame, size_t length)
{
    char hex[2048];
    if (rc == 0) {
        to_hex(frame, length, hex);
        printf("%s\trc=0\tlen=%zu\thex=%s\n", label, length, hex);
    } else {
        printf("%s\trc=-1\tlen=0\thex=-\n", label);
    }
}

static void run_case(const char *label, uint16_t command, const char *name,
                     uint8_t transport, uint8_t shape, uint8_t family,
                     const uint8_t *area_id)
{
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        perror("socketpair");
        failures++;
        return;
    }
    char err[256] = {0};
    int rc;
    if (area_id) {
        rc = d2k_link_area_identified(fds[0], command, name, transport, shape,
                                      family, NULL, area_id, err, sizeof err);
    } else if (command == D2K_CMD_DEL_SUFFIX) {
        rc = d2k_link_del_suffix_family(fds[0], name, transport, shape, family,
                                        err, sizeof err);
    } else if (command == D2K_CMD_SET_BYPASS) {
        rc = d2k_link_set_bypass_family(fds[0], name, transport, shape, family,
                                        err, sizeof err);
    } else if (command == D2K_CMD_DEL_BYPASS) {
        rc = d2k_link_del_bypass_family(fds[0], name, transport, shape, family,
                                        err, sizeof err);
    } else {
        failures++;
        close(fds[0]);
        close(fds[1]);
        return;
    }
    uint8_t frame[2048];
    size_t length = 0;
    if (rc == 0 && read_frame(fds[1], frame, sizeof frame, &length) != 0) {
        fprintf(stderr, "%s: кадр не прочитан\n", label);
        failures++;
        rc = -1;
    }
    check_case(label, rc, frame, length);
    close(fds[0]);
    close(fds[1]);
}

int main(void)
{
    char long_name[255];
    memset(long_name, 'b', sizeof long_name);
    long_name[253] = '\0';
    char too_long[256];
    memset(too_long, 'c', sizeof too_long);
    too_long[254] = '\0';

    run_case("set_bypass_tcp4", D2K_CMD_SET_BYPASS, "a", 6, 1, 4, NULL);
    run_case("set_bypass_tcp6_253", D2K_CMD_SET_BYPASS, long_name, 6, 2, 6, NULL);
    run_case("del_bypass_quic", D2K_CMD_DEL_BYPASS, "quic.example", 17, 3, 4, NULL);
    run_case("del_suffix_ech", D2K_CMD_DEL_SUFFIX, "ech.example", 6, 6, 4, NULL);

    uint8_t area_id[16];
    memset(area_id, 0x11, sizeof area_id);
    run_case("set_bypass_area_id", D2K_CMD_SET_BYPASS, "area.example", 6, 1, 4, area_id);

    uint8_t zero_id[16] = {0};
    run_case("del_bypass_zero_id", D2K_CMD_DEL_BYPASS, "zero.example", 17, 3, 4, zero_id);

    run_case("empty_name", D2K_CMD_SET_BYPASS, "", 6, 1, 4, NULL);
    run_case("too_long_name", D2K_CMD_SET_BYPASS, too_long, 6, 1, 4, NULL);
    run_case("bad_transport", D2K_CMD_SET_BYPASS, "bad.example", 5, 1, 4, NULL);
    run_case("bad_family", D2K_CMD_SET_BYPASS, "bad.example", 6, 1, 5, NULL);
    run_case("bad_shape", D2K_CMD_SET_BYPASS, "bad.example", 6, 5, 4, NULL);

    if (failures) {
        fprintf(stderr, "%d C invariant(s) failed\n", failures);
        return 1;
    }
    return 0;
}
