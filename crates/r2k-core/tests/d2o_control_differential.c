#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_link.h"
#include "sched.c"

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_hex(const char *text, uint8_t *out, size_t cap, size_t *len) {
    size_t n = strlen(text);
    if ((n & 1u) || n / 2 > cap) return -1;
    for (size_t i = 0; i < n; i += 2) {
        int hi = hex_value(text[i]);
        int lo = hex_value(text[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *len = n / 2;
    return 0;
}

static void encode_hex(const uint8_t *bytes, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 15];
    }
    out[len * 2] = '\0';
}

static int write_all(int fd, const uint8_t *bytes, size_t len) {
    while (len) {
        ssize_t n = write(fd, bytes, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        bytes += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *fixture = fopen(argv[1], "r");
    if (!fixture) return 2;

    char name[32], wire_hex[8192], expected[8192];
    unsigned line = 0;
    while (fscanf(fixture, "%31s %8191s %8191s", name, wire_hex, expected) == 3) {
        (void)expected;
        line++;
        uint8_t wire[4096];
        size_t wire_len = 0;
        if (decode_hex(wire_hex, wire, sizeof wire, &wire_len) != 0) return 3;

        int fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return 4;
        if (write_all(fds[1], wire, wire_len) != 0) return 5;

        d2k_ev event;
        char err[256] = {0};
        int rc = d2k_link_next(fds[0], &event, 1000, err, sizeof err);
        close(fds[0]);
        close(fds[1]);
        if (rc != 0) {
            if (strncmp(expected, "REJECT:", 7) == 0) {
                puts(expected);
                continue;
            }
            fprintf(stderr, "C decoder rejected fixture line %u (%s): %s\n",
                    line, name, err);
            return 6;
        }
        if (strncmp(expected, "REJECT:", 7) == 0) {
            fprintf(stderr, "C decoder accepted truncated fixture line %u (%s)\n",
                    line, name);
            return 9;
        }

        if (strcmp(name, "ACK") == 0 && event.kind == D2K_EV_ACK) {
            char trial[2 * D2K_TRIAL_ID_LEN + 1];
            encode_hex(event.trial_id, D2K_TRIAL_ID_LEN, trial);
            printf("ACK:%u:%u:%u:%s\n", event.code, event.num >> 8,
                   event.num & 0xffu, trial);
        } else if (strcmp(name, "APPLIED") == 0 && event.kind == D2K_EV_APPLIED) {
            char low_ip[33], high_ip[33], plan[2 * D2K_PLAN_ID_LEN + 1];
            char trial[2 * D2K_TRIAL_ID_LEN + 1], epoch[33];
            encode_hex(event.low_ip, sizeof event.low_ip, low_ip);
            encode_hex(event.high_ip, sizeof event.high_ip, high_ip);
            encode_hex(event.plan_id, D2K_PLAN_ID_LEN, plan);
            encode_hex(event.trial_id, D2K_TRIAL_ID_LEN, trial);
            encode_hex(event.execution_binding.epoch, sizeof event.execution_binding.epoch, epoch);
            printf("APPLIED:%u:%s:%s:%u:%u:%u:%s:%s:%llu:%llu:%u:%u:%u:%u:%s\n",
                   event.family, low_ip, high_ip, event.low_port, event.high_port,
                   event.transport, plan, trial,
                   (unsigned long long)event.execution_id,
                   (unsigned long long)event.execution_binding.generation,
                   event.execution_binding.kind, event.execution_binding.family,
                   event.execution_binding.shape, event.execution_binding.temporary,
                   epoch);

            task candidate;
            memset(&candidate, 0, sizeof candidate);
            candidate.by_addr = 1;
            candidate.family = 4;
            candidate.transport = 6;
            snprintf(candidate.ip, sizeof candidate.ip, "%s", "198.51.100.2");
            candidate.port = 443;
            memset(candidate.ver_plan_id, 0x11, D2K_PLAN_ID_LEN);
            memset(candidate.addr_probe_trial_id, 0x22, D2K_TRIAL_ID_LEN);
            printf("MATCH:%u\n",
                   (unsigned)(applied_trial_is_ours(&candidate, &event) &&
                              applied_of_candidate(&candidate, &event)));
        } else {
            fprintf(stderr, "unexpected C event for fixture line %u (%s)\n", line, name);
            return 7;
        }
    }
    fclose(fixture);
    return line == 3 ? 0 : 8;
}
