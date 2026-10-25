#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_sched.h"

int main(int argc, char **argv)
{
    int first_batch = argc == 4 && strcmp(argv[3], "--first-batch") == 0;
    if (argc != 3 && !first_batch) return 2;
    char *end = NULL;
    unsigned long parsed_cap = strtoul(argv[2], &end, 10);
    if (!end || *end || parsed_cap > UINT32_MAX) return 2;

    d2k_catalog catalog = {0};
    char error[256];
    if (d2k_catalog_load(argv[1], &catalog, error, sizeof error) != 0) {
        fprintf(stderr, "donor catalog load failed: %s\n", error);
        return 2;
    }

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        d2k_catalog_free(&catalog);
        return 2;
    }
    d2k_sched *scheduler = d2k_sched_new(&catalog, sockets[0], 0x2e);
    if (!scheduler) {
        close(sockets[0]);
        close(sockets[1]);
        d2k_catalog_free(&catalog);
        return 2;
    }
    d2k_sched_set_send_cap(scheduler, (uint32_t)parsed_cap);
    if (d2k_sched_sync(scheduler) != 0) return 2;
    if (first_batch) {
        (void)d2k_sched_sync_step(scheduler);
    } else {
        for (size_t steps = 0; d2k_sched_sync_pending(scheduler) && steps < 100; steps++) {
            (void)d2k_sched_sync_step(scheduler);
        }
    }
    if (!first_batch && d2k_sched_sync_pending(scheduler)) return 2;

    d2k_sched_free(scheduler);
    close(sockets[0]);

    uint8_t bytes[65536];
    size_t length = 0;
    for (;;) {
        ssize_t count = read(sockets[1], bytes + length, sizeof bytes - length);
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            close(sockets[1]);
            d2k_catalog_free(&catalog);
            return 2;
        }
        length += (size_t)count;
        if (length == sizeof bytes) return 2;
    }
    close(sockets[1]);
    d2k_catalog_free(&catalog);

    size_t offset = 0;
    size_t operations = 0;
    while (offset < length) {
        if (length - offset < 6) return 2;
        size_t payload_length = ((size_t)bytes[offset] << 24) |
                                ((size_t)bytes[offset + 1] << 16) |
                                ((size_t)bytes[offset + 2] << 8) |
                                (size_t)bytes[offset + 3];
        if (payload_length < 3 || payload_length > length - offset - 4) return 2;
        uint16_t command = (uint16_t)(((uint16_t)bytes[offset + 4] << 8) |
                                      bytes[offset + 5]);
        const uint8_t *body = bytes + offset + 6;
        size_t body_length = payload_length - 2;
        if (command != 0x0081 && command != 0x0083) return 2;
        if (body_length < 1 || body[0] == 0 || body_length < (size_t)body[0] + 1) return 2;
        printf("%s=%s:%.*s\n",
               first_batch ? "D2O_CATALOG_BATCH_OP" : "D2O_CATALOG_OP",
               command == 0x0081 ? "SET_NAME" : "DEL_NAME",
               (int)body[0], body + 1);
        operations++;
        offset += payload_length + 4;
    }
    if (first_batch) printf("D2O_CATALOG_BATCH_COUNT=%zu\n", operations);
    return 0;
}
