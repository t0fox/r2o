#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_sched.h"
#include "d2k_link.h"
#include "d2k_httpsearch.h"
#include "d2k_plantlv.h"

static int http_bound_set_wire(void)
{
    int sockets[2];
    uint8_t plan_id[16];
    uint8_t token[16];
    char text[2048];
    char hex[8192];
    char error[160] = {0};
    memset(plan_id, 0x11, sizeof plan_id);
    memset(token, 0x55, sizeof token);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 2;
    if (d2k_hs_candidate_text("split", plan_id, text, sizeof text) != 0 ||
        d2k_plan_text_to_hex(text, hex, sizeof hex, error, sizeof error) != 0 ||
        d2k_link_set_name_bound(sockets[0], "example.test", 6, hex,
                                D2K_PLAN_SHAPE_HTTP, 4, token,
                                error, sizeof error) != 0) {
        fprintf(stderr, "donor HTTP bound set failed: %s\n", error);
        close(sockets[0]);
        close(sockets[1]);
        return 2;
    }
    close(sockets[0]);
    uint8_t bytes[4096];
    ssize_t length = read(sockets[1], bytes, sizeof bytes);
    close(sockets[1]);
    if (length <= 0) return 2;
    /* The controllers use different plan-envelope magics (D2KP versus R2OP);
       normalize that four-byte codec tag before comparing the shared command. */
    size_t plan_offset = 6u + 1u + strlen("example.test") + 2u;
    if ((size_t)length < plan_offset + 4u ||
        memcmp(bytes + plan_offset, "D2KP", 4) != 0) return 2;
    memcpy(bytes + plan_offset, "R2OP", 4);
    printf("D2O_HTTP_BOUND_SET=");
    for (ssize_t i = 0; i < length; i++) printf("%02x", bytes[i]);
    putchar('\n');
    return 0;
}

static int http_bound_del_wire(void)
{
    int sockets[2];
    d2k_binding_context binding = {0};
    char error[160] = {0};
    binding.generation = 42;
    binding.kind = D2K_BIND_NAME;
    binding.family = 4;
    binding.shape = D2K_PLAN_SHAPE_HTTP;
    memset(binding.epoch, 7, sizeof binding.epoch);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 2;
    if (d2k_link_del_name_bound(sockets[0], "example.test", 6, &binding,
                                error, sizeof error) != 0) {
        fprintf(stderr, "donor HTTP bound delete failed: %s\n", error);
        close(sockets[0]);
        close(sockets[1]);
        return 2;
    }
    close(sockets[0]);
    uint8_t bytes[256];
    ssize_t length = read(sockets[1], bytes, sizeof bytes);
    close(sockets[1]);
    if (length <= 0) return 2;
    printf("D2O_HTTP_BOUND_DEL=");
    for (ssize_t i = 0; i < length; i++) printf("%02x", bytes[i]);
    putchar('\n');
    return 0;
}

static int area_wire(void)
{
    int sockets[2];
    uint8_t id[D2K_TRIAL_ID_LEN] = {1};
    char error[160] = {0};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 2;
    if (d2k_link_area_identified(sockets[0], D2K_CMD_SET_BYPASS,
                                 "child.example", 6, D2K_SHAPE_MODERN, 4,
                                 NULL, id, error, sizeof error) != 0) {
        fprintf(stderr, "donor area command failed: %s\n", error);
        close(sockets[0]);
        close(sockets[1]);
        return 2;
    }
    close(sockets[0]);
    uint8_t bytes[256];
    ssize_t length = read(sockets[1], bytes, sizeof bytes);
    close(sockets[1]);
    if (length <= 0) return 2;
    printf("D2O_AREA_COMMAND=");
    for (ssize_t i = 0; i < length; i++) printf("%02x", bytes[i]);
    putchar('\n');
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--http-bound-set") == 0) return http_bound_set_wire();
    if (argc == 2 && strcmp(argv[1], "--http-bound-del") == 0) return http_bound_del_wire();
    if (argc == 2 && strcmp(argv[1], "--area-wire") == 0) return area_wire();
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
