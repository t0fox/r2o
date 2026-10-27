#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "d2k_sched.h"
#include "d2k_groups.h"
#include "d2k_link.h"
#include "d2k_httpsearch.h"
#include "d2k_plantlv.h"

static int read_exact(int fd, uint8_t *bytes, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(fd, bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        offset += (size_t)count;
    }
    return 0;
}

static int read_control_frame(int fd, uint8_t *bytes, size_t capacity, size_t *length)
{
    uint8_t header[4];
    if (read_exact(fd, header, sizeof header) != 0) return -1;
    size_t payload = ((size_t)header[0] << 24) | ((size_t)header[1] << 16) |
                    ((size_t)header[2] << 8) | (size_t)header[3];
    if (payload < 2 || payload > capacity - sizeof header) return -1;
    memcpy(bytes, header, sizeof header);
    if (read_exact(fd, bytes + sizeof header, payload) != 0) return -1;
    *length = payload + sizeof header;
    return 0;
}

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

static int area_pending(const char *path, uint32_t send_cap)
{
    d2k_catalog catalog = {0};
    char error[256];
    if (d2k_catalog_load(path, &catalog, error, sizeof error) != 0) {
        fprintf(stderr, "donor area-pending catalog load failed: %s\n", error);
        return 2;
    }
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        d2k_catalog_free(&catalog);
        return 2;
    }
    d2k_sched *scheduler = d2k_sched_new(&catalog, sockets[0], 0x2f);
    if (!scheduler) {
        close(sockets[0]);
        close(sockets[1]);
        d2k_catalog_free(&catalog);
        return 2;
    }
    d2k_sched_set_send_cap(scheduler, send_cap);
    if (d2k_sched_sync(scheduler) != 0) return 2;
    (void)d2k_sched_sync_step(scheduler);
    int pending = d2k_sched_sync_pending(scheduler);
    d2k_sched_free(scheduler);
    close(sockets[0]);

    uint8_t bytes[4096];
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

    printf("D2O_AREA_PENDING=%d\n", pending);
    size_t offset = 0;
    int found = 0;
    while (offset < length) {
        if (length - offset < 6) return 2;
        size_t payload_length = ((size_t)bytes[offset] << 24) |
                                ((size_t)bytes[offset + 1] << 16) |
                                ((size_t)bytes[offset + 2] << 8) |
                                (size_t)bytes[offset + 3];
        if (payload_length < 2 || payload_length > length - offset - 4) return 2;
        uint16_t command = (uint16_t)(((uint16_t)bytes[offset + 4] << 8) |
                                      bytes[offset + 5]);
        if (command == D2K_CMD_SET_BYPASS) {
            printf("D2O_AREA_COMMAND=");
            for (size_t i = 0; i < payload_length + 4; i++)
                printf("%02x", bytes[offset + i]);
            putchar('\n');
            found = 1;
        }
        offset += payload_length + 4;
    }
    return pending && found ? 0 : 2;
}

static int area_timeout(const char *path, uint32_t send_cap)
{
    d2k_catalog catalog = {0};
    char error[256];
    if (d2k_catalog_load(path, &catalog, error, sizeof error) != 0) return 2;
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        d2k_catalog_free(&catalog);
        return 2;
    }
    d2k_sched *scheduler = d2k_sched_new(&catalog, sockets[0], 0x30);
    if (!scheduler) return 2;
    d2k_sched_set_send_cap(scheduler, send_cap);
    if (d2k_sched_sync(scheduler) != 0) return 2;
    d2k_sched_tick(scheduler, 1000);
    (void)d2k_sched_sync_step(scheduler);
    int before_deadline = d2k_sched_sync_pending(scheduler);
    d2k_sched_tick(scheduler, 5999);
    (void)d2k_sched_sync_step(scheduler);
    int at_deadline_minus_one = d2k_sched_sync_pending(scheduler);
    d2k_sched_tick(scheduler, 6000);
    (void)d2k_sched_sync_step(scheduler);
    int at_deadline = d2k_sched_sync_pending(scheduler);
    d2k_sched_free(scheduler);
    close(sockets[0]);
    close(sockets[1]);
    d2k_catalog_free(&catalog);
    printf("D2O_AREA_TIMEOUT=%d:%d:%d\n",
           before_deadline, at_deadline_minus_one, at_deadline);
    return before_deadline && at_deadline_minus_one && !at_deadline ? 0 : 2;
}

static int area_timeout_delete(const char *path, uint32_t send_cap)
{
    d2k_catalog catalog = {0};
    char error[256];
    if (d2k_catalog_load(path, &catalog, error, sizeof error) != 0) return 2;
    if (!catalog.groups || !catalog.groups->n_groups) {
        fprintf(stderr, "donor area-timeout fixture did not restore a group\n");
        d2k_catalog_free(&catalog);
        return 2;
    }
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        d2k_catalog_free(&catalog);
        return 2;
    }
    d2k_sched *scheduler = d2k_sched_new(&catalog, sockets[0], 0x31);
    if (!scheduler) return 2;
    d2k_sched_set_send_cap(scheduler, send_cap);
    if (d2k_sched_sync(scheduler) != 0) return 2;
    d2k_sched_tick(scheduler, 1000);
    (void)d2k_sched_sync_step(scheduler);
    int install_pending = d2k_sched_sync_pending(scheduler);
    d2k_sched_tick(scheduler, 6000);
    (void)d2k_sched_sync_step(scheduler);
    catalog.groups->disabled = 1;
    if (d2k_group_restore(catalog.groups) != 0 || d2k_sched_sync(scheduler) != 0) return 2;
    (void)d2k_sched_sync_step(scheduler);
    int delete_pending = d2k_sched_sync_pending(scheduler);
    d2k_sched_free(scheduler);
    close(sockets[0]);

    uint8_t bytes[4096];
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
    int found_delete = 0;
    while (offset < length) {
        if (length - offset < 6) return 2;
        size_t payload_length = ((size_t)bytes[offset] << 24) |
                                ((size_t)bytes[offset + 1] << 16) |
                                ((size_t)bytes[offset + 2] << 8) |
                                (size_t)bytes[offset + 3];
        if (payload_length < 2 || payload_length > length - offset - 4) return 2;
        uint16_t command = (uint16_t)(((uint16_t)bytes[offset + 4] << 8) |
                                      bytes[offset + 5]);
        if (command == D2K_CMD_DEL_SUFFIX) {
            printf("D2O_AREA_DELETE_COMMAND=");
            for (size_t i = 0; i < payload_length + 4; i++)
                printf("%02x", bytes[offset + i]);
            putchar('\n');
            found_delete = 1;
        }
        offset += payload_length + 4;
    }
    printf("D2O_AREA_TIMEOUT_DELETE=%d:%d\n", install_pending, delete_pending);
    return install_pending && delete_pending && found_delete ? 0 : 2;
}

static int area_delete_order(const char *path, uint32_t send_cap)
{
    d2k_catalog catalog = {0};
    char error[256];
    if (d2k_catalog_load(path, &catalog, error, sizeof error) != 0) return 2;
    if (!catalog.groups || catalog.groups->n_groups != 3) {
        fprintf(stderr, "donor area-delete-order fixture did not restore three groups\n");
        d2k_catalog_free(&catalog);
        return 2;
    }
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        d2k_catalog_free(&catalog);
        return 2;
    }
    d2k_sched *scheduler = d2k_sched_new(&catalog, sockets[0], 0x32);
    if (!scheduler) return 2;
    d2k_sched_set_send_cap(scheduler, send_cap);
    if (d2k_sched_sync(scheduler) != 0) return 2;

    uint8_t bytes[4096];
    size_t length = 0;
    for (size_t i = 0; i < 3; i++) {
        (void)d2k_sched_sync_step(scheduler);
        if (read_control_frame(sockets[1], bytes, sizeof bytes, &length) != 0) return 2;
        uint16_t command = (uint16_t)(((uint16_t)bytes[4] << 8) | bytes[5]);
        if (command != D2K_CMD_SET_SUFFIX) return 2;
        d2k_ev ack = {0};
        ack.kind = D2K_EV_ACK;
        ack.code = command;
        ack.num = 1u << 8;
        memcpy(ack.trial_id, bytes + length - D2K_TRIAL_ID_LEN, D2K_TRIAL_ID_LEN);
        d2k_sched_event(scheduler, &ack);
    }
    (void)d2k_sched_sync_step(scheduler);
    if (d2k_sched_sync_pending(scheduler)) return 2;
    catalog.groups->disabled = 1;
    if (d2k_group_restore(catalog.groups) != 0 || d2k_sched_sync(scheduler) != 0) return 2;

    for (size_t i = 0; i < 3; i++) {
        (void)d2k_sched_sync_step(scheduler);
        if (!d2k_sched_sync_pending(scheduler) ||
            read_control_frame(sockets[1], bytes, sizeof bytes, &length) != 0) return 2;
        uint16_t command = (uint16_t)(((uint16_t)bytes[4] << 8) | bytes[5]);
        if (command != D2K_CMD_DEL_SUFFIX) return 2;
        size_t name_len = bytes[6];
        if (length < 6 + 1 + name_len + 3 + D2K_TRIAL_ID_LEN) return 2;
        printf("D2O_AREA_DELETE_NAME=%.*s\n", (int)name_len, bytes + 7);
        printf("D2O_AREA_DELETE_COMMAND=");
        for (size_t j = 0; j < length; j++) printf("%02x", bytes[j]);
        putchar('\n');
        d2k_ev ack = {0};
        ack.kind = D2K_EV_ACK;
        ack.code = command;
        ack.num = 1u << 8;
        memcpy(ack.trial_id, bytes + length - D2K_TRIAL_ID_LEN, D2K_TRIAL_ID_LEN);
        d2k_sched_event(scheduler, &ack);
    }
    (void)d2k_sched_sync_step(scheduler);
    int complete = !d2k_sched_sync_pending(scheduler);
    d2k_sched_free(scheduler);
    close(sockets[0]);
    close(sockets[1]);
    d2k_catalog_free(&catalog);
    printf("D2O_AREA_DELETE_ORDER_COMPLETE=%d\n", complete);
    return complete ? 0 : 2;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--http-bound-set") == 0) return http_bound_set_wire();
    if (argc == 2 && strcmp(argv[1], "--http-bound-del") == 0) return http_bound_del_wire();
    if (argc == 2 && strcmp(argv[1], "--area-wire") == 0) return area_wire();
    int area_pending_mode = argc == 4 && strcmp(argv[3], "--area-pending") == 0;
    int area_timeout_mode = argc == 4 && strcmp(argv[3], "--area-timeout") == 0;
    int area_timeout_delete_mode = argc == 4 && strcmp(argv[3], "--area-timeout-delete") == 0;
    int area_delete_order_mode = argc == 4 && strcmp(argv[3], "--area-delete-order") == 0;
    int first_batch = argc == 4 && strcmp(argv[3], "--first-batch") == 0;
    if (argc != 3 && !first_batch && !area_pending_mode && !area_timeout_mode &&
        !area_timeout_delete_mode && !area_delete_order_mode) return 2;
    char *end = NULL;
    unsigned long parsed_cap = strtoul(argv[2], &end, 10);
    if (!end || *end || parsed_cap > UINT32_MAX) return 2;
    if (area_pending_mode) return area_pending(argv[1], (uint32_t)parsed_cap);
    if (area_timeout_mode) return area_timeout(argv[1], (uint32_t)parsed_cap);
    if (area_timeout_delete_mode) return area_timeout_delete(argv[1], (uint32_t)parsed_cap);
    if (area_delete_order_mode) return area_delete_order(argv[1], (uint32_t)parsed_cap);

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
