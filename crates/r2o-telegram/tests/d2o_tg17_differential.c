/* TG17: C-оракул official secret/DD.
 *
 * Modes:
 *   d2o_tg17 secrets SNAPSHOT NOW
 *   d2o_tg17 route SNAPSHOT NOW HANDSHAKE_DIR
 */
#define _POSIX_C_SOURCE 200809L
#include "tg_transparent.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NOW_CONST INT64_C(1800000000)

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *file = fopen(path, "rb");
    if (!file) return -1;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    long length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }
    uint8_t *bytes = malloc((size_t)length);
    if (!bytes) {
        fclose(file);
        return -1;
    }
    size_t used = fread(bytes, 1, (size_t)length, file);
    fclose(file);
    if (used != (size_t)length) {
        free(bytes);
        return -1;
    }
    *out = bytes;
    *out_len = used;
    return 0;
}

static int parse_destination(const char *text, uint16_t port,
                             tg_listener_destination *out) {
    memset(out, 0, sizeof(*out));
    out->port = port;
    if (inet_pton(AF_INET, text, out->address) == 1) {
        out->family = AF_INET;
        return 0;
    }
    if (inet_pton(AF_INET6, text, out->address) == 1) {
        out->family = AF_INET6;
        return 0;
    }
    return -1;
}

static int load_snapshot(const char *path, int64_t now, tg_dc_snapshot *out) {
    uint8_t *bytes = NULL;
    size_t length = 0;
    if (read_file(path, &bytes, &length) != 0) return -1;
    int rc = tg_dc_snapshot_parse_json(bytes, length, now, out);
    free(bytes);
    return rc;
}

static void print_secret_hex(const tg_dc_secret *secret) {
    for (size_t i = 0; i < secret->len; i++) printf("%02x", secret->bytes[i]);
}

static void secrets_mode(const char *snapshot_path) {
    tg_dc_snapshot snapshot = {0};
    if (load_snapshot(snapshot_path, NOW_CONST, &snapshot) != 0) {
        fprintf(stderr, "snapshot parse failed\n");
        exit(2);
    }
    const struct {
        const char *name;
        const char *address;
        uint16_t port;
        int64_t now;
    } cases[] = {
        {"exact", "149.154.167.151", 5222, NOW_CONST},
        {"mapped", "::ffff:149.154.167.151", 5222, NOW_CONST},
        {"port-zero", "149.154.167.151", 0, NOW_CONST},
        {"thisport-443", "149.154.167.156", 443, NOW_CONST},
        {"non-tcpo", "149.154.167.152", 5222, NOW_CONST},
        {"ipv6", "2001:67c:4e8:f005::a", 5222, NOW_CONST},
        {"empty-secret", "149.154.167.153", 5222, NOW_CONST},
        {"stale", "149.154.167.151", 5222, NOW_CONST + 90 * 24 * 60 * 60 + 1},
        {"many", "149.154.167.160", 5222, NOW_CONST},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        tg_listener_destination destination;
        if (parse_destination(cases[i].address, cases[i].port, &destination) != 0) {
            exit(3);
        }
        tg_dc_secret secrets[64] = {0};
        size_t count = tg_dc_handshake_secrets(&snapshot, &destination,
                                               cases[i].now, secrets, 64);
        printf("secrets %s count=%zu", cases[i].name, count);
        for (size_t j = 0; j < count; j++) {
            putchar(' ');
            print_secret_hex(&secrets[j]);
        }
        putchar('\n');
    }
    tg_dc_snapshot_destroy(&snapshot);
}

static const char *const route_cidrs[] = {
    "149.154.0.0/16", "2001:67c::/32", "0.0.0.0/0"
};

static void route_mode(const char *snapshot_path, const char *handshake_dir) {
    tg_dc_snapshot snapshot = {0};
    if (load_snapshot(snapshot_path, NOW_CONST, &snapshot) != 0) {
        fprintf(stderr, "snapshot parse failed\n");
        exit(2);
    }
    tg_dc_map_store store = {0};
    store.snapshot = snapshot;
    store.has_snapshot = 1;
    uint16_t ports[] = {443, 5222, 1443};
    tg_transparent_policy policy = {
        .map_store = &store,
        .allowed_ports = ports,
        .allowed_port_count = sizeof ports / sizeof ports[0],
        .allowed_cidrs = route_cidrs,
        .allowed_cidr_count = sizeof route_cidrs / sizeof route_cidrs[0],
    };

    const struct {
        const char *name;
        const char *file;
        const char *address;
        uint16_t port;
    } cases[] = {
        {"normal", "direct_dc4_media.bin", "149.154.167.91", 443},
        {"tcpo", "direct_dc2.bin", "149.154.167.151", 5222},
        {"secret", "secret_dc2.bin", "149.154.167.151", 5222},
        {"cdn", "direct_dc2.bin", "149.154.167.155", 443},
        {"ipv6", "direct_dc4_media.bin", "2001:67c:4e8:f004::a", 443},
        {"unlisted-no-dc", "direct_dc0.bin", "8.8.8.8", 443},
        {"unlisted-hint", "direct_dc2.bin", "8.8.8.8", 443},
        {"port80", "direct_dc4_media.bin", "149.154.167.91", 80},
        {"private", "direct_dc4_media.bin", "10.0.0.1", 443},
        {"this-port-mismatch", "direct_dc2.bin", "149.154.167.156", 443},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        char path[4096];
        snprintf(path, sizeof path, "%s/%s", handshake_dir, cases[i].file);
        uint8_t *handshake = NULL;
        size_t handshake_len = 0;
        if (read_file(path, &handshake, &handshake_len) != 0 ||
            handshake_len != TG_MTPROTO_HANDSHAKE_LEN) {
            fprintf(stderr, "handshake read failed: %s\n", path);
            exit(3);
        }
        tg_listener_destination destination;
        if (parse_destination(cases[i].address, cases[i].port, &destination) != 0) {
            exit(3);
        }
        tg_epoll_route_selection selection = {0};
        int rc = tg_transparent_select_route(&policy, &destination, handshake,
                                             &selection);
        free(handshake);
        if (rc != 0) {
            printf("route %s ok=0\n", cases[i].name);
            continue;
        }
        printf("route %s ok=1 dc=%u media=%d proto=%d tcp_only=%d\n",
               cases[i].name, selection.dc_id, selection.is_media,
               (int)selection.proto, selection.tcp_only);
    }
    tg_dc_map_store_destroy(&store);
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    if (strcmp(argv[1], "secrets") == 0 && argc == 3) {
        secrets_mode(argv[2]);
        return 0;
    }
    if (strcmp(argv[1], "route") == 0 && argc == 4) {
        route_mode(argv[2], argv[3]);
        return 0;
    }
    fprintf(stderr, "usage: %s secrets SNAPSHOT | route SNAPSHOT HANDSHAKE_DIR\n",
            argv[0]);
    return 2;
}
