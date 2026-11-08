#include "tg_dc_map.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t file_count(const char *path, int64_t now) {
    FILE *file = fopen(path, "rb");
    if (!file) return 0;
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (length <= 0) {
        fclose(file);
        return 0;
    }
    uint8_t *bytes = malloc((size_t)length);
    if (!bytes) {
        fclose(file);
        return 0;
    }
    size_t used = fread(bytes, 1, (size_t)length, file);
    fclose(file);
    tg_dc_snapshot snapshot = {0};
    int rc = tg_dc_snapshot_parse_json(bytes, used, now, &snapshot);
    size_t count = rc == 0 ? snapshot.endpoint_count : 0;
    tg_dc_snapshot_destroy(&snapshot);
    free(bytes);
    return count;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int64_t now = strtoll(argv[2], NULL, 10);
    tg_dc_map_store store;
    if (tg_dc_map_store_init(&store, argv[1]) != 0) return 3;
    int loaded = tg_dc_map_store_load(&store, now);
    const tg_dc_snapshot *current = tg_dc_map_store_current(&store);
    printf("load rc=%d count=%zu file=%zu\n", loaded,
           current ? current->endpoint_count : 0, file_count(argv[1], now));

    tg_dc_snapshot incoming = {0};
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 4;
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t *bytes = malloc((size_t)length);
    if (!bytes) return 4;
    size_t used = fread(bytes, 1, (size_t)length, file);
    fclose(file);
    int parsed = tg_dc_snapshot_parse_json(bytes, used, now, &incoming);
    free(bytes);
    if (parsed != 0) return 5;
    int installed = tg_dc_map_store_install(&store, &incoming, now);
    current = tg_dc_map_store_current(&store);
    printf("install rc=%d count=%zu file=%zu\n", installed,
           current ? current->endpoint_count : 0, file_count(argv[1], now));
    tg_dc_snapshot_destroy(&incoming);
    tg_dc_map_store_destroy(&store);
    return 0;
}
