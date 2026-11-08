/* TG4: C-оракул `tg_mtproto_config_parse` для TL-байтов help.getConfig.
 *
 * Использование: `d2o_config_trace NAME FILE NOW`
 * Печатает строку в том же формате, что Rust example `dc_config_trace.rs`.
 */
#include "tg_mtproto_discovery.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_address(const tg_dc_endpoint *endpoint) {
    size_t len = endpoint->family == AF_INET ? 4 : 16;
    for (size_t i = 0; i < len; i++) printf("%02x", endpoint->address[i]);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s NAME FILE NOW\n", argv[0]);
        return 2;
    }
    const char *name = argv[1];
    FILE *file = fopen(argv[2], "rb");
    if (!file) return 3;
    if (fseek(file, 0, SEEK_END) != 0) return 3;
    long length = ftell(file);
    if (length < 0) return 3;
    if (fseek(file, 0, SEEK_SET) != 0) return 3;
    uint8_t *bytes = malloc((size_t)length + 1);
    if (!bytes) return 3;
    size_t used = fread(bytes, 1, (size_t)length, file);
    fclose(file);
    if (used != (size_t)length) {
        free(bytes);
        return 3;
    }
    int64_t now = strtoll(argv[3], NULL, 10);
    tg_dc_snapshot snapshot = {0};
    int rc = tg_mtproto_config_parse(bytes, used, now, &snapshot);
    free(bytes);

    printf("%s ok=%d", name, rc == 0 ? 1 : 0);
    if (rc == 0) {
        printf(" schema=%u fetched=%" PRId64 " date=%" PRId64 " expires=%" PRId64
               " this_dc=%u count=%zu",
               snapshot.schema_version, snapshot.fetched_at,
               snapshot.config_date, snapshot.config_expires,
               snapshot.this_dc, snapshot.endpoint_count);
        for (size_t i = 0; i < snapshot.endpoint_count; i++) {
            const tg_dc_endpoint *endpoint = &snapshot.endpoints[i];
            printf(" e%zu=%u/%d/%u/%u/%u/%u/%u/%u/", i, endpoint->id,
                   (int)endpoint->family, endpoint->port, endpoint->media_only,
                   endpoint->tcpo_only, endpoint->cdn, endpoint->is_static,
                   endpoint->this_port_only);
            print_address(endpoint);
            printf("/%zu", endpoint->secret_len);
        }
    }
    putchar('\n');
    tg_dc_snapshot_destroy(&snapshot);
    return 0;
}
