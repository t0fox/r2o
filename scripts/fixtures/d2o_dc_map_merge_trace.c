#include "dc_map_store.c"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char valid_json[] =
    "{\"schema_version\":1,\"fetched_at\":1800000000,"
    "\"config_date\":1799999900,\"config_expires\":1800086400,"
    "\"this_dc\":2,\"endpoints\":["
    "{\"id\":1,\"address\":\"149.154.175.50\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":true,\"cdn\":false,\"is_static\":true,\"this_port_only\":false,\"secret\":\"aabbccdd\",\"last_seen\":1800000000},"
    "{\"id\":2,\"address\":\"149.154.167.51\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000},"
    "{\"id\":3,\"address\":\"149.154.175.100\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000},"
    "{\"id\":4,\"address\":\"149.154.167.91\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000},"
    "{\"id\":5,\"address\":\"149.154.171.5\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}]}";

static char *insert(const char *json, const char *extra) {
    size_t base = strlen(json);
    if (base < 2) return NULL;
    size_t len = base - 2 + strlen(extra) + 4;
    char *out = malloc(len);
    if (!out) return NULL;
    memcpy(out, json, base - 2);
    snprintf(out + base - 2, len - (base - 2), ",%s]}", extra);
    return out;
}

static void print_snapshot(const char *name, int rc, const tg_dc_snapshot *snapshot) {
    printf("%s ok=%d", name, rc == 0 ? 1 : 0);
    if (rc == 0) {
        printf(" count=%zu", snapshot->endpoint_count);
        for (size_t i = 0; i < snapshot->endpoint_count; i++) {
            const tg_dc_endpoint *e = &snapshot->endpoints[i];
            printf(" e%zu=%u/%d/%u/%u/%u/%u/%u/%u/", i, e->id, (int)e->family,
                   e->port, e->media_only, e->tcpo_only, e->cdn, e->is_static,
                   e->this_port_only);
            size_t len = e->family == AF_INET ? 4 : 16;
            for (size_t b = 0; b < len; b++) printf("%02x", e->address[b]);
            printf("/%zu", e->secret_len);
        }
    }
    putchar('\n');
}

static void merge_case(const char *name, const char *previous_json,
                       const char *incoming_json, int64_t now) {
    tg_dc_snapshot previous = {0}, incoming = {0}, merged = {0};
    int prev_ok = previous_json
        ? tg_dc_snapshot_parse_json((const uint8_t *)previous_json,
                                    strlen(previous_json), now, &previous)
        : -1;
    int in_ok = tg_dc_snapshot_parse_json((const uint8_t *)incoming_json,
                                          strlen(incoming_json), now, &incoming);
    if (in_ok != 0 || (previous_json && prev_ok != 0)) {
        printf("%s ok=0 parse-previous=%d parse-incoming=%d\n", name, prev_ok, in_ok);
        tg_dc_snapshot_destroy(&previous);
        tg_dc_snapshot_destroy(&incoming);
        return;
    }
    int rc = merge_snapshot(previous_json ? &previous : NULL, &incoming, now, &merged);
    print_snapshot(name, rc, &merged);
    tg_dc_snapshot_destroy(&previous);
    tg_dc_snapshot_destroy(&incoming);
    tg_dc_snapshot_destroy(&merged);
}

int main(void) {
    const int64_t now = INT64_C(1800000000);
    merge_case("same", valid_json, valid_json, now);

    {
        const char *older = "{\"schema_version\":1,\"fetched_at\":1799999000,"
            "\"config_date\":1799999000,\"config_expires\":1800086400,"
            "\"this_dc\":2,\"endpoints\":["
            "{\"id\":1,\"address\":\"149.154.175.50\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000},"
            "{\"id\":2,\"address\":\"149.154.167.51\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000},"
            "{\"id\":3,\"address\":\"149.154.175.100\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000},"
            "{\"id\":4,\"address\":\"149.154.167.91\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000},"
            "{\"id\":5,\"address\":\"149.154.171.5\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000}]}";
        merge_case("older", valid_json, older, now);
    }

    {
        char *previous = insert(valid_json,
            "{\"id\":6,\"address\":\"8.8.8.8\",\"port\":443,\"ipv6\":false,"
            "\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,"
            "\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000},"
            "{\"id\":7,\"address\":\"1.1.1.1\",\"port\":443,\"ipv6\":false,"
            "\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,"
            "\"this_port_only\":false,\"secret\":null,\"last_seen\":1792223999},"
            "{\"id\":9,\"address\":\"149.154.167.51\",\"port\":443,\"ipv6\":false,"
            "\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,"
            "\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000}");
        merge_case("retain-expire-replace", previous, valid_json, now);
        free(previous);
    }

    {
        char *previous = insert(valid_json,
            "{\"id\":2,\"address\":\"149.154.167.51\",\"port\":443,\"ipv6\":false,"
            "\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,"
            "\"this_port_only\":false,\"secret\":null,\"last_seen\":1799999000}");
        merge_case("identity-ignores-static", previous, valid_json, now);
        free(previous);
    }

    {
        char *incoming = insert(valid_json,
            "{\"id\":4,\"address\":\"149.154.167.43\",\"port\":443,\"ipv6\":false,"
            "\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,"
            "\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}");
        merge_case("builtin-conflict", valid_json, incoming, now);
        free(incoming);
    }
    return 0;
}
