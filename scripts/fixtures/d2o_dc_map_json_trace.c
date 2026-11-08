#include "tg_dc_map.h"

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

static void report(const char *name, const char *json, size_t len, int64_t now) {
    tg_dc_snapshot snapshot = {0};
    int rc = tg_dc_snapshot_parse_json((const uint8_t *)json, len, now, &snapshot);
    printf("%s ok=%d", name, rc == 0 ? 1 : 0);
    if (rc == 0) {
        printf(" schema=%u fetched=%" PRId64 " date=%" PRId64 " expires=%" PRId64
               " this_dc=%u count=%zu",
               snapshot.schema_version, snapshot.fetched_at, snapshot.config_date,
               snapshot.config_expires, snapshot.this_dc, snapshot.endpoint_count);
        for (size_t i = 0; i < snapshot.endpoint_count; i++) {
            const tg_dc_endpoint *endpoint = &snapshot.endpoints[i];
            printf(" e%zu=%u/%d/%u/%u/%u/%u/%u/%u/%zu",
                   i, endpoint->id, (int)endpoint->family, endpoint->port,
                   endpoint->media_only, endpoint->tcpo_only, endpoint->cdn,
                   endpoint->is_static, endpoint->this_port_only,
                   endpoint->secret_len);
        }
    }
    putchar('\n');
    tg_dc_snapshot_destroy(&snapshot);
}

static char *with_endpoint(const char *endpoint) {
    size_t base = sizeof valid_json - 1;
    if (base < 2) return NULL;
    size_t len = base - 2 + strlen(endpoint) + 4;
    char *json = malloc(len);
    if (!json) return NULL;
    memcpy(json, valid_json, base - 2);
    snprintf(json + base - 2, len - (base - 2), ",%s]}", endpoint);
    return json;
}

int main(void) {
    report("valid", valid_json, sizeof valid_json - 1, INT64_C(1800000000));
    report("duplicate", "{\"schema_version\":1,\"schema_version\":1}", 43,
           INT64_C(1800000000));
    report("unknown", "{\"unexpected\":true}", 19, INT64_C(1800000000));

    const char *bad_address =
        "{\"schema_version\":1,\"fetched_at\":1800000000,"
        "\"config_date\":1799999900,\"config_expires\":1800086400,"
        "\"this_dc\":2,\"endpoints\":[{\"id\":1,\"address\":\"bad\"}]}";
    report("bad-address", bad_address, strlen(bad_address), INT64_C(1800000000));
    {
        const char *marker = "\"this_dc\":2,";
        const char *at = strstr(valid_json, marker);
        if (!at) return 2;
        size_t offset = (size_t)(at - valid_json) + strlen(marker);
        size_t len = sizeof valid_json - 1 + strlen(marker);
        char *duplicate = malloc(len + 1);
        if (!duplicate) return 2;
        memcpy(duplicate, valid_json, offset);
        memcpy(duplicate + offset, marker, strlen(marker));
        memcpy(duplicate + offset + strlen(marker), valid_json + offset,
               sizeof valid_json - 1 - offset);
        duplicate[len] = '\0';
        report("duplicate-valid", duplicate, len, INT64_C(1800000000));
        free(duplicate);
    }
    report("future-clock", valid_json, sizeof valid_json - 1, INT64_MIN);

    char *oversized = malloc(1024u * 1024u + 2u);
    size_t valid_len = sizeof valid_json - 1;
    memcpy(oversized, valid_json, valid_len);
    memset(oversized + valid_len, ' ', 1024u * 1024u + 1u - valid_len);
    report("oversized", oversized, 1024u * 1024u + 1u, INT64_C(1800000000));
    free(oversized);

    const char *wrong_schema =
        "{\"schema_version\":2,\"fetched_at\":1800000000,"
        "\"config_date\":1799999900,\"config_expires\":1800086400,"
        "\"this_dc\":2,\"endpoints\":[]}";
    report("wrong-schema", wrong_schema, strlen(wrong_schema), INT64_C(1800000000));

    char *endpoint = with_endpoint(
        "{\"id\":1,\"address\":\"100.64.0.1\",\"port\":443,\"ipv6\":false,"
        "\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,"
        "\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}");
    report("cgnat", endpoint, strlen(endpoint), INT64_C(1800000000));
    free(endpoint);

    endpoint = with_endpoint(
        "{\"id\":1,\"address\":\"::ffff:127.0.0.1\",\"port\":443,\"ipv6\":true,"
        "\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,"
        "\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}");
    report("v4-mapped-loopback", endpoint, strlen(endpoint), INT64_C(1800000000));
    free(endpoint);

    endpoint = with_endpoint(
        "{\"id\":1,\"address\":\"2001:db8::1\",\"port\":443,\"ipv6\":true,"
        "\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,"
        "\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}");
    report("documentation-v6", endpoint, strlen(endpoint), INT64_C(1800000000));
    free(endpoint);

    endpoint = with_endpoint(
        "{\"id\":1,\"address\":\"149.154.175.50\",\"port\":443,\"ipv6\":true,"
        "\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,"
        "\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}");
    report("ipv6-flag-mismatch", endpoint, strlen(endpoint), INT64_C(1800000000));
    free(endpoint);

    endpoint = with_endpoint(
        "{\"id\":1,\"address\":\"149.154.175.50\",\"port\":443,\"ipv6\":false,"
        "\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,"
        "\"this_port_only\":false,\"secret\":\"abc\",\"last_seen\":1800000000}");
    report("odd-secret", endpoint, strlen(endpoint), INT64_C(1800000000));
    free(endpoint);
    return 0;
}
