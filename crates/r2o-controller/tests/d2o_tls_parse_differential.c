/* CL12: C-оракул ClientHello/TLS1.2/1.3/ECH parser helpers.
 *
 * Использование: d2o-tls-parse DIR CASES
 */
#define _POSIX_C_SOURCE 200809L
#include "d2k_hello.h"
#include "d2k_tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    uint8_t *bytes = malloc((size_t)length + 1);
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

static const char *shape_name(d2k_shape shape) {
    switch (shape) {
    case D2K_SHAPE_MODERN: return "modern";
    case D2K_SHAPE_LEGACY: return "legacy";
    default: return "unknown";
    }
}

static void print_case(const char *name, const uint8_t *bytes, size_t length) {
    d2k_tls_info info = {0};
    d2k_tls_parse(bytes, length, &info);
    size_t sni_off = 0, sni_len = 0;
    int hello_sni = d2k_hello_sni(bytes, length, &sni_off, &sni_len);
    uint8_t config_id = 0;
    int hello_ech = d2k_hello_ech_offer(bytes, length, &config_id);
    printf(
        "%s tls=%d type=%u ch=%d sh=%d tls13=%d ech=%d trunc=%d "
        "sni=%d:%zu:%zu hello_sni=%d:%zu:%zu rec=%d:%zu mid=%d:%zu "
        "shape=%s complete=%d hello_ech=%d hello_ech_id=%u\n",
        name, info.is_tls_record, (unsigned)info.record_type,
        info.is_client_hello, info.is_server_hello, info.is_tls13,
        info.ech_offer, info.exts_truncated, info.have_sni, info.sni_off,
        info.sni_len, hello_sni == 0, sni_off, sni_len, info.have_record_end,
        info.record_end, info.have_hello_middle, info.hello_middle,
        shape_name(d2k_hello_shape(bytes, length)),
        d2k_hello_complete(bytes, length), hello_ech, (unsigned)config_id);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    FILE *cases = fopen(argv[2], "r");
    if (!cases) return 3;
    char name[256];
    while (fgets(name, sizeof name, cases)) {
        size_t length = strlen(name);
        while (length && (name[length - 1] == '\n' || name[length - 1] == '\r'))
            name[--length] = '\0';
        if (!length) continue;
        char path[4096];
        snprintf(path, sizeof path, "%s/%s.bin", argv[1], name);
        uint8_t *bytes = NULL;
        size_t bytes_len = 0;
        if (read_file(path, &bytes, &bytes_len) != 0) {
            printf("%s read-error\n", name);
            continue;
        }
        print_case(name, bytes, bytes_len);
        free(bytes);
    }
    fclose(cases);
    return 0;
}
