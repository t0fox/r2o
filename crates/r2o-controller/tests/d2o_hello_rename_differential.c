/* C-оракул: d2k_hello_rename/splice_sni (core/hello.c:409-535).
 *
 * Использование: d2o-hello-rename DIR CASES
 * На входе — полные TLS-записи; оракул передаёт d2k_hello_rename тело
 * ClientHello (байты после 5-байтной записи) и печатает результат.
 */
#define _POSIX_C_SOURCE 200809L
#include "d2k_hello.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEMPLATE_MAX 4096

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

static void print_hex(const uint8_t *bytes, size_t length) {
    if (!length) return;
    for (size_t index = 0; index < length; index++) printf("%02x", bytes[index]);
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
        const uint8_t *body = bytes_len >= 5 ? bytes + 5 : bytes;
        size_t body_len = bytes_len >= 5 ? bytes_len - 5 : bytes_len;
        uint8_t out[TEMPLATE_MAX];
        size_t out_len = 0;
        int rc = d2k_hello_rename(body, body_len, "new.example", out, sizeof out,
                                  &out_len);
        printf("%s rename=%d len=%zu hex=", name, rc == 0 ? 0 : -1, out_len);
        if (rc == 0) print_hex(out, out_len);
        printf("\n");
        free(bytes);
    }
    fclose(cases);
    return 0;
}
