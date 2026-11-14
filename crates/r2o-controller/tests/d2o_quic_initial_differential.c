/* C-оракул: d2k_quic_is_initial (core/quic.c:182-185).
 *
 * Использование: d2o-quic-initial DIR CASES
 */
#define _POSIX_C_SOURCE 200809L
#include "d2k_quic.h"

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
        printf("%s initial=%d\n", name, d2k_quic_is_initial(bytes, bytes_len));
        free(bytes);
    }
    fclose(cases);
    return 0;
}
