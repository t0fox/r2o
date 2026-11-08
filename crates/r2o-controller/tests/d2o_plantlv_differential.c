/* M6: C-оракул plantlv — текст плана в TLV.
 *
 * Кейсы берутся из общей фикстуры, чтобы C и Rust читали одни и те же
 * тексты. Печатается только результат и байты: текст ошибки у C и Rust
 * разный, для паритета важны принятие/отказ и точные TLV-байты. */
#include "d2k_plantlv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    long size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    char *data = malloc((size_t)size + 1);
    if (!data) {
        fclose(file);
        return NULL;
    }
    if (fread(data, 1, (size_t)size, file) != (size_t)size) {
        free(data);
        fclose(file);
        return NULL;
    }
    fclose(file);
    data[size] = '\0';
    *length = (size_t)size;
    return data;
}

static void run_case(const char *name, size_t name_len, const char *text,
                     size_t text_len) {
    char *copy = malloc(text_len + 1);
    uint8_t raw[65536];
    size_t length = 0;
    char error[256];
    if (!copy) {
        return;
    }
    memcpy(copy, text, text_len);
    copy[text_len] = '\0';

    printf("case %.*s\n", (int)name_len, name);
    int result = d2k_plan_text_to_tlv(copy, raw, sizeof raw, &length, error,
                                      sizeof error);
    free(copy);
    if (result != 0) {
        printf("result err\n");
        return;
    }
    printf("result ok\nhex ");
    for (size_t i = 0; i < length; i++) {
        printf("%02x", raw[i]);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s FIXTURE\n", argv[0]);
        return 2;
    }
    size_t file_length = 0;
    char *data = read_file(argv[1], &file_length);
    if (!data) {
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return 2;
    }

    const char *cursor = data;
    const char *end = data + file_length;
    const char *name = NULL;
    size_t name_len = 0;
    const char *text = NULL;

    while (cursor < end) {
        const char *line_end = memchr(cursor, '\n', (size_t)(end - cursor));
        size_t line_len = line_end ? (size_t)(line_end - cursor) : (size_t)(end - cursor);
        if (line_len >= 4 && memcmp(cursor, "### ", 4) == 0) {
            if (name) {
                run_case(name, name_len, text, (size_t)(cursor - text));
            }
            name = cursor + 4;
            name_len = line_len - 4;
            text = line_end ? line_end + 1 : end;
        }
        cursor = line_end ? line_end + 1 : end;
    }
    if (name) {
        run_case(name, name_len, text, (size_t)(end - text));
    }

    free(data);
    return 0;
}
