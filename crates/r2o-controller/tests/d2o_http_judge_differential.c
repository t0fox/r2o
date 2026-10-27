#include <stdio.h>
#include <stdlib.h>
#include "d2k_httpsearch.h"

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 2;
    if (fseek(file, 0, SEEK_END) != 0) return 2;
    long size = ftell(file);
    if (size <= 1 || fseek(file, 0, SEEK_SET) != 0) return 2;
    char *response = malloc((size_t)size);
    if (!response) return 2;
    int ok = fread(response, 1, (size_t)size, file) == (size_t)size;
    fclose(file);
    if (!ok || response[size - 1] != '\0') {
        free(response);
        return 2;
    }
    printf("%d\n", (int)d2k_hs_judge(NULL, response, (size_t)size - 1, 100000, 100000));
    free(response);
    return 0;
}
