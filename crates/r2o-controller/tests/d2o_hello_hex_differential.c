/* C-оракул: статический hex_decode из core/hello.c (480-498).
 *
 * `hello.c` включается целиком, чтобы вызвать статическую функцию без
 * копирования её тела. Использование: d2o-hello-hex CASES
 */
#define _POSIX_C_SOURCE 200809L
#include "hello.c"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *cases = fopen(argv[1], "r");
    if (!cases) return 3;
    char line[4096];
    while (fgets(line, sizeof line, cases)) {
        size_t length = strlen(line);
        while (length && (line[length - 1] == '\n' || line[length - 1] == '\r'))
            line[--length] = '\0';
        uint8_t out[16];
        size_t out_len = 0;
        int rc = hex_decode(line, length, out, sizeof out, &out_len);
        printf("%s rc=%d len=%zu hex=", line, rc == 0 ? 0 : -1, out_len);
        if (rc == 0) {
            for (size_t index = 0; index < out_len; index++) printf("%02x", out[index]);
        }
        printf("\n");
    }
    fclose(cases);
    return 0;
}
