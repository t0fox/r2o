/* C/Rust differential: static plan helpers wr16/wr24/cmp_size. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plan_apply.c"

static void print_hex(const uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", bytes[i]);
    }
}

int main(void) {
    static const size_t u16_values[] = {0, 1, 0xff, 0x100, 0xffff, 0x10000,
                                        0xffffff, 0x1000000};
    static const size_t u24_values[] = {0, 1, 0xff, 0x100, 0xffff, 0x10000,
                                        0xffffff, 0x1000000};
    for (size_t i = 0; i < sizeof u16_values / sizeof u16_values[0]; i++) {
        uint8_t bytes[2] = {0xaa, 0xaa};
        wr16(bytes, 0, u16_values[i]);
        printf("wr16 %zu ", u16_values[i]);
        print_hex(bytes, sizeof bytes);
        printf("\n");
    }
    for (size_t i = 0; i < sizeof u24_values / sizeof u24_values[0]; i++) {
        uint8_t bytes[3] = {0xaa, 0xaa, 0xaa};
        wr24(bytes, 0, u24_values[i]);
        printf("wr24 %zu ", u24_values[i]);
        print_hex(bytes, sizeof bytes);
        printf("\n");
    }
    size_t values[] = {9, 1, 7, 1, 0xffff, 0, 7, 0x10000};
    size_t count = sizeof values / sizeof values[0];
    qsort(values, count, sizeof values[0], cmp_size);
    printf("sort");
    for (size_t i = 0; i < count; i++) {
        printf(" %zu", values[i]);
    }
    printf("\n");
    return 0;
}
