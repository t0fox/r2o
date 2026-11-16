#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "link.c"

static void run_case(const char *label, const char *text, size_t cap)
{
    uint8_t output[64];
    int rc = hex_decode(text, output, cap);
    if (rc < 0) {
        printf("%s\trc=-1\thex=-\n", label);
        return;
    }
    char hex[129];
    static const char digits[] = "0123456789abcdef";
    for (int i = 0; i < rc; i++) {
        hex[2 * i] = digits[output[i] >> 4];
        hex[2 * i + 1] = digits[output[i] & 0x0f];
    }
    hex[2 * rc] = '\0';
    printf("%s\trc=0\thex=%s\n", label, hex);
}

int main(void)
{
    run_case("empty", "", 16);
    run_case("one", "00", 16);
    run_case("mixed", "0aFf", 16);
    run_case("invalid_high", "g0", 16);
    run_case("invalid_low", "0g", 16);
    run_case("cap_exact", "0011", 2);
    return 0;
}
