/* C-оракул local_addr_for (detect/raw.c:556). */
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>

#include "raw.c"

int64_t d2k_now_ms(void) { return 0; }

static void run(const char *name, const uint8_t *dst, uint16_t port, uint8_t family)
{
    uint8_t out[16];
    memset(out, 0, sizeof out);
    int ok = local_addr_for(dst, port, out, family);
    printf("%s|%d|", name, ok);
    size_t n = family == 6 ? 16 : 4;
    for (size_t i = 0; i < n; i++) printf("%02x", out[i]);
    printf("\n");
}

int main(void)
{
    static const uint8_t v4[] = {127, 0, 0, 1};
    static const uint8_t v6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    run("v4-loopback", v4, 9, 4);
    run("v6-loopback", v6, 9, 6);
    return 0;
}
