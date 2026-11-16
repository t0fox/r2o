/* compose.c сам определяет _POSIX_C_SOURCE до libc-заголовков, поэтому
 * включаем его первым: иначе glibc/zig-заголовки фиксируют другой уровень. */
#include "compose.c"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void show(const char *name, int rc, const uint8_t *buf, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    if (rc != 0) {
        printf("%s -\n", name);
        return;
    }
    printf("%s ", name);
    for (size_t i = 0; i < len; i++) {
        putchar(digits[buf[i] >> 4]);
        putchar(digits[buf[i] & 0x0f]);
    }
    putchar('\n');
}

int main(void)
{
    uint8_t buf[4096];
    size_t len = 0;
    show("overlap", overlap_plan_tlv(buf, sizeof buf, &len), buf, len);
    show("reorder", reorder_plan_tlv(buf, sizeof buf, &len), buf, len);
    uint8_t filler[64];
    memset(filler, D2K_OVERLAP_FILLER, sizeof filler);
    show("badsum", badsum_fake_plan_tlv(filler, sizeof filler, 1, 0, buf, sizeof buf, &len),
         buf, len);
    show("badsum_gap", badsum_fake_plan_tlv((const uint8_t *)"hello", 5, 2, 20000,
                                            buf, sizeof buf, &len),
         buf, len);
    show("checksum", checksum_plan_tlv(buf, sizeof buf, &len), buf, len);
    return 0;
}
