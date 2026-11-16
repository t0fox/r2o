/* compose.c сам определяет _POSIX_C_SOURCE до libc-заголовков, поэтому
 * включаем его первым: иначе glibc/zig-заголовки фиксируют другой уровень. */
#include "compose.c"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *buf, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        putchar(digits[buf[i] >> 4]);
        putchar(digits[buf[i] & 0x0f]);
    }
}

static void show(const char *name, int rc, const uint8_t *buf, size_t len)
{
    if (rc != 0) {
        printf("%s rc=-1\n", name);
        return;
    }
    uint8_t stamped[4096];
    if (len > sizeof stamped) {
        printf("%s rc=-1\n", name);
        return;
    }
    memcpy(stamped, buf, len);
    uint8_t id[D2K_PLAN_ID_LEN];
    if (plan_tlv_stamp_ident(stamped, len, id) != 0) {
        printf("%s rc=-1\n", name);
        return;
    }
    printf("%s id=", name);
    print_hex(id, sizeof id);
    printf(" tlv=");
    print_hex(stamped, len);
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

    uint8_t id[D2K_PLAN_ID_LEN];
    uint8_t short_tlv[31] = {0};
    printf("short rc=%d\n", plan_tlv_stamp_ident(short_tlv, sizeof short_tlv, id));
    uint8_t wrong_type[32] = {0};
    printf("wrong_type rc=%d\n", plan_tlv_stamp_ident(wrong_type, sizeof wrong_type, id));
    uint8_t wrong_len[32] = {0};
    wrong_len[13] = 1;
    wrong_len[15] = 15;
    printf("wrong_len rc=%d\n", plan_tlv_stamp_ident(wrong_len, sizeof wrong_len, id));
    return 0;
}
