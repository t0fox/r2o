/* C/Rust differential: install_next боковой эффект `rst_guard_wanted` +
 * `plan_arm_rst_guard` (core/sched.c:4013-4031). */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>

#include "sched.c"

static void print_hex(const char *text)
{
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        printf("%02x", *p);
    }
}

int main(void)
{
    task t;
    memset(&t, 0, sizeof t);
    t.transport = 6;
    const uint8_t codes[] = {1, 2, 3, 4, 5, 6, 8};
    for (size_t i = 0; i < sizeof codes; i++) {
        t.trigger_code = codes[i];
        printf("code_%u=%d\n", codes[i], rst_guard_wanted(&t));
    }
    const char *base =
        "r2o-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\n"
        "split sni_middle +0\n";
    char armed[4096];
    snprintf(armed, sizeof armed, "%s", base);
    printf("arm_added=%d\n", plan_arm_rst_guard(armed, sizeof armed));
    printf("arm1="); print_hex(armed); printf("\n");
    printf("arm_added_twice=%d\n", plan_arm_rst_guard(armed, sizeof armed));
    printf("arm2="); print_hex(armed); printf("\n");
    const char *existing =
        "r2o-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\n"
        "guard rst_alien\n";
    char kept[4096];
    snprintf(kept, sizeof kept, "%s", existing);
    printf("existing_added=%d\n", plan_arm_rst_guard(kept, sizeof kept));
    printf("existing="); print_hex(kept); printf("\n");
    return 0;
}
