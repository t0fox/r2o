/* C-оракул: production `box_injects_rst`, `rst_guard_wanted` и
 * `plan_arm_rst_guard` из core/sched.c. */
#include "sched.c"

#include <stdio.h>
#include <string.h>

static void box_case(const char *label, const char *const *kinds, size_t count)
{
    static d2k_cat_box box;
    memset(&box, 0, sizeof box);
    box.fp.n_sig = count;
    for (size_t index = 0; index < count; index++) {
        snprintf(box.fp.sig[index].kind, sizeof box.fp.sig[index].kind,
                 "%s", kinds[index]);
    }
    printf("box %s=%d\n", label, box_injects_rst(&box));
}

static void guard_case(uint8_t transport, uint8_t code)
{
    static task t;
    memset(&t, 0, sizeof t);
    t.transport = transport;
    t.trigger_code = code;
    printf("guard t=%u c=%u=%d\n", (unsigned)transport, (unsigned)code,
           rst_guard_wanted(&t));
}

static void arm_case(const char *label, const char *text, size_t cap)
{
    char buffer[8192];
    snprintf(buffer, sizeof buffer, "%s", text);
    int rc = plan_arm_rst_guard(buffer, cap);
    printf("arm %s cap=%zu rc=%d text=", label, cap, rc);
    for (const char *p = buffer; *p; p++) {
        if (*p == '\n') {
            fputs("\\n", stdout);
        } else {
            putchar((unsigned char)*p);
        }
    }
    putchar('\n');
}

int main(void)
{
    box_case("empty", NULL, 0);
    {
        static const char *const volume[] = {"volume"};
        box_case("volume", volume, 1);
    }
    {
        static const char *const rst[] = {"rst"};
        box_case("rst", rst, 1);
    }
    {
        static const char *const both[] = {"volume", "rst"};
        box_case("both", both, 2);
    }
    {
        static const char *const upper[] = {"RST"};
        box_case("upper", upper, 1);
    }

    for (uint8_t code = 0; code <= 8; code++) {
        guard_case(6, code);
        guard_case(17, code);
    }

    const char *base =
        "r2o-plan 1 8\nid 00000000000000000000000000000000\nproto tcp tls\n";
    size_t length = strlen(base);
    arm_case("base", base, length + 16);
    arm_case("base", base, length + 17);
    arm_case("base", base, 64);
    arm_case("base", base, 4096);
    arm_case("existing",
             "r2o-plan 1 8\nid 00000000000000000000000000000000\nguard rst_alien\n",
             4096);
    arm_case("guard_word", "proto tcp tls\nguard\n", 4096);
    arm_case("empty", "", 16);
    arm_case("empty", "", 17);
    arm_case("utf8", "\xd0\xbf\xd0\xbb\xd0\xb0\xd0\xbd", 4096);
    return 0;
}
