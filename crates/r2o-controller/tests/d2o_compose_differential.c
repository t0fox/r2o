/* CL15: C-оракул d2k_compose (d2k-plan text). */
#include "d2k_compose.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    d2k_props props;
    d2k_shape shape;
    const char *decoy;
    size_t send_cap;
    size_t cap;
} test_case;

static void print_case(const test_case *test) {
    char out[8][4096];
    size_t cap = test->cap < 8 ? test->cap : 8;
    size_t count = d2k_compose(&test->props, test->shape, test->decoy,
                               test->send_cap, out, cap);
    printf("case %s\nn=%zu\n", test->name, count);
    for (size_t i = 0; i < count; i++) {
        printf("plan %zu\n%s", i, out[i]);
        size_t length = strlen(out[i]);
        if (length && out[i][length - 1] != '\n') printf("\n");
    }
}

int main(void) {
    static const test_case cases[] = {
        { "empty-legacy", { 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 8 },
        { "empty-modern", { 0 }, D2K_SHAPE_MODERN, "disk.rzd.ru", 0, 8 },
        { "empty-unknown", { 0 }, D2K_SHAPE_UNKNOWN, "disk.rzd.ru", 0, 8 },
        { "empty-no-decoy", { 0 }, D2K_SHAPE_LEGACY, NULL, 0, 8 },
        { "empty-empty-decoy", { 0 }, D2K_SHAPE_LEGACY, "", 0, 8 },
        { "overlap-no", { D2K_P_NO, 0, 0, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 8 },
        { "overlap-yes", { D2K_P_YES, 0, 0, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 8 },
        { "reorder-no", { 0, D2K_P_NO, 0, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 8 },
        { "reorder-yes", { 0, D2K_P_YES, 0, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 8 },
        { "checksum-no", { 0, 0, D2K_P_NO, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 8 },
        { "checksum-no-parse-yes", { 0, 0, D2K_P_NO, D2K_P_YES, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 8 },
        { "duplicates-yes", { 0, 0, 0, 0, D2K_P_YES }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 8 },
        { "parse-yes", { 0, 0, 0, D2K_P_YES, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 8 },
        { "overlap-reorder-no", { D2K_P_NO, D2K_P_NO, 0, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 8 },
        { "all-mixed", { D2K_P_NO, D2K_P_NO, D2K_P_NO, D2K_P_YES, D2K_P_YES }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 8 },
        { "duplicates-modern", { 0, 0, 0, 0, D2K_P_YES }, D2K_SHAPE_MODERN, "disk.rzd.ru", 0, 8 },
        { "parse-modern", { 0, 0, 0, D2K_P_YES, 0 }, D2K_SHAPE_MODERN, "disk.rzd.ru", 0, 8 },
        { "duplicates-no-decoy", { 0, 0, 0, 0, D2K_P_YES }, D2K_SHAPE_LEGACY, NULL, 0, 8 },
        { "parse-no-decoy", { 0, 0, 0, D2K_P_YES, 0 }, D2K_SHAPE_LEGACY, NULL, 0, 8 },
        { "duplicates-empty-decoy", { 0, 0, 0, 0, D2K_P_YES }, D2K_SHAPE_LEGACY, "", 0, 8 },
        { "parse-empty-decoy", { 0, 0, 0, D2K_P_YES, 0 }, D2K_SHAPE_LEGACY, "", 0, 8 },
        { "empty-sendcap-100", { 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 100, 8 },
        { "empty-sendcap-120", { 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 120, 8 },
        { "empty-sendcap-200", { 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 200, 8 },
        { "all-mixed-sendcap-1500", { D2K_P_NO, D2K_P_NO, D2K_P_NO, D2K_P_YES, D2K_P_YES }, D2K_SHAPE_MODERN, "disk.rzd.ru", 1500, 8 },
        { "overlap-cap-1", { D2K_P_NO, 0, 0, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 1 },
        { "overlap-cap-0", { D2K_P_NO, 0, 0, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 0 },
        { "empty-cap-0", { 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 0 },
        { "all-mixed-cap-2", { D2K_P_NO, D2K_P_NO, D2K_P_NO, D2K_P_YES, D2K_P_YES }, D2K_SHAPE_LEGACY, "disk.rzd.ru", 0, 2 },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        print_case(&cases[i]);
    }
    return 0;
}
