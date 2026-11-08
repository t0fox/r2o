#include "d2k_compose.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    d2k_props props;
    d2k_shape shape;
    const char *decoy;
} test_case;

int main(void) {
    static const test_case cases[] = {
        { "empty", { 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru" },
        { "overlap-no", { D2K_P_NO, 0, 0, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru" },
        { "overlap-yes", { D2K_P_YES, 0, 0, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru" },
        { "reorder-no", { 0, D2K_P_NO, 0, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru" },
        { "reorder-yes", { 0, D2K_P_YES, 0, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru" },
        { "checksum-no", { 0, 0, D2K_P_NO, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru" },
        { "checksum-no-parse-yes", { 0, 0, D2K_P_NO, D2K_P_YES, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru" },
        { "duplicates-yes", { 0, 0, 0, 0, D2K_P_YES }, D2K_SHAPE_LEGACY, "disk.rzd.ru" },
        { "parse-yes", { 0, 0, 0, D2K_P_YES, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru" },
        { "overlap-reorder-no", { D2K_P_NO, D2K_P_NO, 0, 0, 0 }, D2K_SHAPE_LEGACY, "disk.rzd.ru" },
        { "all-mixed", { D2K_P_NO, D2K_P_NO, D2K_P_NO, D2K_P_YES, D2K_P_YES }, D2K_SHAPE_LEGACY, "disk.rzd.ru" },
    };
    char out[8][4096];
    for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        size_t n = d2k_compose(&cases[c].props, cases[c].shape, cases[c].decoy, 0, out, 8);
        printf("case %s\nn=%zu\n", cases[c].name, n);
        for (size_t i = 0; i < n; i++) {
            const char *body = strchr(out[i], '\n');
            body = body ? body + 1 : out[i] + strlen(out[i]);
            printf("plan\n%s", body);
            if (body[0] && body[strlen(body) - 1] != '\n') printf("\n");
        }
    }
    return 0;
}
