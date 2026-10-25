#include <stdio.h>
#include "d2k_compose.h"

int main(void) {
    const size_t limits[] = {0, 1492, 1200, 100, 60};
    for (unsigned shape = 1; shape <= 2; shape++) {
        for (unsigned c = 0; c < sizeof limits / sizeof limits[0]; c++) {
            for (size_t index = 0; index <= d2k_fallback_arms(); index++) {
                char text[8192];
                int rc = d2k_fallback_plan(index, (d2k_shape)shape, "disk.rzd.ru", limits[c], text, sizeof text);
                printf("%u %zu %zu %s\n", shape, limits[c], index, rc == 0 ? "plan" : "skip");
                if (rc == 0) fputs(text, stdout);
            }
        }
    }
    return 0;
}
