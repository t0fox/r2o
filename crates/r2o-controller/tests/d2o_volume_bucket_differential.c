/* C-оракул: production `volume_bucket` из core/sched.c. */
#include "sched.c"

#include <stdio.h>

int main(void)
{
    static const int cases[] = {
        -2147483647 - 1, -1, 0, 1, 2, 3, 4, 7, 8, 15, 16, 19, 23, 27,
        31, 32, 35, 63, 64, 127, 128, 255, 256, 1023, 1024, 16383,
        16384, 2147483647,
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        printf("%d %d\n", cases[i], volume_bucket(cases[i]));
    }
    return 0;
}
