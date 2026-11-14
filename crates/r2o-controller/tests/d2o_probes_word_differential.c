/* C-оракул: probes_word (core/sched.c:5191-5201).
 *
 * sched.c включается целиком: нужна статическая функция. */
#include "sched.c"

#include <stdio.h>

int main(void) {
    for (int n = 0; n <= 130; n++) {
        printf("%d %s\n", n, probes_word(n));
    }
    return 0;
}
