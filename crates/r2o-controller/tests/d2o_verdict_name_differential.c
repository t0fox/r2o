/* C-оракул: production `verdict_name` из core/sched.c (static — включаем TU). */
#include "sched.c"

#include <stdio.h>

int main(void)
{
    static const int codes[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 255};
    for (size_t index = 0; index < sizeof codes / sizeof codes[0]; index++) {
        printf("%d\t%s\n", codes[index], verdict_name((d2k_verdict)codes[index]));
    }
    return 0;
}
