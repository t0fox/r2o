/* C-оракул: production `level_name` из core/sched.c. */
#include "sched.c"

#include <stdio.h>

int main(void)
{
    for (int level = -2; level <= 7; level++) {
        printf("%d %s\n", level, level_name(level));
    }
    return 0;
}
