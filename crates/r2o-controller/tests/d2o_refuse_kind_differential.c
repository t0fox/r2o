/* C-оракул: production `refuse_is_permanent`/`refuse_is_damage`
 * из core/sched.c. */
#include "sched.c"

#include <stdio.h>

int main(void)
{
    for (int value = 0; value <= 255; value++) {
        printf("%d %d %d\n", value,
               refuse_is_permanent((uint8_t)value),
               refuse_is_damage((uint8_t)value));
    }
    return 0;
}
