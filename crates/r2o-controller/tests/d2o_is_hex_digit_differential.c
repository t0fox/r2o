/* C-оракул: production `is_hex_digit` из core/sched.c. */
#include "sched.c"

#include <stdio.h>

int main(void)
{
    for (int value = 0; value <= 255; value++) {
        printf("%d %d\n", value, is_hex_digit((char)value));
    }
    return 0;
}
