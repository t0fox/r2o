/* C-оракул: тексты CLI d2kask — step_rc_str/ack_code_str/pval_str
 * (core/d2kask.c). TU включается целиком, main переименован. */
#define main d2kask_program_main
#include "d2kask.c"
#undef main

#include <stdio.h>

int main(void)
{
    for (int value = 0; value <= 12; value++) {
        printf("step %d %s\n", value, step_rc_str((d2k_step_rc)value));
    }
    for (int value = 0; value <= 8; value++) {
        printf("ack %d %s\n", value, ack_code_str((uint8_t)value));
    }
    for (int value = 0; value <= 3; value++) {
        printf("pval %d %s\n", value, pval_str((d2k_pval)value));
    }
    for (int mask = 0; mask < 16; mask++) {
        printf("seen %d ", mask);
        print_seen_types((uint8_t)mask);
        printf("\n");
    }
    return 0;
}
