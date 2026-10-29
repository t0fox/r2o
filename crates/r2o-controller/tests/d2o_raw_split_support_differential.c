#include <stdio.h>

#include "d2k_detect.h"

int main(void)
{
    const int has_cut = 1;
    const int no_raw = 0;
    printf("raw_split=%u\n", (unsigned)(has_cut && !no_raw && d2k_raw_supported()));
    return 0;
}
