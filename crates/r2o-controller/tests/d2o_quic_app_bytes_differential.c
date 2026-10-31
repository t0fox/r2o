#include <inttypes.h>
#include <stdio.h>

#include "d2k_quicwire.h"

static void add_and_print(d2k_qw_ranges *ranges, uint64_t offset, uint64_t length) {
    d2k_qw_ranges_add(ranges, offset, length, 0);
    printf("%" PRIu64 "\n", d2k_qw_ranges_bytes(ranges));
}

int main(void) {
    d2k_qw_ranges ranges;
    d2k_qw_ranges_reset(&ranges);

    add_and_print(&ranges, 0, 4);
    add_and_print(&ranges, 2, 8);
    add_and_print(&ranges, UINT64_C(1) << 32, UINT64_C(1) << 32);
    add_and_print(&ranges, (UINT64_C(3) << 32), UINT64_C(1) << 32);
    add_and_print(&ranges, (UINT64_C(3) << 32), UINT64_C(1) << 32);
    return 0;
}
