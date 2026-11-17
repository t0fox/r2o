/* C-оракул: production `d2k_qw_ranges_*` из core/quicwire.c. */
#include "d2k_quicwire.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static d2k_qw_ranges ranges;

static void print_state(const char *label)
{
    printf("%s,%zu,", label, ranges.n);
    if (ranges.n == 0) {
        putchar('-');
    } else {
        for (size_t index = 0; index < ranges.n; index++) {
            printf("%s%" PRIu64 "-%" PRIu64, index ? ";" : "",
                   ranges.start[index], ranges.end[index]);
        }
    }
    printf(",%" PRIu64 ",%d,%d,%" PRIu64 "\n",
           d2k_qw_ranges_bytes(&ranges),
           d2k_qw_ranges_complete(&ranges),
           ranges.fin, ranges.fin_off);
}

int main(void)
{
    d2k_qw_ranges_reset(&ranges);
    print_state("empty");
    d2k_qw_ranges_add(&ranges, 0, 4, 0);
    print_state("first4");
    d2k_qw_ranges_add(&ranges, 2, 8, 0);
    print_state("merge_to10");
    d2k_qw_ranges_add(&ranges, 10, 5, 0);
    print_state("touch_to15");
    d2k_qw_ranges_add(&ranges, 20, 5, 0);
    print_state("gap");
    d2k_qw_ranges_add(&ranges, 15, 5, 0);
    print_state("fill_gap");
    d2k_qw_ranges_add(&ranges, 0, 25, 0);
    print_state("duplicate");
    d2k_qw_ranges_add(&ranges, 25, 0, 1);
    print_state("fin");
    d2k_qw_ranges_reset(&ranges);
    print_state("reset");
    d2k_qw_ranges_add(&ranges, 1000, 2000, 1);
    print_state("fin_no_prefix");
    d2k_qw_ranges_add(&ranges, 0, 1000, 0);
    print_state("fin_prefix_filled");
    d2k_qw_ranges_reset(&ranges);
    d2k_qw_ranges_add(&ranges, 2000, 1000, 1);
    d2k_qw_ranges_add(&ranges, 0, 1000, 0);
    print_state("hole_before_fin");
    d2k_qw_ranges_reset(&ranges);
    d2k_qw_ranges_add(&ranges, 0, 0, 1);
    print_state("empty_fin");
    d2k_qw_ranges_reset(&ranges);
    d2k_qw_ranges_add(&ranges, UINT64_MAX, 1, 0);
    print_state("overflow");
    d2k_qw_ranges_add(&ranges, UINT64_MAX - 1, 10, 0);
    print_state("overflow_fin");
    d2k_qw_ranges_reset(&ranges);
    for (uint64_t index = 0; index < D2K_QW_RANGES_MAX; index++) {
        d2k_qw_ranges_add(&ranges, index * 10, 1, 0);
    }
    print_state("max64");
    d2k_qw_ranges_add(&ranges, 1000, 1, 0);
    print_state("max64_extra");
    d2k_qw_ranges_add(&ranges, 0, 630, 0);
    print_state("max64_merge");
    d2k_qw_ranges_reset(&ranges);
    d2k_qw_ranges_add(&ranges, 30, 10, 0);
    d2k_qw_ranges_add(&ranges, 0, 10, 0);
    d2k_qw_ranges_add(&ranges, 10, 10, 0);
    d2k_qw_ranges_add(&ranges, 20, 10, 0);
    print_state("out_of_order");
    d2k_qw_ranges_reset(&ranges);
    d2k_qw_ranges_add(&ranges, 0, 10, 1);
    d2k_qw_ranges_add(&ranges, 10, 10, 0);
    print_state("fin_then_data");
    d2k_qw_ranges_reset(&ranges);
    d2k_qw_ranges_add(&ranges, 0, 0, 0);
    print_state("zero_len");
    d2k_qw_ranges_reset(&ranges);
    d2k_qw_ranges_add(&ranges, UINT64_C(1) << 32, UINT64_C(1) << 32, 0);
    print_state("large1");
    d2k_qw_ranges_add(&ranges, UINT64_C(3) << 32, UINT64_C(1) << 32, 0);
    print_state("large2");
    d2k_qw_ranges_add(&ranges, UINT64_C(3) << 32, UINT64_C(1) << 32, 0);
    print_state("large_dup");
    return 0;
}
