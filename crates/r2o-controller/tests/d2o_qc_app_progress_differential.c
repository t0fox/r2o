/* C-оракул: `d2k_qc_app_progress` (core/quicconn.c:1425-1428) поверх
 * `d2k_qw_ranges_*`: байты и complete ТЕКУЩЕГО потока после reset. */
#include "d2k_quicwire.h"

#include <inttypes.h>
#include <stdio.h>

static d2k_qw_ranges ranges;

static void report(const char *label)
{
    printf("%s,%" PRIu64 ",%d\n", label, d2k_qw_ranges_bytes(&ranges),
           d2k_qw_ranges_complete(&ranges));
}

int main(void)
{
    d2k_qw_ranges_reset(&ranges);
    d2k_qw_ranges_add(&ranges, 0, 4, 0);
    d2k_qw_ranges_add(&ranges, 2, 8, 0);
    d2k_qw_ranges_add(&ranges, 0, 10, 1);
    report("stream1");

    d2k_qw_ranges_reset(&ranges);
    d2k_qw_ranges_add(&ranges, 1000, 2000, 1);
    d2k_qw_ranges_add(&ranges, 0, 1000, 0);
    report("stream2");

    d2k_qw_ranges_reset(&ranges);
    d2k_qw_ranges_add(&ranges, 0, 1000, 0);
    d2k_qw_ranges_add(&ranges, 2000, 1000, 1);
    report("stream3");

    d2k_qw_ranges_reset(&ranges);
    d2k_qw_ranges_add(&ranges, 0, 0, 1);
    report("stream4");

    d2k_qw_ranges_reset(&ranges);
    d2k_qw_ranges_add(&ranges, 0, 100, 0);
    d2k_qw_ranges_add(&ranges, 100, 0, 1);
    report("stream5");

    d2k_qw_ranges_reset(&ranges);
    report("stream6");
    return 0;
}
