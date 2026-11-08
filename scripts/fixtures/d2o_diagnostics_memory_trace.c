/* d2o_diagnostics_memory_trace — allocator/madvise contract из diagnostics.c. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_diagnostics.h"

int main(void) {
    d2k_diag_memory_enable(1);
    int tracked0 = d2k_diag_memory_acquire(0, 100);
    int tracked1 = d2k_diag_memory_acquire(1, 200);
    int tracked4 = d2k_diag_memory_acquire(4, 300);
    int tracked5 = d2k_diag_memory_acquire(5, 400);
    d2k_diag_memory_release(0, 40, tracked0);
    d2k_diag_memory_alloc_failure(2);
    printf("enabled=%s\n", d2k_diag_memory_active() ? "true" : "false");
    d2k_diag_mem_site sites[D2K_DIAG_MEMORY_SITE_COUNT];
    d2k_diag_memory_snapshot(sites);
    for (unsigned i = 0; i < D2K_DIAG_MEMORY_SITE_COUNT; i++) {
        printf("site=%u live=%u peak=%u objects=%u created=%u destroyed=%u failures=%u\n",
               i, sites[i].live_bytes, sites[i].peak_bytes, sites[i].live_objects,
               sites[i].created, sites[i].destroyed, sites[i].alloc_failures);
    }
    d2k_diag_counts counts;
    memset(&counts, 0, sizeof counts);
    d2k_diag_memory_counts(&counts);
    printf("tracked tcp=%llu tls=%llu quic=%llu\n",
           (unsigned long long)counts.tracked_tcp_bytes,
           (unsigned long long)counts.tracked_tls_bytes,
           (unsigned long long)counts.tracked_quic_bytes);
    (void)tracked1;
    (void)tracked4;
    (void)tracked5;

    d2k_diag_madvise madvise;
    memset(&madvise, 0, sizeof madvise);
    madvise.successes = 3;
    madvise.failures = 2;
    madvise.requested_bytes = 1000;
    madvise.failed_requested_bytes = 500;
    madvise.last_errno = 12;
    madvise.other_errno_count = 1;
    madvise.errno_hist[0].error = 12;
    madvise.errno_hist[0].count = 2;
    madvise.errno_hist[1].error = 5;
    madvise.errno_hist[1].count = 1;
    printf("madvise successes=%llu failures=%llu requested=%llu failed=%llu last_errno=%d other=%llu errno=",
           (unsigned long long)madvise.successes,
           (unsigned long long)madvise.failures,
           (unsigned long long)madvise.requested_bytes,
           (unsigned long long)madvise.failed_requested_bytes,
           madvise.last_errno,
           (unsigned long long)madvise.other_errno_count);
    int comma = 0;
    for (unsigned i = 0; i < D2K_DIAG_MADVISE_ERRNO_SLOTS; i++) {
        if (!madvise.errno_hist[i].error) continue;
        printf("%s%d:%llu", comma ? "," : "", madvise.errno_hist[i].error,
               (unsigned long long)madvise.errno_hist[i].count);
        comma = 1;
    }
    printf("\n");
    d2k_diag_memory_enable(0);
    return 0;
}
