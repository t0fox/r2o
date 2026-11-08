//! Печатает allocator/madvise contract в том же виде, что C diagnostics.c.

use r2o_controller::diagnostics::{
    MADVISE_ERRNO_SLOTS, MEMORY_SITE_COUNT, MadviseErrno, MadviseStats, memory_acquire,
    memory_alloc_failure, memory_enable, memory_release, memory_snapshot, tracked_memory_bytes,
};

fn main() {
    memory_enable(true);
    let tracked0 = memory_acquire(0, 100);
    let _tracked1 = memory_acquire(1, 200);
    let _tracked4 = memory_acquire(4, 300);
    let _tracked5 = memory_acquire(5, 400);
    memory_release(0, 40, tracked0);
    memory_alloc_failure(2);
    println!("enabled={}", memory_active_text());
    let sites = memory_snapshot();
    for (index, site) in sites.iter().enumerate() {
        println!(
            "site={} live={} peak={} objects={} created={} destroyed={} failures={}",
            index,
            site.live_bytes,
            site.peak_bytes,
            site.live_objects,
            site.created,
            site.destroyed,
            site.alloc_failures
        );
    }
    let (tcp, tls, quic) = tracked_memory_bytes();
    println!("tracked tcp={tcp} tls={tls} quic={quic}");

    let mut madvise = MadviseStats {
        successes: 3,
        failures: 2,
        requested_bytes: 1000,
        failed_requested_bytes: 500,
        last_errno: 12,
        other_errno_count: 1,
        errno_hist: [MadviseErrno::default(); MADVISE_ERRNO_SLOTS],
    };
    madvise.errno_hist[0] = MadviseErrno {
        error: 12,
        count: 2,
    };
    madvise.errno_hist[1] = MadviseErrno { error: 5, count: 1 };
    print!(
        "madvise successes={} failures={} requested={} failed={} last_errno={} other={} errno=",
        madvise.successes,
        madvise.failures,
        madvise.requested_bytes,
        madvise.failed_requested_bytes,
        madvise.last_errno,
        madvise.other_errno_count
    );
    let mut comma = false;
    for entry in &madvise.errno_hist {
        if entry.error == 0 {
            continue;
        }
        print!(
            "{}{}:{}",
            if comma { "," } else { "" },
            entry.error,
            entry.count
        );
        comma = true;
    }
    println!();
    memory_enable(false);
    let _ = memory_snapshot().len() == MEMORY_SITE_COUNT;
}

fn memory_active_text() -> &'static str {
    if r2o_controller::diagnostics::memory_active() {
        "true"
    } else {
        "false"
    }
}
