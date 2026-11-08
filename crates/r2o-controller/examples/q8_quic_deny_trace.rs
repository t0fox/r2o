//! Q8: Rust trace backoff-лестницы и active-флага quicdeny.

use r2o_controller::r2o_quic_deny::R2oQuicDenyCache;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

fn server() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)), 443)
}

fn main() {
    let now = Instant::now();
    let mut cache = R2oQuicDenyCache::default();
    for streak in 1..=5u32 {
        let delay = cache.r2o_next_delay("media.example", 4).unwrap();
        println!("case streak-{streak}\nms={}", delay.as_millis());
        cache.r2o_record_cut("media.example", 4, server(), b"initial", now);
    }

    let mut cache = R2oQuicDenyCache::default();
    cache.r2o_record_cut("media.example", 4, server(), b"initial", now);
    println!(
        "case active-yes\nvalue={}",
        u8::from(cache.r2o_is_active("media.example", 4))
    );
    let _ = cache.r2o_start_recheck("media.example", 4, now + Duration::from_secs(600));
    let _ = cache.r2o_recheck_clear("media.example", 4);
    cache.r2o_finish_removal("media.example", 4, true, now + Duration::from_secs(601));
    println!(
        "case active-no\nvalue={}",
        u8::from(cache.r2o_is_active("media.example", 4))
    );
}
