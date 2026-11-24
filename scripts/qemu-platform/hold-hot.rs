use r2o_datapath::hold::{HoldOptions, HoldOutcome, HoldTable};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

// Считаем вызовы аллокатора только во время обработки подготовленных пакетов.
struct Counted;
static CALLS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        CALLS.fetch_add(1, Relaxed);
        BYTES.fetch_add(layout.size(), Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOC: Counted = Counted;

fn packet(port: u16, flags: u8, payload: bool) -> [u8; 128] {
    let mut wire = [0u8; 128];
    wire[0] = 0x45;
    wire[2..4].copy_from_slice(&(if payload { 128u16 } else { 40 }).to_be_bytes());
    wire[8] = 64;
    wire[9] = 6;
    wire[12..16].copy_from_slice(&[192, 0, 2, 20]);
    wire[16..20].copy_from_slice(&[198, 51, 100, 2]);
    wire[20..22].copy_from_slice(&port.to_be_bytes());
    wire[22..24].copy_from_slice(&443u16.to_be_bytes());
    wire[24..28].copy_from_slice(&50_000u32.to_be_bytes());
    wire[32] = 0x50;
    wire[33] = flags;
    wire[40..].fill(b'x');
    wire
}

fn main() {
    let loops: u32 = std::env::args()
        .nth(1)
        .map_or(100_000, |v| v.parse().unwrap());
    for count in [0, 64, 512, 1024] {
        let mut table = HoldTable::default();
        let now = Instant::now();
        let options = HoldOptions {
            revision: 0,
            allow_tls: true,
            allow_http: true,
            observe_tls: true,
            observe_http: true,
            own_packets: false,
        };
        for port in 20_001..=20_000 + count {
            let syn = packet(port, 0x02, false);
            black_box(table.feed_observing(1, &syn[..40], now, options));
        }
        // При заполненной таблице используем последний добавленный якорь.
        let wire = packet(20_000 + count, 0x18, true);
        let (allocs, bytes) = (CALLS.load(Relaxed), BYTES.load(Relaxed));
        let start = Instant::now();
        for i in 0..loops {
            let result = table.feed_observing(i, black_box(&wire), now, options);
            assert_eq!(black_box(result.outcome), HoldOutcome::Pass);
        }
        let us = start.elapsed().as_micros();
        let (allocs, bytes) = (CALLS.load(Relaxed) - allocs, BYTES.load(Relaxed) - bytes);
        println!("anchors={count} packets={loops} us={us} allocs={allocs} bytes={bytes}");
    }
}
