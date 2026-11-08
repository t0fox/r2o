//! Печатает limits/memory budget в формате C `d2o_limits_trace.c`.

use r2o_telegram::limits::{
    D2O_CONFIGURED_MAX_CONNECTIONS, auto_max_connections, runtime_memory_budget,
};
use r2o_telegram::memory_budget::MemoryBudget;

fn main() {
    const MIB: usize = 1024 * 1024;
    let max_case = |fd: usize, memory: usize, bytes: usize, hedge: usize, configured: usize| {
        println!(
            "max fd={fd} memory={memory} bytes={bytes} hedge={hedge} configured={configured} => {}",
            auto_max_connections(fd, memory, bytes, hedge, configured)
        );
    };
    max_case(128, 16 * MIB, 128 * 1024, 0, 512);
    max_case(32, 16 * MIB, 128 * 1024, 0, 512);
    max_case(4096, MIB, 256 * 1024, 0, 512);
    max_case(usize::MAX, usize::MAX, 1, 0, 12);
    max_case(usize::MAX, usize::MAX, 1, 0, 0);
    max_case(48, MIB, 128 * 1024, 16, 512);
    max_case(256, MIB, 0, 0, 512);
    max_case(256, MIB, 128 * 1024, usize::MAX, 512);
    max_case(
        1024,
        128 * MIB,
        282 * 1024,
        0,
        D2O_CONFIGURED_MAX_CONNECTIONS,
    );
    max_case(1024, 282 * 1024 * 7, 282 * 1024, 0, 64);

    println!(
        "runtime 512/348 => {}",
        runtime_memory_budget(512 * MIB, 348 * MIB)
    );
    println!(
        "runtime 64/40 => {}",
        runtime_memory_budget(64 * MIB, 40 * MIB)
    );
    println!(
        "runtime 2048/1024 => {}",
        runtime_memory_budget(2048 * MIB, 1024 * MIB)
    );
    println!("runtime 512/0 => {}", runtime_memory_budget(512 * MIB, 0));

    let budget = MemoryBudget::new(64 * 1024);
    budget.reserve(48 * 1024);
    println!(
        "budget after48 used={} peak={}",
        budget.used(),
        budget.peak()
    );
    println!(
        "budget reserve16+1 => {}",
        if budget.reserve(16 * 1024 + 1) { 0 } else { -1 }
    );
    println!("budget afterfail used={}", budget.used());
    println!(
        "budget reserve16 => {}",
        if budget.reserve(16 * 1024) { 0 } else { -1 }
    );
    println!("budget full used={} peak={}", budget.used(), budget.peak());
    budget.release(32 * 1024);
    println!("budget release32 used={}", budget.used());
    println!(
        "budget reserve32 => {}",
        if budget.reserve(32 * 1024) { 0 } else { -1 }
    );
    println!("budget peak2 used={} peak={}", budget.used(), budget.peak());
    budget.release(budget.limit());
    println!("budget drained used={}", budget.used());
}
