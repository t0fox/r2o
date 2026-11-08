//! D21: Rust trace ядра очереди отложенной отправки.
//!
//! ```text
//! d21_sched_trace
//! ```

use r2k_core::plan::EmitKind;
use r2o_datapath::engine::WirePacket;
use r2o_datapath::scheduler::{ScheduledOwner, ScheduledPop, ScheduledQueue};
use std::time::{Duration, Instant};

fn packet(id: u32, length: usize) -> WirePacket {
    let mut bytes = vec![0xcc; length.max(4)];
    bytes[..4].copy_from_slice(&id.to_be_bytes());
    bytes.truncate(length);
    WirePacket {
        packet: bytes,
        kind: EmitKind::Payload,
        delay_us: 0,
    }
}

fn id(packet: &WirePacket) -> u32 {
    u32::from_be_bytes(packet.packet[..4].try_into().expect("four bytes"))
}

fn push_raw(
    queue: &mut ScheduledQueue,
    label: &str,
    id: u32,
    due: Instant,
    length: usize,
) -> Result<(), ()> {
    match queue.push_raw(due, packet(id, length)) {
        Ok(()) => {
            println!("{label} push id={id} rc=0");
            Ok(())
        }
        Err(_) => {
            println!("{label} push id={id} rc=-2");
            Err(())
        }
    }
}

fn pop_ex(queue: &mut ScheduledQueue, label: &str, now: Instant, outcap: usize) {
    match queue.pop_due_ex(now, outcap) {
        ScheduledPop::Emitted { packet, owner } => {
            let (owned, owner_id) = match owner {
                ScheduledOwner::Owned(owner_id) => (1, owner_id),
                _ => (0, 0),
            };
            println!(
                "{label} pop id={} rc=1 len={} owned={owned} qid={owner_id}",
                id(&packet),
                packet.packet.len()
            );
        }
        ScheduledPop::OversizedOwned { owner_id } => {
            println!("{label} pop rc=-1 len=0 owned=1 qid={owner_id}");
        }
        ScheduledPop::Dropped | ScheduledPop::Empty => {
            println!("{label} pop rc=0 len=0");
        }
    }
}

fn next_line(queue: &ScheduledQueue, label: &str, base: Instant) {
    let next = queue
        .next_due()
        .map_or(0, |due| due.saturating_duration_since(base).as_millis());
    println!("{label} next={next}");
}

fn main() {
    let base = Instant::now();
    let at = |milliseconds: u64| base + Duration::from_millis(milliseconds);

    {
        let queue = ScheduledQueue::with_limits(4, 64).unwrap();
        println!(
            "empty count={} next=0 refusals={}",
            queue.len(),
            queue.refusals()
        );
        let mut queue = queue;
        pop_ex(&mut queue, "empty", at(0), 64);
    }
    {
        let mut queue = ScheduledQueue::with_limits(8, 64).unwrap();
        let dues = [900, 100, 500, 50, 700];
        for (id, due) in dues.iter().enumerate() {
            push_raw(&mut queue, "order", id as u32, at(*due), 8).unwrap();
        }
        for _ in 0..5 {
            pop_ex(&mut queue, "order", at(100_000), 64);
        }
        println!(
            "order count={} next=0 refusals={}",
            queue.len(),
            queue.refusals()
        );
    }
    {
        let mut queue = ScheduledQueue::with_limits(4, 64).unwrap();
        for id in 1..=3 {
            push_raw(&mut queue, "stable", id, at(500), 8).unwrap();
        }
        for _ in 0..3 {
            pop_ex(&mut queue, "stable", at(500), 64);
        }
    }
    {
        let mut queue = ScheduledQueue::with_limits(2, 64).unwrap();
        push_raw(&mut queue, "cap", 1, at(10), 8).unwrap();
        push_raw(&mut queue, "cap", 2, at(10), 8).unwrap();
        let full = queue.push_raw(at(10), packet(3, 8));
        println!("cap push id=3 rc={}", if full.is_ok() { 0 } else { -1 });
        println!("cap count={} refusals={}", queue.len(), queue.refusals());
    }
    {
        let mut queue = ScheduledQueue::with_limits(4, 8).unwrap();
        let oversize = queue.push_raw(at(10), packet(1, 16));
        println!(
            "slot push id=1 len=16 rc={}",
            if oversize.is_err() { -2 } else { 0 }
        );
        push_raw(&mut queue, "slot", 2, at(10), 8).unwrap();
        println!("slot count={} refusals={}", queue.len(), queue.refusals());
        pop_ex(&mut queue, "slot", at(10), 64);
    }
    {
        let mut queue = ScheduledQueue::with_limits(2, 8).unwrap();
        push_raw(&mut queue, "grow", 1, at(10), 8).unwrap();
        println!("grow 16 rc={}", queue.grow_slot_size(16));
        println!("grow 16 rc={}", queue.grow_slot_size(16));
        println!("grow 4 rc={}", queue.grow_slot_size(4));
        println!("grow max rc={}", queue.grow_slot_size(usize::MAX));
        push_raw(&mut queue, "grow", 2, at(11), 16).unwrap();
        pop_ex(&mut queue, "grow", at(10), 64);
        pop_ex(&mut queue, "grow", at(11), 64);
    }
    {
        let mut queue = ScheduledQueue::with_limits(4, 64).unwrap();
        queue.push_owned(at(100), packet(7, 20), 4242).unwrap();
        println!("owned push id=7 rc=0");
        push_raw(&mut queue, "owned", 8, at(100), 20).unwrap();
        pop_ex(&mut queue, "owned", at(100), 64);
        pop_ex(&mut queue, "owned", at(100), 64);
        queue.push_owned(at(200), packet(9, 20), 77).unwrap();
        println!("owned push id=9 rc=0");
        pop_ex(&mut queue, "owned", at(200), 8);
        println!("owned count={} refusals={}", queue.len(), queue.refusals());
    }
    {
        let mut queue = ScheduledQueue::with_limits(4, 64).unwrap();
        push_raw(&mut queue, "oversize", 1, at(10), 20).unwrap();
        pop_ex(&mut queue, "oversize", at(10), 8);
        println!(
            "oversize count={} refusals={}",
            queue.len(),
            queue.refusals()
        );
    }
    {
        let mut queue = ScheduledQueue::with_limits(4, 64).unwrap();
        push_raw(&mut queue, "next", 1, at(5000), 8).unwrap();
        next_line(&queue, "next", base);
        pop_ex(&mut queue, "next", at(4999), 64);
        next_line(&queue, "next", base);
        pop_ex(&mut queue, "next", at(5000), 64);
        next_line(&queue, "next", base);
    }
}
