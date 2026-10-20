use r2k_core::plan::EmitKind;
use r2o_datapath::engine::WirePacket;
use r2o_datapath::scheduler::{FlowTicket, ScheduledQueue};
use std::time::{Duration, Instant};

fn tcp_packet(reverse: bool, flags: u8) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
    packet[9] = 6;
    let (source, destination, source_port, destination_port): (_, _, u16, u16) = if reverse {
        ([198, 51, 100, 20], [192, 0, 2, 10], 443, 41000)
    } else {
        ([192, 0, 2, 10], [198, 51, 100, 20], 41000, 443)
    };
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = flags;
    packet
}

fn emission(byte: u8) -> WirePacket {
    WirePacket {
        packet: vec![byte],
        kind: EmitKind::Payload,
        delay_us: 0,
    }
}

fn schedule(queue: &mut ScheduledQueue, ticket: FlowTicket, due: Instant, byte: u8) {
    queue.push_reserved(ticket, due, emission(byte)).unwrap();
}

#[test]
fn scheduled_packets_are_due_ordered_and_stable_for_equal_deadlines() {
    let now = Instant::now();
    let flow = tcp_packet(false, 0x18);
    let mut queue = ScheduledQueue::with_capacity(4).unwrap();
    let ticket = queue.reserve(&flow, 3).unwrap();
    schedule(&mut queue, ticket, now + Duration::from_millis(20), 3);
    schedule(&mut queue, ticket, now + Duration::from_millis(10), 1);
    schedule(&mut queue, ticket, now + Duration::from_millis(10), 2);

    assert_eq!(queue.pop_due(now + Duration::from_millis(9)), None);
    assert_eq!(
        queue
            .pop_due(now + Duration::from_millis(10))
            .unwrap()
            .0
            .packet,
        [1]
    );
    assert_eq!(
        queue
            .pop_due(now + Duration::from_millis(10))
            .unwrap()
            .0
            .packet,
        [2]
    );
    assert_eq!(
        queue
            .pop_due(now + Duration::from_millis(20))
            .unwrap()
            .0
            .packet,
        [3]
    );
}

#[test]
fn execution_ticket_stays_pending_until_its_last_scheduled_packet_is_sent() {
    let now = Instant::now();
    let flow = tcp_packet(false, 0x18);
    let mut queue = ScheduledQueue::with_capacity(2).unwrap();
    let ticket = queue.reserve(&flow, 2).unwrap();

    assert!(queue.has_pending(ticket));
    schedule(&mut queue, ticket, now, 1);
    schedule(&mut queue, ticket, now, 2);
    assert!(queue.has_pending(ticket));
    assert_eq!(queue.pop_due(now).unwrap().0.packet, [1]);
    assert!(queue.has_pending(ticket));
    assert_eq!(queue.pop_due(now).unwrap().0.packet, [2]);
    assert!(!queue.has_pending(ticket));
}

#[test]
fn queue_capacity_refuses_a_whole_batch_before_any_emission_is_added() {
    let now = Instant::now();
    let flow = tcp_packet(false, 0x18);
    let mut queue = ScheduledQueue::with_capacity(1).unwrap();

    assert!(queue.reserve(&flow, 2).is_none());
    assert_eq!(queue.len(), 0);
    let pending = queue.reserve(&flow, 1).unwrap();
    assert!(queue.reserve(&flow, 1).is_none());
    queue.cancel(pending);
    let ticket = queue.reserve(&flow, 1).unwrap();
    schedule(&mut queue, ticket, now, 1);
    assert_eq!(queue.len(), 1);
    assert!(queue.reserve(&flow, 1).is_none());
}

#[test]
fn a_reset_invalidates_a_batch_reserved_but_not_yet_inserted() {
    let now = Instant::now();
    let flow = tcp_packet(false, 0x18);
    let mut queue = ScheduledQueue::with_capacity(2).unwrap();
    let ticket = queue.reserve(&flow, 1).unwrap();

    queue.observe(&tcp_packet(true, 0x14), now);
    assert!(queue.push_reserved(ticket, now, emission(1)).is_err());
    assert_eq!(queue.len(), 0);
}

#[test]
fn an_expired_reservation_releases_its_reserved_capacity() {
    let flow = tcp_packet(false, 0x18);
    let mut queue = ScheduledQueue::with_capacity(1).unwrap();
    let ticket = queue.reserve(&flow, 1).unwrap();

    assert_eq!(
        queue.pop_due(Instant::now() + Duration::from_secs(121)),
        None
    );
    assert!(
        queue
            .push_reserved(ticket, Instant::now(), emission(1))
            .is_err()
    );
    assert!(queue.reserve(&flow, 1).is_some());
}

#[test]
fn rst_and_reused_syn_cancel_old_flow_emissions() {
    let now = Instant::now();
    let flow = tcp_packet(false, 0x18);
    let mut queue = ScheduledQueue::with_capacity(4).unwrap();
    let ticket = queue.reserve(&flow, 2).unwrap();
    schedule(&mut queue, ticket, now + Duration::from_secs(1), 1);
    schedule(&mut queue, ticket, now + Duration::from_secs(2), 2);

    queue.observe(&tcp_packet(true, 0x14), now);
    assert_eq!(queue.pop_due(now + Duration::from_secs(3)), None);

    let ticket = queue.reserve(&flow, 1).unwrap();
    schedule(&mut queue, ticket, now + Duration::from_secs(1), 3);
    queue.observe(&tcp_packet(false, 0x02), now + Duration::from_millis(1));
    assert_eq!(queue.pop_due(now + Duration::from_secs(3)), None);
}

#[test]
fn a_fin_cancels_its_direction_and_the_reverse_fin_closes_the_flow() {
    let now = Instant::now();
    let forward = tcp_packet(false, 0x18);
    let reverse = tcp_packet(true, 0x18);
    let mut queue = ScheduledQueue::with_capacity(4).unwrap();
    let forward_ticket = queue.reserve(&forward, 1).unwrap();
    schedule(&mut queue, forward_ticket, now + Duration::from_secs(1), 1);
    let reverse_ticket = queue.reserve(&reverse, 1).unwrap();
    schedule(&mut queue, reverse_ticket, now + Duration::from_secs(1), 2);

    queue.observe(&tcp_packet(false, 0x11), now);
    assert_eq!(queue.len(), 1);
    assert_eq!(
        queue
            .pop_due(now + Duration::from_secs(1))
            .unwrap()
            .0
            .packet,
        [2]
    );

    assert!(queue.reserve(&forward, 1).is_none());
    let ticket = queue.reserve(&reverse, 1).unwrap();
    schedule(&mut queue, ticket, now + Duration::from_secs(2), 3);
    let ticket = queue.reserve(&reverse, 1).unwrap();
    schedule(&mut queue, ticket, now + Duration::from_secs(2), 4);
    queue.observe(&tcp_packet(true, 0x11), now + Duration::from_millis(1));
    assert_eq!(queue.pop_due(now + Duration::from_secs(3)), None);
}

#[test]
fn a_fin_invalidates_only_uninserted_packets_in_its_direction() {
    let now = Instant::now();
    let forward = tcp_packet(false, 0x18);
    let reverse = tcp_packet(true, 0x18);
    let mut queue = ScheduledQueue::with_capacity(2).unwrap();
    let forward_ticket = queue.reserve(&forward, 1).unwrap();
    let reverse_ticket = queue.reserve(&reverse, 1).unwrap();

    queue.observe(&tcp_packet(false, 0x11), now);

    assert!(
        queue
            .push_reserved(forward_ticket, now, emission(1))
            .is_err()
    );
    assert!(
        queue
            .push_reserved(reverse_ticket, now, emission(2))
            .is_ok()
    );
    assert_eq!(queue.pop_due(now).unwrap().0.packet, [2]);
}

#[test]
fn idle_flow_emissions_expire_at_the_runtime_session_limit() {
    let now = Instant::now();
    let flow = tcp_packet(false, 0x18);
    let mut queue = ScheduledQueue::with_capacity(2).unwrap();
    let ticket = queue.reserve(&flow, 1).unwrap();
    schedule(&mut queue, ticket, now + Duration::from_secs(180), 1);

    assert_eq!(queue.pop_due(now + Duration::from_secs(119)), None);
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.pop_due(now + Duration::from_secs(121)), None);
    assert_eq!(queue.len(), 0);
}
