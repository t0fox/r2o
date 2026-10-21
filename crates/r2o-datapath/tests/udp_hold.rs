use r2o_datapath::netlink::{
    R2O_NF_INET_FORWARD, R2O_NF_INET_LOCAL_IN, R2O_NF_INET_LOCAL_OUT, R2O_NF_INET_POST_ROUTING,
    R2O_NF_INET_PRE_ROUTING,
};
use r2o_datapath::r2o_quic::R2oQuicSessions;
use r2o_datapath::r2o_udp_hold::{
    R2oUdpDeferredResends, R2oUdpDeferredVerdicts, R2oUdpFollowTable, R2oUdpHoldFeed,
    R2oUdpHoldTable, r2o_release_batch_with, r2o_udp_hold_candidate,
};
use r2o_datapath::r2o_udp_sessions::R2oUdpSessions;
use std::time::{Duration, Instant};

fn r2o_udp_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut packet = vec![0; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

fn r2o_quic_packet(destination_port: u16, payload: &[u8]) -> Vec<u8> {
    r2o_udp_packet(
        [192, 0, 2, 1],
        [198, 51, 100, 2],
        50_000,
        destination_port,
        payload,
    )
}

const R2O_QUIC_INITIAL: &[u8] = include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin");
const R2O_QUIC_INITIAL_FIRST: &[u8] = include_bytes!("../tests/fixtures/quic_v1_initial_first.bin");
const R2O_QUIC_INITIAL_SECOND: &[u8] =
    include_bytes!("../tests/fixtures/quic_v1_initial_second.bin");

#[test]
fn r2o_udp_hold_распознаёт_только_клиентский_quic_initial_на_исходящем_hook() {
    let packet = r2o_quic_packet(8443, R2O_QUIC_INITIAL);
    assert!(r2o_udp_hold_candidate(
        &packet,
        Some(R2O_NF_INET_POST_ROUTING)
    ));
    assert!(r2o_udp_hold_candidate(&packet, Some(R2O_NF_INET_LOCAL_OUT)));
    assert!(!r2o_udp_hold_candidate(&packet, Some(R2O_NF_INET_LOCAL_IN)));
    assert!(!r2o_udp_hold_candidate(
        &packet,
        Some(R2O_NF_INET_PRE_ROUTING)
    ));
    assert!(!r2o_udp_hold_candidate(&packet, Some(R2O_NF_INET_FORWARD)));
    assert!(!r2o_udp_hold_candidate(&packet, None));

    let fallback = r2o_quic_packet(443, R2O_QUIC_INITIAL);
    assert!(r2o_udp_hold_candidate(&fallback, None));
}

#[test]
fn r2o_udp_hold_отказывает_для_фрагментов_и_не_initial() {
    let mut fragment = r2o_quic_packet(443, R2O_QUIC_INITIAL);
    fragment[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    assert!(!r2o_udp_hold_candidate(
        &fragment,
        Some(R2O_NF_INET_POST_ROUTING)
    ));

    let ordinary = r2o_quic_packet(443, b"ordinary UDP datagram");
    assert!(!r2o_udp_hold_candidate(
        &ordinary,
        Some(R2O_NF_INET_POST_ROUTING)
    ));
}

#[test]
fn r2o_udp_sessions_ограничивает_hold_окном_потока() {
    let packet = r2o_quic_packet(443, R2O_QUIC_INITIAL);
    let mut sessions = R2oUdpSessions::new().unwrap();
    let now = Instant::now();
    assert!(sessions.observe_packet(&packet, now));

    for _ in 0..8 {
        assert!(sessions.r2o_begin_hold(&packet));
    }
    assert!(!sessions.r2o_begin_hold(&packet));

    assert!(sessions.r2o_mark_plan_applied(&packet));
    assert!(!sessions.r2o_begin_hold(&packet));
}

#[test]
fn r2o_udp_sessions_после_собранного_hello_не_открывает_hold_заново() {
    let packet = r2o_quic_packet(443, R2O_QUIC_INITIAL);
    let mut sessions = R2oUdpSessions::new().unwrap();
    assert!(sessions.observe_packet(&packet, Instant::now()));
    assert!(sessions.r2o_begin_hold(&packet));
    assert!(sessions.r2o_mark_hello_seen(&packet));
    assert!(!sessions.r2o_begin_hold(&packet));
}

#[test]
fn r2o_udp_hold_собирает_split_clienthello_и_возвращает_пачку_для_replay() {
    let now = Instant::now();
    let first = r2o_quic_packet(443, R2O_QUIC_INITIAL_FIRST);
    let second = r2o_quic_packet(443, R2O_QUIC_INITIAL_SECOND);
    let mut holds = R2oUdpHoldTable::new();
    let mut sessions = R2oUdpSessions::new().unwrap();
    let mut quic = R2oQuicSessions::default();

    for (id, packet) in [(71, &first), (72, &second)] {
        assert!(sessions.observe_packet(packet, now));
        assert!(r2o_udp_hold_candidate(packet, None));
        assert!(sessions.r2o_begin_hold(packet));
        assert_eq!(holds.r2o_feed(id, 0, packet, now), R2oUdpHoldFeed::Held);
        let hello = quic.capture_hello(packet).map(|hello| hello.host);
        if id == 71 {
            assert!(hello.is_none());
        } else {
            assert_eq!(hello.as_deref(), Some(b"example.com".as_slice()));
            let batch = holds.r2o_take(packet).unwrap();
            assert_eq!(
                batch
                    .packets
                    .iter()
                    .map(|packet| packet.id)
                    .collect::<Vec<_>>(),
                [71, 72]
            );
            assert_eq!(batch.packets[0].packet, first);
            assert_eq!(batch.packets[1].packet, second);
        }
    }
}

#[test]
fn r2o_udp_отложенные_вердикты_выдаются_по_сроку_и_порядку() {
    let now = Instant::now();
    let mut releases = R2oUdpDeferredVerdicts::new();
    assert!(releases.r2o_enqueue(now + Duration::from_millis(20), &[41, 42], &[0, 1], None));
    assert!(releases.r2o_enqueue(now + Duration::from_millis(20), &[51], &[1], None));

    let mut sent = Vec::new();
    assert_eq!(
        releases
            .r2o_flush(now + Duration::from_millis(19), |id, verdict| {
                sent.push((id, verdict));
                Ok::<_, std::io::Error>(())
            })
            .unwrap(),
        0
    );
    assert!(sent.is_empty());
    assert_eq!(
        releases
            .r2o_flush(now + Duration::from_millis(20), |id, verdict| {
                sent.push((id, verdict));
                Ok::<_, std::io::Error>(())
            })
            .unwrap(),
        2
    );
    assert_eq!(sent, [(41, 0), (42, 1), (51, 1)]);
    assert!(releases.is_empty());
}

#[test]
fn r2o_udp_очередь_отложенных_вердиктов_отказывает_без_потери_id() {
    let now = Instant::now();
    let mut releases = R2oUdpDeferredVerdicts::new();
    for id in 0..16 {
        assert!(releases.r2o_enqueue(now + Duration::from_secs(1), &[id], &[1], None));
    }
    assert!(!releases.r2o_enqueue(now + Duration::from_secs(1), &[99], &[1], None));
    assert_eq!(releases.r2o_drain_accept(), (0..16).collect::<Vec<_>>());
    assert!(releases.is_empty());
}

#[test]
fn r2o_udp_сбой_emit_снимает_отложенные_хвосты_только_своего_потока() {
    let now = Instant::now();
    let first = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"first");
    let second = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 3], 50_000, 443, b"second");

    let mut verdicts = R2oUdpDeferredVerdicts::new();
    assert!(verdicts.r2o_enqueue(now + Duration::from_secs(1), &[41], &[1], Some(&first)));
    assert!(verdicts.r2o_enqueue(now + Duration::from_secs(1), &[51], &[1], Some(&second)));
    assert_eq!(verdicts.r2o_cancel_flow(&first), [41]);
    assert_eq!(verdicts.r2o_drain_accept(), [51]);

    let mut resends = R2oUdpDeferredResends::new();
    assert!(resends.r2o_enqueue(now + Duration::from_secs(1), 61, &first));
    assert!(resends.r2o_enqueue(now + Duration::from_secs(1), 71, &second));
    assert_eq!(resends.r2o_cancel_flow(&first), [61]);
    assert_eq!(resends.r2o_drain_accept(), [71]);
}

#[test]
fn r2o_udp_освобождает_голову_перед_raw_хвостом_и_его_drop() {
    let now = Instant::now();
    let mut table = R2oUdpHoldTable::new();
    let head = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"head");
    let tail = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"tail");
    assert_eq!(table.r2o_feed(11, 0, &head, now), R2oUdpHoldFeed::Held);
    assert_eq!(table.r2o_feed(12, 0, &tail, now), R2oUdpHoldFeed::Held);
    let batch = table.r2o_take(&head).unwrap();
    let events = std::cell::RefCell::new(Vec::<String>::new());

    let stats = r2o_release_batch_with(
        &batch,
        1,
        false,
        true,
        |_| true,
        |packet| {
            events
                .borrow_mut()
                .push(format!("raw:{}", packet.packet[28] as char));
            Ok::<_, std::io::Error>(())
        },
        |id, verdict| {
            events.borrow_mut().push(format!("вердикт:{id}:{verdict}"));
            Ok::<_, std::io::Error>(())
        },
    );

    assert_eq!(stats.resent, 1);
    assert_eq!(stats.resend_failed, 0);
    assert_eq!(*events.borrow(), ["вердикт:11:1", "raw:t", "вердикт:12:0"]);
}

#[test]
fn r2o_udp_при_ошибке_вердикта_головы_не_обгоняет_её_raw_хвостом() {
    let now = Instant::now();
    let mut table = R2oUdpHoldTable::new();
    let head = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"head");
    let tail = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"tail");
    assert_eq!(table.r2o_feed(21, 0, &head, now), R2oUdpHoldFeed::Held);
    assert_eq!(table.r2o_feed(22, 0, &tail, now), R2oUdpHoldFeed::Held);
    let batch = table.r2o_take(&head).unwrap();
    let mut resent = 0;
    let mut verdicts = Vec::new();

    let stats = r2o_release_batch_with(
        &batch,
        1,
        false,
        true,
        |_| true,
        |_| {
            resent += 1;
            Ok::<_, std::io::Error>(())
        },
        |id, verdict| {
            verdicts.push((id, verdict));
            if id == 21 {
                Err(std::io::Error::other("сбой тестового вердикта"))
            } else {
                Ok(())
            }
        },
    );

    assert_eq!(resent, 0);
    assert_eq!(stats.verdict_failures, 1);
    assert_eq!(verdicts, [(21, 1), (22, 1)]);
}

#[test]
fn r2o_udp_follow_ограничивает_поздний_хвост_пачкой_и_пятью_миллисекундами() {
    let now = Instant::now();
    let head = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"head");
    let tail = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"tail");
    let reverse = r2o_udp_packet([198, 51, 100, 2], [192, 0, 2, 1], 443, 50_000, b"reply");
    let mut follow = R2oUdpFollowTable::new();
    assert!(follow.r2o_mark(&head, now, None, 7));

    assert!(
        follow
            .r2o_match(&tail, now + Duration::from_millis(1), 7)
            .is_some()
    );
    assert!(
        follow
            .r2o_match(&tail, now + Duration::from_millis(5), 7)
            .is_some()
    );
    assert!(
        follow
            .r2o_match(&reverse, now + Duration::from_millis(1), 7)
            .is_none()
    );
    assert!(
        follow
            .r2o_match(&tail, now + Duration::from_millis(5), 8)
            .is_none()
    );
    assert!(follow.is_empty());
}

#[test]
fn r2o_udp_follow_сохраняет_срок_отложенной_головы_и_помечает_постоянный_отказ() {
    let now = Instant::now();
    let head = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"head");
    let tail = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"tail");
    let due = now + Duration::from_millis(30);
    let mut follow = R2oUdpFollowTable::new();
    assert!(follow.r2o_mark(&head, now, Some(due), 9));
    assert_eq!(follow.r2o_match(&tail, now, 9).unwrap().at, Some(due));
    assert!(follow.r2o_mark_failed(&tail));
    assert!(follow.r2o_match(&tail, now, 9).unwrap().failed);
}

#[test]
fn r2o_udp_отложенный_raw_хвост_получает_drop_только_после_отправки() {
    let now = Instant::now();
    let packet = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"tail");
    let mut deferred = R2oUdpDeferredResends::new();
    assert!(deferred.r2o_enqueue(now + Duration::from_millis(10), 31, &packet));
    let events = std::cell::RefCell::new(Vec::new());

    assert_eq!(
        deferred
            .r2o_flush(
                now + Duration::from_millis(9),
                |_, _| {
                    panic!("сырая отправка ещё не должна запускаться")
                },
                |id, verdict| {
                    events.borrow_mut().push((id, verdict));
                    Ok::<_, std::io::Error>(())
                },
                |_| {}
            )
            .flushed,
        0
    );
    let stats = deferred.r2o_flush(
        now + Duration::from_millis(10),
        |id, bytes| {
            events.borrow_mut().push((id, bytes[28] as u32));
            Ok::<_, std::io::Error>(())
        },
        |id, verdict| {
            events.borrow_mut().push((id, 100 + verdict));
            Ok(())
        },
        |_| {},
    );
    assert_eq!(stats.flushed, 1);
    assert_eq!(*events.borrow(), [(31, b't' as u32), (31, 100)]);
}

#[test]
fn r2o_udp_hold_сохраняет_датаграммы_потока_fifo_с_метками() {
    let now = Instant::now();
    let mut table = R2oUdpHoldTable::new();
    let head = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"head");
    let tail = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"tail");
    let reverse = r2o_udp_packet([198, 51, 100, 2], [192, 0, 2, 1], 443, 50_000, b"reply");

    assert_eq!(table.r2o_feed(41, 0, &head, now), R2oUdpHoldFeed::Held);
    assert_eq!(
        table.r2o_feed(42, 7, &tail, now + Duration::from_millis(1)),
        R2oUdpHoldFeed::Held
    );
    let batch = table.r2o_take(&reverse).unwrap();
    assert_eq!(batch.packets.len(), 2);
    assert_eq!(batch.packets[0].id, 41);
    assert_eq!(batch.packets[0].packet, head);
    assert_eq!(batch.packets[0].mark, 0);
    assert_eq!(batch.packets[1].id, 42);
    assert_eq!(batch.packets[1].packet, tail);
    assert_eq!(batch.packets[1].mark, 7);
    assert!(table.is_empty());
}

#[test]
fn r2o_udp_hold_истекает_на_границе_ста_миллисекунд() {
    let now = Instant::now();
    let mut table = R2oUdpHoldTable::new();
    let packet = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"head");
    assert_eq!(table.r2o_feed(73, 0, &packet, now), R2oUdpHoldFeed::Held);

    assert!(table.r2o_flush(now + Duration::from_millis(99)).is_empty());
    let expired = table.r2o_flush(now + Duration::from_millis(100));
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].packets[0].id, 73);
    assert!(table.is_empty());
    assert!(table.r2o_flush(now + Duration::from_millis(200)).is_empty());
}

#[test]
fn r2o_udp_hold_при_переполнении_возвращает_всю_старую_пачку() {
    let now = Instant::now();
    let mut table = R2oUdpHoldTable::new();
    let mut packet = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 50_000, 443, b"0");
    for id in 1..=8 {
        packet[28] = b'0' + id as u8;
        assert_eq!(table.r2o_feed(id, 0, &packet, now), R2oUdpHoldFeed::Held);
    }

    packet[28] = b'9';
    let overflow = table.r2o_feed(9, 0, &packet, now);
    let R2oUdpHoldFeed::Overflow(batch) = overflow else {
        panic!("переполненная пачка должна вернуться владельцу ID");
    };
    assert_eq!(batch.packets.len(), 8);
    assert_eq!(batch.packets[0].id, 1);
    assert_eq!(batch.packets[7].id, 8);
    assert_eq!(batch.packets[7].packet[28], b'8');
    assert!(table.is_empty());
    assert_eq!(table.r2o_feed(9, 0, &packet, now), R2oUdpHoldFeed::Held);
}

#[test]
fn r2o_udp_hold_отказывает_после_шестнадцати_потоков_без_вытеснения() {
    let now = Instant::now();
    let mut table = R2oUdpHoldTable::new();
    let mut packets = Vec::new();
    for offset in 0..16 {
        let packet = r2o_udp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            50_000 + offset,
            443,
            b"head",
        );
        assert_eq!(
            table.r2o_feed(offset as u32, 0, &packet, now),
            R2oUdpHoldFeed::Held
        );
        packets.push(packet);
    }
    let next = r2o_udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 60_000, 443, b"next");

    assert_eq!(table.r2o_feed(99, 0, &next, now), R2oUdpHoldFeed::Refused);
    for (offset, packet) in packets.iter().enumerate() {
        let batch = table.r2o_take(packet).unwrap();
        assert_eq!(batch.packets[0].id, offset as u32);
    }
    assert!(table.is_empty());
}

#[test]
fn r2o_udp_hold_отказывает_для_датаграмм_больше_тысячи_шестисот_байт() {
    let now = Instant::now();
    let mut table = R2oUdpHoldTable::new();
    let oversized = r2o_udp_packet(
        [192, 0, 2, 1],
        [198, 51, 100, 2],
        50_000,
        443,
        &vec![0; 1600 - 28 + 1],
    );

    assert_eq!(
        table.r2o_feed(1, 0, &oversized, now),
        R2oUdpHoldFeed::Refused
    );
    assert!(table.is_empty());
}
