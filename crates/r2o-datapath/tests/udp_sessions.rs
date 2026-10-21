use r2o_datapath::netlink::{R2O_NF_INET_FORWARD, R2O_NF_INET_LOCAL_OUT};
use r2o_datapath::r2o_udp_sessions::R2oUdpSessions;
use std::time::{Duration, Instant};

#[test]
fn r2o_udp_hold_ограничивает_удержание_первыми_восемью_клиентскими_пакетами() {
    let mut sessions = R2oUdpSessions::new().unwrap();
    let start = Instant::now();
    let outbound = udp_packet([10, 0, 0, 1], [203, 0, 113, 8], 53000, 443);
    let inbound = udp_packet([203, 0, 113, 8], [10, 0, 0, 1], 443, 53000);

    for index in 0..7 {
        assert!(sessions.r2o_observe_packet_at_hook(
            &outbound,
            start + Duration::from_millis(index),
            Some(R2O_NF_INET_FORWARD),
        ));
    }
    for index in 0..4 {
        assert!(sessions.r2o_observe_packet_at_hook(
            &inbound,
            start + Duration::from_millis(10 + index),
            Some(R2O_NF_INET_FORWARD),
        ));
    }
    assert!(sessions.r2o_observe_packet_at_hook(
        &outbound,
        start + Duration::from_millis(20),
        Some(R2O_NF_INET_FORWARD),
    ));
    assert!(sessions.r2o_begin_hold(&outbound));

    assert!(sessions.r2o_observe_packet_at_hook(
        &outbound,
        start + Duration::from_millis(21),
        Some(R2O_NF_INET_FORWARD),
    ));
    assert!(sessions.r2o_observe_packet_at_hook(
        &outbound,
        start + Duration::from_millis(22),
        Some(R2O_NF_INET_FORWARD),
    ));
    assert!(!sessions.r2o_begin_hold(&outbound));
}

#[test]
fn r2o_udp_forward_сохраняет_известное_направление_при_двух_портах_443() {
    let mut sessions = R2oUdpSessions::new().unwrap();
    let start = Instant::now();
    let outbound = udp_packet([10, 0, 0, 1], [203, 0, 113, 8], 443, 443);
    let inbound = udp_packet([203, 0, 113, 8], [10, 0, 0, 1], 443, 443);

    for index in 0..7 {
        assert!(sessions.r2o_observe_packet_at_hook(
            &outbound,
            start + Duration::from_millis(index),
            Some(R2O_NF_INET_LOCAL_OUT),
        ));
    }
    for index in 0..4 {
        assert!(sessions.r2o_observe_packet_at_hook(
            &inbound,
            start + Duration::from_millis(10 + index),
            Some(R2O_NF_INET_FORWARD),
        ));
    }
    assert!(sessions.r2o_observe_packet_at_hook(
        &outbound,
        start + Duration::from_millis(20),
        Some(R2O_NF_INET_FORWARD),
    ));
    assert!(sessions.r2o_begin_hold(&outbound));

    assert!(sessions.r2o_observe_packet_at_hook(
        &outbound,
        start + Duration::from_millis(21),
        Some(R2O_NF_INET_FORWARD),
    ));
    assert!(!sessions.r2o_begin_hold(&outbound));
}

#[test]
fn обратные_датаграммы_обновляют_один_поток_и_он_истекает_на_границе() {
    let mut sessions = R2oUdpSessions::new().unwrap();
    let start = Instant::now();
    let forward = udp_packet([10, 0, 0, 1], [203, 0, 113, 8], 53000, 7000);
    let reverse = udp_packet([203, 0, 113, 8], [10, 0, 0, 1], 7000, 53000);

    assert!(sessions.observe_packet(&forward, start));
    assert!(sessions.observe_packet(&reverse, start + Duration::from_secs(1)));
    assert_eq!(sessions.stats().flows, 1);
    assert_eq!(sessions.expire(start + Duration::from_secs(120)), 0);
    assert_eq!(sessions.expire(start + Duration::from_secs(121)), 1);
    assert!(sessions.is_empty());
}

#[test]
fn таблица_отказывает_после_трёх_четвертей_слотов() {
    let mut sessions = R2oUdpSessions::new().unwrap();
    let start = Instant::now();
    for index in 0..1536_u16 {
        let packet = udp_packet(
            [10, 0, (index >> 8) as u8, index as u8],
            [203, 0, 113, 8],
            53000,
            7000,
        );
        assert!(sessions.observe_packet(&packet, start));
    }

    let refused = udp_packet([10, 1, 0, 1], [203, 0, 113, 8], 53000, 7000);
    assert!(!sessions.observe_packet(&refused, start));
    assert_eq!(sessions.stats().flows, 1536);
    assert_eq!(sessions.stats().capacity, 2048);
    assert_eq!(sessions.stats().refusals, 1);
    println!(
        "R2O UDP_TABLE flows={} capacity={} refusals={}",
        sessions.stats().flows,
        sessions.stats().capacity,
        sessions.stats().refusals
    );
}

#[test]
fn неполный_udp_заголовок_не_создаёт_поток() {
    let mut sessions = R2oUdpSessions::new().unwrap();
    let packet = udp_packet([10, 0, 0, 1], [203, 0, 113, 8], 53000, 7000);

    assert!(!sessions.observe_packet(&packet[..27], Instant::now()));
    assert_eq!(sessions.stats().flows, 0);
    assert_eq!(sessions.stats().refusals, 0);
}

fn udp_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let mut packet = vec![0; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
    packet
}
