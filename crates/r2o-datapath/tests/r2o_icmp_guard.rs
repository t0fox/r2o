use r2o_datapath::netlink::{
    R2O_NF_INET_FORWARD, R2O_NF_INET_LOCAL_IN, R2O_NF_INET_LOCAL_OUT, R2O_NF_INET_POST_ROUTING,
};
use r2o_datapath::r2o_icmp_guard::R2oIcmpGuard;

const R2O_FIELD_ICMP: [u8; 56] = [
    0x45, 0x70, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0xfb, 0x01, 0x2d, 0x19, 0x3e, 0x73, 0x91, 0xdd,
    0xc0, 0xa8, 0x01, 0x43, 0x0b, 0x00, 0xe1, 0x72, 0x00, 0x00, 0x00, 0x00, 0x45, 0x70, 0x04, 0xcc,
    0x00, 0x01, 0x40, 0x00, 0x01, 0x11, 0x16, 0x59, 0xc0, 0xa8, 0x01, 0x43, 0x68, 0x15, 0x34, 0x57,
    0xd8, 0x8b, 0x01, 0xbb, 0x04, 0xb8, 0x34, 0x8e,
];

fn r2o_ipv4_udp(ttl: u8, id: u16, source_port: u16, total_len: usize) -> Vec<u8> {
    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6] = 0x40;
    packet[8] = ttl;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[192, 168, 1, 67]);
    packet[16..20].copy_from_slice(&[104, 21, 52, 87]);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&443u16.to_be_bytes());
    packet[24..26].copy_from_slice(&((total_len - 20) as u16).to_be_bytes());
    packet[28] = 0xc0;
    packet
}

fn r2o_ipv4_tcp(ttl: u8, id: u16, sequence: u32) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40u16.to_be_bytes());
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6] = 0x40;
    packet[8] = ttl;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[192, 168, 1, 67]);
    packet[16..20].copy_from_slice(&[104, 21, 52, 87]);
    packet[20..22].copy_from_slice(&40000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443u16.to_be_bytes());
    packet[24..28].copy_from_slice(&sequence.to_be_bytes());
    packet[32] = 0x50;
    packet
}

fn r2o_icmpv4(kind: u8, code: u8, quote: &[u8], quote_len: usize) -> Vec<u8> {
    let mut packet = vec![0; 28 + quote_len];
    packet[0] = 0x45;
    let total_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[8] = 251;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&[62, 115, 145, 221]);
    packet[16..20].copy_from_slice(&[192, 1, 2, 3]);
    packet[20] = kind;
    packet[21] = code;
    packet[28..].copy_from_slice(&quote[..quote_len]);
    packet
}

fn r2o_ipv6(proto: u8, hop_limit: u8, source_port: u16, destination_port: u16) -> Vec<u8> {
    let transport_len = if proto == 6 { 20 } else { 8 };
    let mut packet = vec![0; 40 + transport_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(transport_len as u16).to_be_bytes());
    packet[6] = proto;
    packet[7] = hop_limit;
    packet[8..24].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x67,
    ]);
    packet[24..40].copy_from_slice(&[0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87]);
    packet[40..42].copy_from_slice(&source_port.to_be_bytes());
    packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
    if proto == 17 {
        packet[44..46].copy_from_slice(&(transport_len as u16).to_be_bytes());
    } else {
        packet[44..48].copy_from_slice(&0x1122_3344u32.to_be_bytes());
        packet[52] = 0x50;
    }
    packet
}

fn r2o_icmpv6(kind: u8, code: u8, quote: &[u8], quote_len: usize) -> Vec<u8> {
    let mut packet = vec![0; 48 + quote_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((8 + quote_len) as u16).to_be_bytes());
    packet[6] = 58;
    packet[7] = 250;
    packet[8] = 0x20;
    packet[9] = 1;
    packet[10] = 0x0d;
    packet[11] = 0xb8;
    packet[23] = 3;
    packet[24] = 0x20;
    packet[25] = 1;
    packet[26] = 0x0d;
    packet[27] = 0xb8;
    packet[39] = 0x67;
    packet[40] = kind;
    packet[41] = code;
    packet[48..].copy_from_slice(&quote[..quote_len]);
    packet
}

#[test]
fn r2o_снимает_только_icmp_ошибку_на_свою_фальшивку_из_полевого_пакета() {
    let mut guard = R2oIcmpGuard::default();
    let fake = r2o_ipv4_udp(3, 1, 55435, 1228);
    assert!(!guard.r2o_check(&R2O_FIELD_ICMP, 100_000_000_000));
    assert!(guard.r2o_note(&fake, 63, 100_000_000_000));
    assert!(guard.r2o_check(&R2O_FIELD_ICMP, 100_033_333_333));
    assert!(guard.r2o_check(&R2O_FIELD_ICMP, 100_033_333_334));
    assert_eq!(guard.r2o_noted(), 1);
    assert_eq!(guard.r2o_dropped(), 2);
    assert!(!guard.r2o_check(&R2O_FIELD_ICMP, 105_000_000_001));
}

#[test]
fn r2o_пропускает_чужие_пакеты_и_ошибки_для_traceroute_и_pmtu() {
    let mut guard = R2oIcmpGuard::default();
    let fake = r2o_ipv4_udp(3, 1, 55435, 1228);
    assert!(guard.r2o_note(&fake, 63, 100));

    let mut client_packet = fake.clone();
    client_packet[4..6].copy_from_slice(&0u16.to_be_bytes());
    client_packet[8] = 1;
    assert!(!guard.r2o_check(&r2o_icmpv4(11, 0, &client_packet, 28), 100));

    let mut traceroute = fake.clone();
    traceroute[20..22].copy_from_slice(&33434u16.to_be_bytes());
    assert!(!guard.r2o_check(&r2o_icmpv4(11, 0, &traceroute, 28), 100));
    assert!(!guard.r2o_check(&r2o_icmpv4(3, 4, &fake, 28), 100));
    assert!(!guard.r2o_check(&r2o_icmpv4(11, 1, &fake, 28), 100));

    let mut changed_port = fake.clone();
    changed_port[21] ^= 1;
    assert!(!guard.r2o_check(&r2o_icmpv4(11, 0, &changed_port, 28), 100));
    let mut raised_ttl = fake;
    raised_ttl[8] = 4;
    assert!(!guard.r2o_check(&r2o_icmpv4(11, 0, &raised_ttl, 28), 100));
    assert_eq!(guard.r2o_dropped(), 0);
}

#[test]
fn r2o_сверяет_номер_последовательности_tcp_и_не_сверяет_udp_checksum() {
    let mut guard = R2oIcmpGuard::default();
    let fake = r2o_ipv4_tcp(4, 0x2001, 0xdead_beef);
    assert!(guard.r2o_note(&fake, 63, 1));
    let mut quote = fake[..28].to_vec();
    quote[8] = 1;
    assert!(guard.r2o_check(&r2o_icmpv4(11, 0, &quote, 28), 1));
    quote[27] ^= 1;
    assert!(!guard.r2o_check(&r2o_icmpv4(11, 0, &quote, 28), 1));

    let mut udp_guard = R2oIcmpGuard::default();
    let fake = r2o_ipv4_udp(3, 1, 55435, 1228);
    assert!(udp_guard.r2o_note(&fake, 63, 1));
    let mut quote = fake[..28].to_vec();
    quote[8] = 1;
    quote[26..28].copy_from_slice(&[0x34, 0x8e]);
    assert!(udp_guard.r2o_check(&r2o_icmpv4(11, 0, &quote, 28), 1));
}

#[test]
fn r2o_учитывает_ipv6_udp_tcp_и_пропускает_packet_too_big() {
    let mut guard = R2oIcmpGuard::default();
    let udp = r2o_ipv6(17, 3, 55435, 443);
    let quote = &udp[..48];
    let icmp = r2o_icmpv6(3, 0, quote, quote.len());
    assert!(!guard.r2o_check(&icmp, 1));
    assert!(guard.r2o_note(&udp, 64, 1));
    assert!(guard.r2o_check(&icmp, 1));
    assert!(!guard.r2o_check(&r2o_icmpv6(2, 0, quote, quote.len()), 1));

    let tcp = r2o_ipv6(6, 2, 40001, 443);
    assert!(guard.r2o_note(&tcp, 64, 1));
    let tcp_icmp = r2o_icmpv6(3, 0, &tcp[..48], 48);
    assert!(guard.r2o_check(&tcp_icmp, 1));
}

#[test]
fn r2o_сверяет_ipv4_id_только_если_его_задал_сам_отправитель() {
    let mut guard = R2oIcmpGuard::default();
    let fake = r2o_ipv4_udp(3, 0, 55435, 1228);
    assert!(guard.r2o_note(&fake, 63, 1));
    let mut quote = fake[..28].to_vec();
    quote[8] = 1;
    quote[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    assert!(guard.r2o_check(&r2o_icmpv4(11, 0, &quote, 28), 1));
}

#[test]
fn r2o_переполнение_кольца_вытесняет_старую_запись_а_длинная_цитата_совпадает() {
    let mut guard = R2oIcmpGuard::default();
    let fake = r2o_ipv4_udp(3, 1, 55435, 1228);
    assert!(guard.r2o_note(&fake, 63, 1));
    let mut long_quote = fake.clone();
    long_quote[8] = 1;
    assert!(guard.r2o_check(&r2o_icmpv4(11, 0, &long_quote, 128), 1));

    for port in 1000..1256 {
        let other = r2o_ipv4_udp(3, 1, port, 1228);
        assert!(guard.r2o_note(&other, 63, 1));
    }
    assert!(!guard.r2o_check(&R2O_FIELD_ICMP, 1));
}

#[test]
fn r2o_направление_hook_ограничивает_drop_входящими_icmp() {
    let mut guard = R2oIcmpGuard::default();
    let fake = r2o_ipv4_udp(3, 1, 55435, 1228);
    assert!(guard.r2o_note(&fake, 63, 1));

    assert_eq!(
        guard.r2o_handle_at_hook(&R2O_FIELD_ICMP, Some(R2O_NF_INET_FORWARD), 2),
        Some(true)
    );
    assert_eq!(
        guard.r2o_handle_at_hook(&R2O_FIELD_ICMP, Some(R2O_NF_INET_LOCAL_IN), 2),
        Some(true)
    );
    assert_eq!(
        guard.r2o_handle_at_hook(&R2O_FIELD_ICMP, Some(R2O_NF_INET_LOCAL_OUT), 2),
        Some(false)
    );
    assert_eq!(
        guard.r2o_handle_at_hook(&R2O_FIELD_ICMP, Some(R2O_NF_INET_POST_ROUTING), 2),
        Some(false)
    );
    assert_eq!(
        guard.r2o_handle_at_hook(&R2O_FIELD_ICMP, None, 2),
        Some(false)
    );
    assert_eq!(guard.r2o_handle_at_hook(&[0x45, 0, 0, 0], Some(2), 2), None);
    assert_eq!(guard.r2o_seen(), 5);
    assert_eq!(guard.r2o_dropped(), 2);
}

#[test]
fn r2o_ошибки_с_обрезанной_цитатой_или_неверным_заголовком_проходят() {
    let mut guard = R2oIcmpGuard::default();
    let fake = r2o_ipv4_udp(3, 1, 55435, 1228);
    assert!(guard.r2o_note(&fake, 63, 1));
    assert!(!guard.r2o_check(&R2O_FIELD_ICMP[..55], 1));
    assert!(!guard.r2o_check(&R2O_FIELD_ICMP[..20], 1));
    assert!(!guard.r2o_note(&fake[..10], 63, 1));
    assert!(!guard.r2o_check(&[], 1));
    assert!(!guard.r2o_check(&fake, 1));
    assert_eq!(guard.r2o_dropped(), 0);
}

#[test]
fn r2o_periodic_icmp_summary_matches_d2o_fields() {
    let mut guard = R2oIcmpGuard::default();
    assert_eq!(guard.r2o_stats_line(), None);

    let fake = r2o_ipv4_udp(3, 1, 55435, 1228);
    assert!(guard.r2o_note(&fake, 63, 100_000_000_000));
    for _ in 0..2 {
        assert_eq!(
            guard.r2o_handle_at_hook(&R2O_FIELD_ICMP, Some(R2O_NF_INET_FORWARD), 100_033_333_333,),
            Some(true)
        );
    }
    assert_eq!(
        guard.r2o_stats_line().as_deref(),
        Some(
            "ICMP time-exceeded: получено 2, снято на свои фальшивки 2; фальшивок с пониженным TTL запомнено 1"
        )
    );

    let mut guard_v6 = R2oIcmpGuard::default();
    let fake_v6 = r2o_ipv6(17, 3, 55435, 443);
    let icmp_v6 = r2o_icmpv6(3, 0, &fake_v6[..48], 48);
    assert!(guard_v6.r2o_note(&fake_v6, 64, 100_000_000_000));
    for _ in 0..2 {
        assert_eq!(
            guard_v6.r2o_handle_at_hook(&icmp_v6, Some(R2O_NF_INET_FORWARD), 100_033_333_333,),
            Some(true)
        );
    }

    let packet_too_big = r2o_icmpv6(2, 0, &fake_v6[..48], 48);
    assert_eq!(
        guard_v6.r2o_handle_at_hook(&packet_too_big, Some(R2O_NF_INET_FORWARD), 100_033_333_333,),
        Some(false)
    );
    let mut changed_port_quote = fake_v6.clone();
    changed_port_quote[43] ^= 1;
    let changed_port = r2o_icmpv6(3, 0, &changed_port_quote, 48);
    assert_eq!(
        guard_v6.r2o_handle_at_hook(&changed_port, Some(R2O_NF_INET_FORWARD), 100_033_333_333,),
        Some(false)
    );
    let mut raised_hop_limit_quote = fake_v6.clone();
    raised_hop_limit_quote[7] = 4;
    let raised_hop_limit = r2o_icmpv6(3, 0, &raised_hop_limit_quote, 48);
    assert_eq!(
        guard_v6.r2o_handle_at_hook(
            &raised_hop_limit,
            Some(R2O_NF_INET_FORWARD),
            100_033_333_333,
        ),
        Some(false)
    );
    assert_eq!(
        guard_v6.r2o_handle_at_hook(&icmp_v6, Some(R2O_NF_INET_FORWARD), 105_000_000_001,),
        Some(false)
    );
    let icmp_v6_line = format!(
        "ICMPv6: получено {}, снято на свои фальшивки {}; фальшивок с пониженным TTL запомнено {}",
        guard_v6.r2o_seen(),
        guard_v6.r2o_dropped(),
        guard_v6.r2o_noted()
    );
    assert_eq!(guard_v6.r2o_seen(), 6);
    assert_eq!(guard_v6.r2o_dropped(), 2);
    assert_eq!(guard_v6.r2o_noted(), 1);

    if let Ok(path) = std::env::var("R2O_ICMP_GUARD_DIFF_OUTPUT") {
        std::fs::write(
            path,
            format!("{}\n{}\n", guard.r2o_stats_line().unwrap(), icmp_v6_line),
        )
        .unwrap();
    }
}

#[test]
#[ignore]
fn d2o_icmpguard_check_trace() {
    fn inner4(
        proto: u8,
        ttl: u8,
        id: u16,
        sport: u16,
        dport: u16,
        w0: u16,
        w1: u16,
        ip_len_override: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(
            &(if ip_len_override == 0 {
                28
            } else {
                ip_len_override
            })
            .to_be_bytes(),
        );
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        packet[8] = ttl;
        packet[9] = proto;
        packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 20]);
        packet[20..22].copy_from_slice(&sport.to_be_bytes());
        packet[22..24].copy_from_slice(&dport.to_be_bytes());
        packet[24..26].copy_from_slice(&w0.to_be_bytes());
        packet[26..28].copy_from_slice(&w1.to_be_bytes());
        packet
    }
    fn inner4_fragment() -> Vec<u8> {
        let mut packet = inner4(6, 63, 0x1234, 50000, 443, 1, 2, 0);
        packet[6..8].copy_from_slice(&1_u16.to_be_bytes());
        packet
    }
    fn icmp4(kind: u8, code: u8, quote: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 28 + quote.len()];
        let total = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[203, 0, 113, 9]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 10]);
        packet[20] = kind;
        packet[21] = code;
        packet[28..].copy_from_slice(quote);
        packet
    }
    fn icmp4_fragment(quote: &[u8]) -> Vec<u8> {
        let mut packet = icmp4(11, 0, quote);
        packet[6..8].copy_from_slice(&1_u16.to_be_bytes());
        packet
    }
    fn inner6(proto: u8, ttl: u8, sport: u16, dport: u16, w0: u16, w1: u16) -> Vec<u8> {
        let mut packet = vec![0; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
        packet[6] = proto;
        packet[7] = ttl;
        packet[8..24]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40..42].copy_from_slice(&sport.to_be_bytes());
        packet[42..44].copy_from_slice(&dport.to_be_bytes());
        packet[44..46].copy_from_slice(&w0.to_be_bytes());
        packet[46..48].copy_from_slice(&w1.to_be_bytes());
        packet
    }
    fn icmp6(kind: u8, code: u8, quote: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 48 + quote.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((8 + quote.len()) as u16).to_be_bytes());
        packet[6] = 58;
        packet[7] = 64;
        packet[8..24]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        packet[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[40] = kind;
        packet[41] = code;
        packet[48..].copy_from_slice(quote);
        packet
    }
    fn run(name: &str, fake: &[u8], original_ttl: u8, note_now: u64, icmp: &[u8], check_now: u64) {
        let mut guard = R2oIcmpGuard::default();
        let noted = guard.r2o_note(fake, original_ttl, note_now);
        let checked = guard.r2o_check(icmp, check_now);
        println!(
            "{name} note={} check={} noted={} dropped={}",
            u8::from(noted),
            u8::from(checked),
            guard.r2o_noted(),
            guard.r2o_dropped()
        );
    }

    let fake = inner4(6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    let quote = inner4(6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    run("A tcp-exact", &fake, 64, 1000, &icmp4(11, 0, &quote), 1000);

    let fake = inner4(17, 63, 0x1234, 50000, 443, 0x0010, 0, 0);
    let quote = inner4(17, 63, 0x1234, 50000, 443, 0x0010, 0, 0);
    run("B udp-exact", &fake, 64, 1000, &icmp4(11, 0, &quote), 1000);

    let fake = inner4(6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    let quote = inner4(6, 63, 0x1234, 50000, 443, 0x0103, 0x0304, 0);
    run("C seq-diff", &fake, 64, 1000, &icmp4(11, 0, &quote), 1000);

    let quote = inner4(6, 64, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    run(
        "D ttl-greater",
        &fake,
        64,
        1000,
        &icmp4(11, 0, &quote),
        1000,
    );

    let quote = inner4(6, 62, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    run("E ttl-lower", &fake, 64, 1000, &icmp4(11, 0, &quote), 1000);

    let quote = inner4(6, 63, 0x1234, 50001, 443, 0x0102, 0x0304, 0);
    run("F sport-diff", &fake, 64, 1000, &icmp4(11, 0, &quote), 1000);

    let quote = inner4(6, 63, 0x1234, 50000, 444, 0x0102, 0x0304, 0);
    run("G dport-diff", &fake, 64, 1000, &icmp4(11, 0, &quote), 1000);

    let quote = inner4(6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 29);
    run("H iplen-diff", &fake, 64, 1000, &icmp4(11, 0, &quote), 1000);

    let quote = inner4(6, 63, 0x9999, 50000, 443, 0x0102, 0x0304, 0);
    run("I ipid-diff", &fake, 64, 1000, &icmp4(11, 0, &quote), 1000);

    let quote = inner4(6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    run(
        "J orig-ttl-equal",
        &fake,
        63,
        1000,
        &icmp4(11, 0, &quote),
        1000,
    );

    let fake_zero = inner4(6, 63, 0, 50000, 443, 0x0102, 0x0304, 0);
    let quote = inner4(6, 63, 0x9999, 50000, 443, 0x0102, 0x0304, 0);
    run(
        "K ipid-zero",
        &fake_zero,
        64,
        1000,
        &icmp4(11, 0, &quote),
        1000,
    );

    let quote = inner4(6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    run(
        "L expired",
        &fake,
        64,
        1000,
        &icmp4(11, 0, &quote),
        1000 + 5_000_000_000 + 1,
    );
    run(
        "M kept-5s",
        &fake,
        64,
        1000,
        &icmp4(11, 0, &quote),
        1000 + 5_000_000_000,
    );

    run("N icmp-type", &fake, 64, 1000, &icmp4(3, 0, &quote), 1000);

    let fake_udp = inner4(17, 63, 0x1234, 50000, 443, 0x0010, 0x1111, 0);
    let quote = inner4(17, 63, 0x1234, 50000, 443, 0x0010, 0x2222, 0);
    run(
        "O udp-checksum-ignored",
        &fake_udp,
        64,
        1000,
        &icmp4(11, 0, &quote),
        1000,
    );

    let quote = inner4(17, 63, 0x1234, 50000, 443, 0x0011, 0x2222, 0);
    run(
        "P udp-len-diff",
        &fake_udp,
        64,
        1000,
        &icmp4(11, 0, &quote),
        1000,
    );

    let fake6 = inner6(6, 63, 50000, 443, 1, 2);
    let quote = inner6(6, 63, 50000, 443, 1, 2);
    run("Q v6-exact", &fake, 64, 1000, &icmp6(3, 0, &quote), 1000);
    run("R v6-real", &fake6, 64, 1000, &icmp6(3, 0, &quote), 1000);

    let mut quote = inner6(6, 63, 50000, 443, 1, 2);
    quote[39] = 3;
    run(
        "S v6-dst-diff",
        &fake6,
        64,
        1000,
        &icmp6(3, 0, &quote),
        1000,
    );

    let quote = inner4(6, 63, 0x1234, 50000, 443, 0x0102, 0x0304, 0);
    run(
        "T family-mismatch",
        &fake6,
        64,
        1000,
        &icmp4(11, 0, &quote),
        1000,
    );
    run(
        "U outer-fragment",
        &fake,
        64,
        1000,
        &icmp4_fragment(&quote),
        1000,
    );
    run(
        "V outer-short",
        &fake,
        64,
        1000,
        &icmp4(11, 0, &quote)[..27],
        1000,
    );
    run(
        "W inner-fragment",
        &inner4_fragment(),
        64,
        1000,
        &icmp4(11, 0, &quote),
        1000,
    );
    run(
        "X inner-proto",
        &inner4(1, 63, 0x1234, 50000, 443, 1, 2, 0),
        64,
        1000,
        &icmp4(11, 0, &quote),
        1000,
    );
    run("Y note-at-zero", &fake, 64, 0, &icmp4(11, 0, &quote), 1);
}
