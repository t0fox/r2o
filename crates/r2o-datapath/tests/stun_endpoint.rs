#![cfg(target_os = "linux")]

use r2k_core::control::{
    EVENT_R2O_STUN_EXCHANGE, Frame, KEY_LEN, SHAPE_VOICE, decode_stun_exchange,
    encode_delete_addr_probe, encode_set_addr_probe, read_frame,
};
use r2o_datapath::control::NamePlans;
use r2o_datapath::engine::{PacketDecision, decide};
use r2o_datapath::netlink::{R2O_NF_INET_LOCAL_IN, R2O_NF_INET_POST_ROUTING};
use std::net::{IpAddr, SocketAddr};

fn packet(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len() as u16;
    let mut bytes = match (source.ip(), destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let mut header = vec![0; 20];
            header[0] = 0x45;
            header[2..4].copy_from_slice(&(20 + udp_len).to_be_bytes());
            header[8] = 64;
            header[9] = 17;
            header[12..16].copy_from_slice(&source.octets());
            header[16..20].copy_from_slice(&destination.octets());
            header
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let mut header = vec![0; 40];
            header[0] = 0x60;
            header[4..6].copy_from_slice(&udp_len.to_be_bytes());
            header[6] = 17;
            header[7] = 64;
            header[8..24].copy_from_slice(&source.octets());
            header[24..40].copy_from_slice(&destination.octets());
            header
        }
        _ => unreachable!(),
    };
    bytes.extend_from_slice(&source.port().to_be_bytes());
    bytes.extend_from_slice(&destination.port().to_be_bytes());
    bytes.extend_from_slice(&udp_len.to_be_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn stun_endpoint_применяет_точную_пробу_и_сохраняет_binding_request() {
    let mut trace = String::new();
    for (source, destination) in [
        ("192.0.2.1:50001", "198.51.100.2:3478"),
        ("[2001:db8::1]:50001", "[2001:db8::2]:3478"),
    ] {
        let source: SocketAddr = source.parse().unwrap();
        let destination: SocketAddr = destination.parse().unwrap();
        let trial = [7; 16];
        let plan_id = [9; 16];
        let mut records = b"R2OP\0\x01\0\x07\0\0\0\x03\0\x01\0\x10".to_vec();
        records.extend_from_slice(&plan_id);
        records.extend_from_slice(b"\0\x02\0\x02\x11\x03\x01\x0c\0\x01\x01");
        let mut plans = NamePlans::default();
        let set = encode_set_addr_probe(source, destination, 3000, &records, trial).unwrap();
        let ack = plans.handle(&read_frame(&mut set.as_slice()).unwrap());
        assert!(ack.ok);
        assert_eq!(ack.trial_id, Some(trial));

        let binding = r2k_core::stun::binding_request([0x37; 12]);
        let request = packet(source, destination, &binding);
        let hook = Some(R2O_NF_INET_POST_ROUTING);
        let plan = plans
            .select_with_quic_host_at_hook(&request, None, hook)
            .unwrap();
        assert_eq!(plan.id, plan_id);
        let applied = plans
            .applied_event_for_packet_at_hook(&request, 42, hook)
            .unwrap();
        assert_eq!(applied.plan_id, plan_id);
        assert_eq!(applied.trial_id, trial);
        assert_eq!(applied.binding.shape, SHAPE_VOICE);
        assert!(applied.binding.temporary);
        assert_eq!(applied.key.len(), KEY_LEN);
        let mut proof = Frame {
            kind: EVENT_R2O_STUN_EXCHANGE,
            body: applied.event_body().unwrap(),
        };
        assert_eq!(decode_stun_exchange(&proof), Ok(applied));
        proof.body.truncate(KEY_LEN + 32);
        assert!(decode_stun_exchange(&proof).is_err());
        let PacketDecision::Transmit { packets, fate } = decide(plan, &request) else {
            panic!("STUN ipfrag 1 должен собрать два IP-фрагмента");
        };
        assert_eq!(fate, r2k_core::plan::OriginalFate::Drop);
        assert_eq!(packets.len(), 2);
        for wire in packets {
            let mut bytes = wire.packet;
            if source.is_ipv4() {
                // IP ID и зависящая от него контрольная сумма меняются на каждом исполнении.
                bytes[4..6].fill(0);
                bytes[10..12].fill(0);
            } else {
                bytes[44..48].fill(0);
            }
            for byte in bytes {
                use std::fmt::Write;
                write!(trace, "{byte:02x}").unwrap();
            }
            trace.push('\n');
        }

        let mut other_source = source;
        other_source.set_port(source.port() + 1);
        let mut other_destination = destination;
        other_destination.set_port(destination.port() + 1);
        let mut discord = [0; 74];
        discord[..4].copy_from_slice(&[0, 1, 0, 70]);
        for miss in [
            packet(other_source, destination, &binding),
            packet(source, other_destination, &binding),
            packet(destination, source, &binding),
            packet(source, destination, &discord),
            packet(source, destination, b"RAW UDP"),
            packet(
                source,
                destination,
                include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin"),
            ),
        ] {
            assert!(
                plans
                    .select_with_quic_host_at_hook(&miss, None, hook)
                    .is_none()
            );
        }
        assert!(
            plans
                .select_with_quic_host_at_hook(&request, None, Some(R2O_NF_INET_LOCAL_IN))
                .is_none()
        );
        let delete = encode_delete_addr_probe(source, destination, trial).unwrap();
        assert!(
            plans
                .handle(&read_frame(&mut delete.as_slice()).unwrap())
                .ok
        );
        assert!(
            plans
                .select_with_quic_host_at_hook(&request, None, hook)
                .is_none()
        );
    }
    if let Some(path) = std::env::var_os("R2O_D2K_STUN_FRAGMENTS") {
        assert_eq!(trace, std::fs::read_to_string(path).unwrap());
    }
}
