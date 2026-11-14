//! C/Rust differential: ECH/ANY-ветвь выбора формы ClientHello.
//!
//! ```text
//! r2o_ech_shape_trace
//! ```
//!
//! Сравнивается с `d2o_ech_shape_differential.c`: те же байты ClientHello,
//! те же планы (REC_ID) и тот же порядок установки через control-команды.

use r2k_core::addr::Address;
use r2k_core::control::{Frame, SHAPE_ECH_TCP};
use r2k_core::plan::Plan;
use r2o_datapath::control::NamePlans;
use std::net::{IpAddr, Ipv4Addr};

const SHAPE_MODERN: u8 = 1;
const SHAPE_LEGACY: u8 = 2;
const SHAPE_GRANDFATHER: u8 = 4;
const HOST: &str = "example.com";

fn server_addr() -> Address {
    Address::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)))
}

fn other_addr() -> Address {
    Address::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
}

fn put_tlv(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

fn plan_records(marker: u8) -> Vec<u8> {
    let mut out = Vec::new();
    put_tlv(&mut out, 0x0001, &[marker; 16]);
    put_tlv(&mut out, 0x0002, &[6, 1]);
    put_tlv(
        &mut out,
        0x0010,
        &[0, 1, b'P', b'L', b'0' + marker % 10, b'!'],
    );
    put_tlv(&mut out, 0x0101, &[0, 1, 0, 0, 1, 0, 0, 0, 0, 0]);
    out
}

fn plan_blob(marker: u8) -> Vec<u8> {
    let records = plan_records(marker);
    let mut out = Vec::with_capacity(12 + records.len());
    out.extend_from_slice(b"D2KP");
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&4_u16.to_be_bytes());
    out.extend_from_slice(&records);
    out
}

#[allow(dead_code)]
fn load(marker: u8) -> Plan {
    Plan::parse_wire(&plan_blob(marker)).expect("план должен разбираться")
}

fn set_name_frame(plans: &mut NamePlans, marker: u8, shape: u8) {
    let mut body = Vec::new();
    body.push(HOST.len() as u8);
    body.extend_from_slice(HOST.as_bytes());
    body.extend_from_slice(&[shape, 4]);
    body.extend_from_slice(&plan_blob(marker));
    let ack = plans.handle(&Frame {
        kind: r2k_core::control::COMMAND_SET_NAME,
        body,
    });
    assert!(
        ack.ok,
        "SET_NAME {marker:#x} shape {shape} reason {}",
        ack.reason
    );
}

fn set_name_probe_frame(plans: &mut NamePlans, marker: u8, shape: u8, port: u16) {
    let mut body = Vec::new();
    body.push(HOST.len() as u8);
    body.extend_from_slice(HOST.as_bytes());
    body.extend_from_slice(&[shape, 4]);
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&plan_blob(marker));
    body.extend_from_slice(&[0x5a; 16]);
    let ack = plans.handle(&Frame {
        kind: r2k_core::control::COMMAND_SET_NAME_PROBE,
        body,
    });
    assert!(ack.ok, "SET_NAME_PROBE {marker:#x}");
}

fn set_suffix_frame(plans: &mut NamePlans, marker: u8, shape: u8) {
    let mut body = Vec::new();
    body.push(HOST.len() as u8);
    body.extend_from_slice(HOST.as_bytes());
    body.extend_from_slice(&[shape, 4]);
    body.extend_from_slice(&plan_blob(marker));
    body.extend_from_slice(&[0x33; 16]);
    let ack = plans.handle(&Frame {
        kind: r2k_core::control::COMMAND_SET_SUFFIX,
        body,
    });
    assert!(ack.ok, "SET_SUFFIX {marker:#x}");
}

fn set_addr_frame(plans: &mut NamePlans, marker: u8, shape: u8) {
    let mut body = vec![4];
    body.extend_from_slice(&[198, 51, 100, 20]);
    body.extend_from_slice(&[0; 12]);
    body.push(shape);
    body.extend_from_slice(&plan_blob(marker));
    let ack = plans.handle(&Frame {
        kind: r2k_core::control::COMMAND_SET_ADDR,
        body,
    });
    assert!(ack.ok, "SET_ADDR {marker:#x}");
}

fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Та же раскладка, что в C-оракуле: SNI + supported_versions; длинами можно
/// объявить больше, чем пришло.
fn client_hello(
    ext_len_claim: u16,
    rec_len_claim: u16,
    hs_len_claim: u32,
    with_tls13: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x16);
    out.push(0x03);
    out.push(0x03);
    put16(&mut out, rec_len_claim);
    out.push(0x01);
    out.push((hs_len_claim >> 16) as u8);
    out.push((hs_len_claim >> 8) as u8);
    out.push(hs_len_claim as u8);
    put16(&mut out, 0x0303);
    out.extend((0x20_u8..0x40).take(32));
    out.push(0);
    put16(&mut out, 2);
    out.extend_from_slice(&[0x13, 0x01]);
    out.push(1);
    out.push(0);
    put16(&mut out, ext_len_claim);
    put16(&mut out, 0x0000);
    put16(&mut out, 2 + 1 + 2 + HOST.len() as u16);
    put16(&mut out, 1 + 2 + HOST.len() as u16);
    out.push(0);
    put16(&mut out, HOST.len() as u16);
    out.extend_from_slice(HOST.as_bytes());
    if with_tls13 {
        put16(&mut out, 0x002b);
        put16(&mut out, 3);
        out.push(2);
        put16(&mut out, 0x0304);
    }
    out
}

fn complete_hello() -> Vec<u8> {
    let mut hello = client_hello(0, 0, 0, true);
    let total = 52 + 20 + 7;
    hello[3..5].copy_from_slice(&((total - 5) as u16).to_be_bytes());
    hello[6] = ((total - 9) >> 16) as u8;
    hello[7] = ((total - 9) >> 8) as u8;
    hello[8] = (total - 9) as u8;
    hello[50..52].copy_from_slice(&27_u16.to_be_bytes());
    assert_eq!(hello.len(), total);
    hello
}

fn tcp_packet(payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 40 + payload.len()];
    let total = packet.len() as u16;
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
    packet[16..20].copy_from_slice(&[198, 51, 100, 20]);
    packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet[24..28].copy_from_slice(&1000_u32.to_be_bytes());
    packet[28..32].copy_from_slice(&777_u32.to_be_bytes());
    packet[32] = 5 << 4;
    packet[33] = 0x18;
    packet[34..36].copy_from_slice(&50240_u16.to_be_bytes());
    packet[40..].copy_from_slice(payload);
    packet
}

fn print_plan(name: &str, plan: Option<&Plan>) {
    match plan {
        None => println!("{name} -"),
        Some(plan) => {
            print!("{name} ");
            for byte in plan.id {
                print!("{byte:02x}");
            }
            println!();
        }
    }
}

fn print_has(name: &str, value: bool) {
    println!("{name} {}", u8::from(value));
}

fn decision(name: &str, plans: &NamePlans, payload: &[u8]) {
    let packet = tcp_packet(payload);
    print_plan(name, plans.select(&packet));
}

fn main() {
    // --- 1. has_ech_target. ---
    {
        let mut plans = NamePlans::with_capacity(64);
        set_name_frame(&mut plans, 0x22, SHAPE_MODERN);
        print_has(
            "H1 modern-only",
            plans.has_ech_target(Some(HOST.as_bytes()), Some(server_addr()), 4, 0),
        );
        set_name_frame(&mut plans, 0xe1, SHAPE_ECH_TCP);
        print_has(
            "H2 ech-name",
            plans.has_ech_target(Some(HOST.as_bytes()), Some(server_addr()), 4, 0),
        );
        print_has(
            "H3 ech-other-name",
            plans.has_ech_target(Some(b"other.example"), Some(server_addr()), 4, 0),
        );
    }
    {
        let mut plans = NamePlans::with_capacity(64);
        set_suffix_frame(&mut plans, 0xe2, SHAPE_ECH_TCP);
        print_has(
            "H4 ech-suffix",
            plans.has_ech_target(Some(HOST.as_bytes()), Some(server_addr()), 4, 0),
        );
    }
    {
        let mut plans = NamePlans::with_capacity(64);
        set_addr_frame(&mut plans, 0xe3, SHAPE_ECH_TCP);
        print_has(
            "H5 ech-addr",
            plans.has_ech_target(Some(HOST.as_bytes()), Some(server_addr()), 4, 0),
        );
        print_has(
            "H6 ech-addr-other",
            plans.has_ech_target(Some(HOST.as_bytes()), Some(other_addr()), 4, 0),
        );
    }
    {
        let mut plans = NamePlans::with_capacity(64);
        set_name_probe_frame(&mut plans, 0xe4, SHAPE_ECH_TCP, 40000);
        let addr = server_addr();
        print_has(
            "H7 ech-probe",
            plans.has_ech_target(Some(HOST.as_bytes()), Some(addr), 4, 40000),
        );
        print_has(
            "H8 ech-probe-other-port",
            plans.has_ech_target(Some(HOST.as_bytes()), Some(addr), 4, 40001),
        );
        print_has(
            "H9 ech-probe-no-port",
            plans.has_ech_target(Some(HOST.as_bytes()), Some(addr), 4, 0),
        );
    }

    // --- 2. find_target. ---
    let addr = server_addr();
    {
        let mut plans = NamePlans::with_capacity(64);
        set_name_frame(&mut plans, 0xe5, SHAPE_ECH_TCP);
        print_plan(
            "F1 any-ech-name",
            plans.find_target(Some(HOST.as_bytes()), Some(addr), 4, 0, 0),
        );
        print_plan(
            "F2 modern-ech-name",
            plans.find_target(Some(HOST.as_bytes()), Some(addr), 4, SHAPE_MODERN, 0),
        );
        print_plan(
            "F3 ech-ech-name",
            plans.find_target(Some(HOST.as_bytes()), Some(addr), 4, SHAPE_ECH_TCP, 0),
        );
    }
    {
        let mut plans = NamePlans::with_capacity(64);
        set_name_frame(&mut plans, 0x33, SHAPE_MODERN);
        print_plan(
            "F4 any-modern-name",
            plans.find_target(Some(HOST.as_bytes()), Some(addr), 4, 0, 0),
        );
        print_plan(
            "F5 modern-modern-name",
            plans.find_target(Some(HOST.as_bytes()), Some(addr), 4, SHAPE_MODERN, 0),
        );
    }
    {
        let mut plans = NamePlans::with_capacity(64);
        set_name_frame(&mut plans, 0x44, SHAPE_GRANDFATHER);
        print_plan(
            "F6 any-grandfather",
            plans.find_target(Some(HOST.as_bytes()), Some(addr), 4, 0, 0),
        );
    }
    {
        let mut plans = NamePlans::with_capacity(64);
        set_suffix_frame(&mut plans, 0xe6, SHAPE_ECH_TCP);
        print_plan(
            "F7 any-ech-suffix",
            plans.find_target(Some(HOST.as_bytes()), Some(addr), 4, 0, 0),
        );
        print_plan(
            "F8 ech-ech-suffix",
            plans.find_target(Some(HOST.as_bytes()), Some(addr), 4, SHAPE_ECH_TCP, 0),
        );
    }

    // --- 3. Решение по байтам ClientHello (production `select`). ---
    {
        let mut plans = NamePlans::with_capacity(64);
        set_name_frame(&mut plans, 0xe7, SHAPE_ECH_TCP);
        set_name_frame(&mut plans, 0x77, SHAPE_MODERN);
        decision(
            "D1 truncated-ech",
            &plans,
            &client_hello(300, 400, 390, true),
        );
    }
    {
        let mut plans = NamePlans::with_capacity(64);
        set_name_frame(&mut plans, 0x78, SHAPE_MODERN);
        decision(
            "D2 truncated-no-ech",
            &plans,
            &client_hello(300, 400, 390, true),
        );
    }
    {
        let mut plans = NamePlans::with_capacity(64);
        set_name_frame(&mut plans, 0xe8, SHAPE_ECH_TCP);
        set_name_frame(&mut plans, 0x79, SHAPE_MODERN);
        decision("D3 complete-ech", &plans, &complete_hello());
    }
    {
        let mut plans = NamePlans::with_capacity(64);
        set_name_frame(&mut plans, 0x7a, SHAPE_LEGACY);
        decision(
            "D4 truncated-no-tls13",
            &plans,
            &client_hello(300, 400, 390, false),
        );
    }
    {
        let mut plans = NamePlans::with_capacity(64);
        set_addr_frame(&mut plans, 0xe9, SHAPE_ECH_TCP);
        set_name_frame(&mut plans, 0x7b, SHAPE_MODERN);
        decision(
            "D5 truncated-ech-addr",
            &plans,
            &client_hello(300, 400, 390, true),
        );
    }
    {
        let mut plans = NamePlans::with_capacity(64);
        set_name_probe_frame(&mut plans, 0xea, SHAPE_ECH_TCP, 40000);
        let packet = tcp_packet(&client_hello(300, 400, 390, true));
        let plan = plans.select_with_quic_host_probe(&packet, None, true);
        print_plan("D6 truncated-ech-probe", plan);
    }
}
