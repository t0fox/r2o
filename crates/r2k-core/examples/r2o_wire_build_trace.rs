//! C/Rust differential: `d2k_wire_build` legacy wire_profile=0.

use r2k_core::plan::{
    Emission, EmitKind, POISON_BADSUM, POISON_IPID_ZERO, POISON_TCPTS_BACK, WIRE_TCP_TEMPLATE,
};
use r2k_core::wire::{build_tcp_packet, build_tcp_packet_at};

fn input4() -> Vec<u8> {
    let mut packet = vec![0; 44];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&44_u16.to_be_bytes());
    packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
    packet[8] = 63;
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
    packet[40..44].copy_from_slice(b"orig");
    packet
}

fn input4_opts() -> Vec<u8> {
    let mut packet = vec![0; 44];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&44_u16.to_be_bytes());
    packet[4..6].copy_from_slice(&0x1000_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[192, 168, 1, 67]);
    packet[16..20].copy_from_slice(&[1, 2, 3, 4]);
    packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet[24..28].copy_from_slice(&1000_u32.to_be_bytes());
    packet[28..32].copy_from_slice(&777_u32.to_be_bytes());
    packet[32] = 6 << 4;
    packet[33] = 0x18;
    packet[34..36].copy_from_slice(&50240_u16.to_be_bytes());
    packet[40..44].copy_from_slice(&[1, 1, 0, 0]);
    packet
}

fn input6() -> Vec<u8> {
    let mut packet = vec![0; 64];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&24_u16.to_be_bytes());
    packet[6] = 6;
    packet[7] = 63;
    packet[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    packet[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    packet[40..42].copy_from_slice(&40000_u16.to_be_bytes());
    packet[42..44].copy_from_slice(&443_u16.to_be_bytes());
    packet[44..48].copy_from_slice(&1000_u32.to_be_bytes());
    packet[48..52].copy_from_slice(&777_u32.to_be_bytes());
    packet[52] = 5 << 4;
    packet[53] = 0x18;
    packet[54..56].copy_from_slice(&50240_u16.to_be_bytes());
    packet[60..64].copy_from_slice(b"orig");
    packet
}

fn emission(
    ttl: u8,
    poison: u8,
    seq_shift: i32,
    prefix: &[u8],
    urgent: bool,
    urgent_ptr: u16,
    bytes: &[u8],
) -> Emission {
    Emission {
        kind: EmitKind::Payload,
        delay_us: 0,
        seq: 1000,
        ttl,
        poison,
        seq_shift,
        wire_profile: 0,
        ipfrag: 0,
        urgent,
        urgent_ptr,
        prefix: prefix.to_vec(),
        bytes: bytes.to_vec(),
    }
}

fn run(name: &str, input: &[u8], emission: &Emission, cap: usize) {
    let mut out = vec![0; cap];
    let rc = build_tcp_packet(input, emission, &mut out).unwrap_or(0);
    print!("{name} len={rc} hex=");
    for byte in &out[..rc] {
        print!("{byte:02x}");
    }
    println!();
}

fn main() {
    let v4 = input4();
    let v6 = input6();
    run(
        "A ipv4",
        &v4,
        &emission(0, 0, 0, &[], false, 0, b"hello"),
        512,
    );
    run(
        "B shift-prefix",
        &v4,
        &emission(0, 0, -5, b"ab", false, 0, b"cd"),
        512,
    );
    run(
        "C ttl",
        &v4,
        &emission(8, 0, 0, &[], false, 0, b"hello"),
        512,
    );
    run(
        "D badsum",
        &v4,
        &emission(0, POISON_BADSUM, 0, &[], false, 0, b"hello"),
        512,
    );
    run(
        "E ts-back",
        &v4,
        &emission(0, POISON_TCPTS_BACK, 0, &[], false, 0, b"hello"),
        512,
    );
    run(
        "F ipid-zero",
        &v4,
        &emission(0, POISON_IPID_ZERO, 0, &[], false, 0, b"hello"),
        512,
    );
    run(
        "G urgent",
        &v4,
        &emission(0, 0, 0, &[], true, 2, b"abcd"),
        512,
    );
    run(
        "H ipv6",
        &v6,
        &emission(0, 0, 0, &[], false, 0, b"hello"),
        512,
    );
    run(
        "I ipv6-shift-ttl",
        &v6,
        &emission(8, 0, 7, &[], false, 0, b"hello"),
        512,
    );
    run(
        "J ipv6-ipid-zero",
        &v6,
        &emission(0, POISON_IPID_ZERO, 0, &[], false, 0, b"hello"),
        512,
    );
    run(
        "K urgent-bad",
        &v4,
        &emission(0, 0, 0, &[], true, 9, b"abcd"),
        512,
    );
    run(
        "L cap-small",
        &v4,
        &emission(0, 0, 0, &[], false, 0, b"hello"),
        40,
    );
    let template_input = input4_opts();
    for index in 0..3 {
        let mut emitted = emission(0, 0, 0, &[], false, 0, b"hello");
        emitted.seq = 1000 + index as u32;
        emitted.wire_profile = WIRE_TCP_TEMPLATE;
        let mut out = vec![0; 512];
        let rc = build_tcp_packet_at(&template_input, &emitted, index, &mut out).unwrap_or(0);
        print!("M template-batch.{index} len={rc} hex=");
        for byte in &out[..rc] {
            print!("{byte:02x}");
        }
        println!();
    }
}
