//! Байтовый дифференциал Geneva → R2OP на реальном ClientHello.
//!
//! Эталон снят с geneva_c (`bdb767d`, `tests/golden/in.pcap`, пакет 10):
//!
//! ```sh
//! build/geneva apply \
//!   -s '[TCP:flags:PA]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-' \
//!   -i tests/golden/in.pcap -o out.pcap -p 443 --rng-seed 1
//! ```
//!
//! Оригинал и изменённая копия сравниваются после нормализации случайных
//! полей (IP ID и контрольные суммы), как требует `docs/geneva-c-adoption.md`.

use r2k_core::packet::PacketView;
use r2k_core::plan::{PacketInput, Plan};
use r2k_core::wire::build_tcp_packet;
use r2o_controller::geneva::parse_strategy;
use r2o_controller::geneva_compile::compile_plan;

const INPUT: &[u8] = include_bytes!("fixtures/geneva/clienthello_in.bin");
const EXPECTED_ORIGINAL: &[u8] = include_bytes!("fixtures/geneva/clienthello_original.bin");
const EXPECTED_TAMPERED: &[u8] = include_bytes!("fixtures/geneva/clienthello_flags_rst.bin");

fn normalize(mut packet: Vec<u8>) -> Vec<u8> {
    let ip_header_len = usize::from(packet[0] & 0x0f) * 4;
    packet[4..6].fill(0); // IP ID
    packet[10..12].fill(0); // IP checksum
    packet[ip_header_len + 16..ip_header_len + 18].fill(0); // TCP checksum
    packet
}

#[test]
fn compiled_duplicate_matches_geneva_bytes_after_normalization() {
    let view = PacketView::parse(INPUT).expect("input packet");
    let tcp = view.tcp_segment(INPUT).expect("tcp");
    let payload = &INPUT[tcp.payload.clone()];
    let input = PacketInput::new(payload, tcp.sequence);

    let strategy = parse_strategy(
        "[TCP:flags:PA]-duplicate(,tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},))-",
    )
    .expect("strategy");
    let bytes = compile_plan(&strategy, payload, [0x42; 16]).expect("compile");
    let plan = Plan::parse(&bytes).expect("plan");
    let actions = plan.apply(&input).expect("apply");
    assert_eq!(actions.emits.len(), 2, "оригинал и фальшивка");

    let build = |index: usize| {
        let mut out = vec![0u8; 2048];
        let length = build_tcp_packet(INPUT, &actions.emits[index], &mut out).expect("wire");
        out[..length].to_vec()
    };

    assert_eq!(
        normalize(build(0)),
        normalize(EXPECTED_ORIGINAL.to_vec()),
        "оригинал уходит без изменений"
    );
    assert_eq!(
        normalize(build(1)),
        normalize(EXPECTED_TAMPERED.to_vec()),
        "фальшивка: flags=R, badsum, тот же seq/ack и нагрузка"
    );
}
