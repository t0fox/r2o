use r2k_core::quic::r2k_quic_dynamic_wait_ms;

#[test]
fn ограничивает_ожидание_quic_по_rtt_как_в_доноре() {
    let cases = [
        (0, 1_500),
        (499, 1_500),
        (500, 1_500),
        (1_000, 3_000),
        (2_000, 6_000),
        (u32::MAX, 6_000),
    ];

    for (rtt_ms, expected_ms) in cases {
        assert_eq!(r2k_quic_dynamic_wait_ms(rtt_ms), expected_ms);
    }
}
