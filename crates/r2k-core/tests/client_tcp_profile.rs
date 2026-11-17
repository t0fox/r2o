//! C/Rust differential: `client_tcp_profile` (core/sched.c:2413-2431).

use r2k_core::packet::{client_tcp_profile, tcp_timestamp_metadata};

fn print_case(output: &mut String, label: &str, known: bool, options: &[u8]) {
    output.push_str(&format!(
        "{label},{},{},{},",
        u8::from(known),
        options.len(),
        options
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    output.push_str(&format!("{}\n", client_tcp_profile(known, options)));
}

#[test]
fn client_tcp_profile_matches_c() {
    let Some(path) = std::env::var_os("R2O_CLIENT_TCP_PROFILE_DIFF_OUTPUT") else {
        return;
    };
    let mut output = String::new();
    let cases: &[(&str, bool, &[u8])] = &[
        ("known0", false, &[]),
        ("empty", true, &[]),
        ("end", true, &[0]),
        ("nop", true, &[1, 1]),
        ("ts", true, &[8, 10, 0, 0, 0, 0, 0, 0, 0, 0]),
        ("ts_short", true, &[8, 10, 0, 0, 0, 0, 0, 0, 0]),
        ("ts_len2", true, &[8, 10]),
        ("ts_badlen", true, &[8, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ("nop_then_ts", true, &[1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0]),
        ("zero_then_ts", true, &[0, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0]),
        ("unknown_kind", true, &[2, 4, 1, 1]),
        ("bad_kind_len", true, &[2, 1]),
        ("zero_len", true, &[2, 0]),
        ("too_long", true, &[2, 5, 1]),
        ("nops40", true, &[1; 40]),
        ("overflow41", true, &[0; 41]),
    ];
    for (label, known, options) in cases {
        print_case(&mut output, label, *known, options);
    }

    let mut state: u32 = 0x1234_5678;
    let mut next = || {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        state
    };
    for index in 0..4096 {
        let known = next() & 1 == 1;
        let len = (next() % 41) as usize;
        let mut options = vec![0_u8; len];
        for byte in &mut options {
            *byte = (next() >> 16) as u8;
        }
        print_case(&mut output, &format!("r{index}"), known, &options);
    }

    std::fs::write(path, &output).unwrap();
    print!("{output}");

    // Профиль metadata: UNKNOWN не должен превращаться в NO_TS.
    assert_eq!(
        tcp_timestamp_metadata(&[8, 10, 0, 0, 0, 0, 0, 0, 0, 0]),
        Some(true)
    );
    assert_eq!(tcp_timestamp_metadata(&[1, 0]), Some(false));
    assert_eq!(tcp_timestamp_metadata(&[8, 10]), None);
    assert_eq!(tcp_timestamp_metadata(&[0; 41]), None);
}
