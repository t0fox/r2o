//! C/Rust differential: Discord IP Discovery response.

use r2k_core::stun::is_discord_ip_discovery_response;

const SSRC: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

fn make(text: &[u8], nul_after_text: bool) -> Vec<u8> {
    let mut packet = vec![0; 74];
    packet[..4].copy_from_slice(&[0, 2, 0, 70]);
    packet[4..8].copy_from_slice(&SSRC);
    packet[8..8 + text.len()].copy_from_slice(text);
    if nul_after_text && 8 + text.len() < 72 {
        packet[8 + text.len()] = 0;
    }
    packet[72..74].copy_from_slice(&[0xC3, 0x5C]);
    packet
}

fn main() {
    let cases: Vec<(&str, Vec<u8>, [u8; 4])> = vec![
        ("valid", make(b"203.0.113.7", true), SSRC),
        ("colons", make(b"::", true), SSRC),
        ("dots", make(b"...", true), SSRC),
        ("ip-port", make(b"1.2.3.4:443", true), SSRC),
        ("nul-tail", make(b"1.2.3.4\0::", false), SSRC),
        ("control", make(b"1.2.3.4\x01", true), SSRC),
        ("letters", make(b"abc", true), SSRC),
        ("space", make(b"1.2.3.4 tail", true), SSRC),
        ("no-nul", make(b"11111111111111111111", false), SSRC),
        ("empty", make(b"", true), SSRC),
        (
            "zero-port",
            {
                let mut packet = make(b"203.0.113.7", true);
                packet[72..74].fill(0);
                packet
            },
            SSRC,
        ),
        (
            "other-ssrc",
            make(b"203.0.113.7", true),
            [0x12, 0x34, 0x56, 0x79],
        ),
        ("short", make(b"203.0.113.7", true)[..73].to_vec(), SSRC),
        (
            "bad-header",
            {
                let mut packet = make(b"203.0.113.7", true);
                packet[1] = 3;
                packet
            },
            SSRC,
        ),
    ];
    for (name, packet, ssrc) in cases {
        println!(
            "{name} result={}",
            u8::from(is_discord_ip_discovery_response(&packet, &ssrc))
        );
    }
}
