//! M6: Rust trace udpplan — голосовой план Discord.

use r2o_controller::voice_measure::{R2oVoiceArm, r2o_measured_voice_arm_plan_text};

fn main() {
    static DECOY: [u8; 20] = [
        0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14,
    ];
    for copies in [1u8, 6, 10] {
        println!("case voice-{copies}");
        match r2o_measured_voice_arm_plan_text(R2oVoiceArm {
            name: "voice",
            bytes: &DECOY,
            copies,
        }) {
            Ok(text) => print!("{text}"),
            Err(_) => println!("rc=-1"),
        }
    }
}
