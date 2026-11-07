//! Печатает v22 SET_NAME_BOUND ACK body для C/Rust differential.

use r2k_core::control::{
    BindingContext, COMMAND_SET_NAME_BOUND, SHAPE_HTTP, WireProfile,
    encode_ack_with_identifiers_profile, read_frame,
};

fn main() {
    let binding = BindingContext {
        generation: 0x0102_0304_0506_0708,
        kind: 1,
        family: 4,
        shape: SHAPE_HTTP,
        temporary: false,
        epoch: [0x11; 16],
    };
    let bytes = encode_ack_with_identifiers_profile(
        WireProfile::V22,
        COMMAND_SET_NAME_BOUND,
        true,
        0,
        Some([0x22; 16]),
        None,
        Some(binding),
    )
    .unwrap();
    let frame = read_frame(&mut std::io::Cursor::new(bytes)).unwrap();
    for byte in frame.body {
        print!("{byte:02x}");
    }
    println!();
}
