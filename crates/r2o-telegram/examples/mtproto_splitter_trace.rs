//! Печатает кадры `MsgSplitter` в формате C `d2o_mtproto_splitter_trace.c`.

use r2o_telegram::crypto::{ProtoTag, make_cipher};
use r2o_telegram::splitter::MsgSplitter;

fn print_hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{byte:02x}");
    }
}

fn run(name: &str, proto: ProtoTag, plain: &[u8], cuts: &[usize], flush: bool) {
    let mut splitter = MsgSplitter::new(proto);
    let mut cipher = make_cipher(&[0u8; 32], &[0u8; 16]);
    let mut frames = Vec::new();
    let mut offset = 0;
    for &len in cuts {
        if len > 0 {
            let mut chunk = plain[offset..offset + len].to_vec();
            frames.extend(splitter.split_and_encrypt(&mut chunk, &mut cipher));
        }
        offset += len;
    }
    if flush {
        frames.extend(splitter.flush());
    }
    print!("{name}=result:0 frames:");
    for (index, frame) in frames.iter().enumerate() {
        if index != 0 {
            print!(",");
        }
        print_hex(frame);
    }
    println!(" error:{}", if splitter.error().is_some() { -2 } else { 0 });
}

fn main() {
    let packet = [8, 0, 0, 0, b'A', b'B', b'C', b'D', b'W', b'X', b'Y', b'Z'];
    run(
        "padded_split",
        ProtoTag::PaddedIntermediate,
        &packet,
        &[5, 7],
        false,
    );
    let packets = [
        8, 0, 0, 0, b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H', 4, 0, 0, 0, b'W', b'X', b'Y',
        b'Z',
    ];
    run(
        "intermediate_two",
        ProtoTag::Intermediate,
        &packets,
        &[packets.len()],
        false,
    );
    let packet = [2, b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H'];
    run(
        "abridged_short",
        ProtoTag::Abridged,
        &packet,
        &[3, 6],
        false,
    );
    let packet = [
        0x7f, 2, 0, 0, b'A', b'B', b'C', b'D', b'E', b'F', b'G', b'H',
    ];
    run(
        "abridged_extended",
        ProtoTag::Abridged,
        &packet,
        &[4, 8],
        false,
    );
    let packet = [12, 0, 0, 0, b'A', b'B', b'C'];
    run(
        "partial_flush",
        ProtoTag::Intermediate,
        &packet,
        &[7],
        true,
    );
}
