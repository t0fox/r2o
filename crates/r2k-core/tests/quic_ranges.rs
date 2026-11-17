//! C/Rust differential: `d2k_qw_ranges_*` (core/quicwire.c:525-571).

use r2k_core::quic_ranges::{R2K_QUIC_RANGES_MAX, R2oQuicRanges};

fn print_state(output: &mut String, label: &str, ranges: &R2oQuicRanges) {
    output.push_str(label);
    output.push(',');
    output.push_str(&ranges.len().to_string());
    output.push(',');
    if ranges.is_empty() {
        output.push('-');
    } else {
        for index in 0..ranges.len() {
            let (start, end) = ranges.range(index).unwrap();
            if index != 0 {
                output.push(';');
            }
            output.push_str(&format!("{start}-{end}"));
        }
    }
    output.push_str(&format!(
        ",{},{},{},{}\n",
        ranges.bytes(),
        u8::from(ranges.complete()),
        u8::from(ranges.fin_seen()),
        ranges.fin_offset()
    ));
}

#[test]
fn quic_ranges_match_c() {
    let Some(path) = std::env::var_os("R2O_QUIC_RANGES_DIFF_OUTPUT") else {
        return;
    };
    let mut output = String::new();
    let mut ranges = R2oQuicRanges::new();
    print_state(&mut output, "empty", &ranges);
    ranges.add(0, 4, false);
    print_state(&mut output, "first4", &ranges);
    ranges.add(2, 8, false);
    print_state(&mut output, "merge_to10", &ranges);
    ranges.add(10, 5, false);
    print_state(&mut output, "touch_to15", &ranges);
    ranges.add(20, 5, false);
    print_state(&mut output, "gap", &ranges);
    ranges.add(15, 5, false);
    print_state(&mut output, "fill_gap", &ranges);
    ranges.add(0, 25, false);
    print_state(&mut output, "duplicate", &ranges);
    ranges.add(25, 0, true);
    print_state(&mut output, "fin", &ranges);
    ranges.reset();
    print_state(&mut output, "reset", &ranges);
    ranges.add(1000, 2000, true);
    print_state(&mut output, "fin_no_prefix", &ranges);
    ranges.add(0, 1000, false);
    print_state(&mut output, "fin_prefix_filled", &ranges);
    ranges.reset();
    ranges.add(2000, 1000, true);
    ranges.add(0, 1000, false);
    print_state(&mut output, "hole_before_fin", &ranges);
    ranges.reset();
    ranges.add(0, 0, true);
    print_state(&mut output, "empty_fin", &ranges);
    ranges.reset();
    ranges.add(u64::MAX, 1, false);
    print_state(&mut output, "overflow", &ranges);
    ranges.add(u64::MAX - 1, 10, false);
    print_state(&mut output, "overflow_fin", &ranges);
    ranges.reset();
    for index in 0..R2K_QUIC_RANGES_MAX as u64 {
        ranges.add(index * 10, 1, false);
    }
    print_state(&mut output, "max64", &ranges);
    ranges.add(1000, 1, false);
    print_state(&mut output, "max64_extra", &ranges);
    ranges.add(0, 630, false);
    print_state(&mut output, "max64_merge", &ranges);
    ranges.reset();
    ranges.add(30, 10, false);
    ranges.add(0, 10, false);
    ranges.add(10, 10, false);
    ranges.add(20, 10, false);
    print_state(&mut output, "out_of_order", &ranges);
    ranges.reset();
    ranges.add(0, 10, true);
    ranges.add(10, 10, false);
    print_state(&mut output, "fin_then_data", &ranges);
    ranges.reset();
    ranges.add(0, 0, false);
    print_state(&mut output, "zero_len", &ranges);
    ranges.reset();
    ranges.add(1_u64 << 32, 1_u64 << 32, false);
    print_state(&mut output, "large1", &ranges);
    ranges.add(3_u64 << 32, 1_u64 << 32, false);
    print_state(&mut output, "large2", &ranges);
    ranges.add(3_u64 << 32, 1_u64 << 32, false);
    print_state(&mut output, "large_dup", &ranges);

    std::fs::write(path, &output).unwrap();
    print!("{output}");
}
