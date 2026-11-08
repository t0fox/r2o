//! M5: Rust trace volume RX — partial/pair/repeat/evidence.

use r2o_controller::r2o_volume::{
    R2oVolumeObservation, R2oVolumeProbeStage, R2oVolumeRxDomain, R2oVolumeRxEncoding,
    r2o_volume_rx_evidence, r2o_volume_rx_needs_repeat, r2o_volume_rx_pair_agrees,
    r2o_volume_rx_partial,
};

fn body() -> R2oVolumeObservation {
    R2oVolumeObservation {
        stage: R2oVolumeProbeStage::Application,
        name_valid: true,
        status: 200,
        body_framing_valid: true,
        body_has_length: true,
        body_bytes: 20000,
        body_expected: 100000,
        data_packets: 10,
        ..R2oVolumeObservation::default()
    }
}

fn wire() -> R2oVolumeObservation {
    R2oVolumeObservation {
        stage: R2oVolumeProbeStage::Handshake,
        name_valid: true,
        negotiated_tls: Some(0x0304),
        rx_tls_wire_bytes: 20000,
        rx_tls_record_missing: true,
        data_packets: 10,
        ..R2oVolumeObservation::default()
    }
}

fn print_partial(name: &str, value: &R2oVolumeObservation) {
    println!("case {name}\nvalue={}", u8::from(r2o_volume_rx_partial(value)));
}

fn main() {
    let body_a = body();
    let mut body_b = body_a;
    body_b.body_bytes = 20100;
    body_b.data_packets = 12;

    let mut chunked = body_a;
    chunked.body_has_length = false;
    chunked.body_chunked = true;
    chunked.body_expected = 30000;

    let wire_a = wire();
    let mut wire_b = wire_a;
    wire_b.rx_tls_wire_bytes = 20100;
    wire_b.data_packets = 12;

    let mut complete = body_a;
    complete.body_complete = true;
    complete.body_bytes = 20000;
    complete.body_expected = 20000;

    let mut small = body_a;
    small.body_bytes = 1000;

    let gzip = R2oVolumeObservation {
        stage: R2oVolumeProbeStage::Application,
        name_valid: true,
        status: 200,
        body_complete: true,
        body_framing_valid: true,
        body_encoding: R2oVolumeRxEncoding::Gzip,
        body_bytes: 5000,
        ..R2oVolumeObservation::default()
    };
    let mut gzip_wire = gzip;
    gzip_wire.negotiated_tls = Some(0x0304);
    gzip_wire.rx_tls_wire_bytes = 10000;

    print_partial("partial-body", &body_a);
    print_partial("partial-chunked", &chunked);
    print_partial("partial-wire", &wire_a);
    print_partial("partial-complete", &complete);
    print_partial("partial-small", &small);
    println!(
        "case pair-body\nvalue={}",
        u8::from(r2o_volume_rx_pair_agrees(&body_a, &body_b))
    );
    println!(
        "case pair-mixed\nvalue={}",
        u8::from(r2o_volume_rx_pair_agrees(&body_a, &wire_a))
    );
    println!(
        "case pair-wire\nvalue={}",
        u8::from(r2o_volume_rx_pair_agrees(&wire_a, &wire_b))
    );
    println!(
        "case repeat-yes\nvalue={}",
        u8::from(r2o_volume_rx_needs_repeat(&body_a, &complete))
    );
    println!(
        "case repeat-no-small\nvalue={}",
        u8::from(r2o_volume_rx_needs_repeat(&body_a, &small))
    );

    for (name, a, b, gzip) in [
        ("evidence-body", &body_a, &body_b, &gzip),
        ("evidence-wire", &wire_a, &wire_b, &gzip_wire),
    ] {
        println!("case {name}");
        match r2o_volume_rx_evidence(a, b, gzip) {
            Some(evidence) => {
                let basis = u8::from(evidence.domain == R2oVolumeRxDomain::TlsWire);
                println!("value=1");
                println!(
                    "cut=1 basis={basis} at_kb={} expected_kb={} packets={} compressed={}",
                    evidence.cut_kb,
                    evidence.expected_kb,
                    evidence.cut_packets,
                    u8::from(evidence.compressed_complete)
                );
            }
            None => println!("value=0"),
        }
    }
    let mut reject = gzip;
    reject.body_encoding = R2oVolumeRxEncoding::Identity;
    println!(
        "case evidence-reject\nvalue={}",
        u8::from(r2o_volume_rx_evidence(&wire_a, &wire_b, &reject).is_some())
    );
}
