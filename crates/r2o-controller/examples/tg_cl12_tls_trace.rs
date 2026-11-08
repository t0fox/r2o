//! CL12: Rust ClientHello/TLS1.2/1.3/ECH parser trace.
//!
//! ```text
//! tg_cl12_tls_trace DIR CASES
//! ```

use r2k_core::tls::parse;
use r2o_controller::hello::{
    HelloEchOffer, HelloShape, hello_complete, hello_ech_offer, hello_shape, hello_sni_bounds,
};

/// Координаты, которых C-оракул не выдал, печатаются как 0: у него поля
/// структуры обнулены `memset`, и сравнение обязано видеть то же самое.
fn coordinate(value: Option<usize>) -> usize {
    value.unwrap_or(0)
}

fn shape_name(shape: HelloShape) -> &'static str {
    match shape {
        HelloShape::Modern => "modern",
        HelloShape::Legacy => "legacy",
        HelloShape::Unknown => "unknown",
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args.next().expect("DIR");
    let cases = args.next().expect("CASES");
    let text = std::fs::read_to_string(cases).expect("cases");
    for name in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let path = format!("{dir}/{name}.bin");
        let Ok(bytes) = std::fs::read(&path) else {
            println!("{name} read-error");
            continue;
        };
        let info = parse(&bytes);
        let tls_sni = info.sni_range.clone();
        let hello_sni = hello_sni_bounds(&bytes);
        let (ech, ech_id) = match hello_ech_offer(&bytes) {
            HelloEchOffer::Incomplete => (-1, 0),
            HelloEchOffer::Absent => (0, 0),
            HelloEchOffer::Present { config_id } => (1, i32::from(config_id)),
        };
        println!(
            "{name} tls={} type={} ch={} sh={} tls13={} ech={} trunc={} \
             sni={}:{}:{} hello_sni={}:{}:{} rec={}:{} mid={}:{} \
             shape={} complete={} hello_ech={} hello_ech_id={}",
            u8::from(info.is_tls_record),
            info.record_type,
            u8::from(info.is_client_hello),
            u8::from(info.is_server_hello),
            u8::from(info.is_tls13),
            u8::from(info.ech_offer),
            u8::from(info.extensions_truncated),
            u8::from(tls_sni.is_some()),
            coordinate(tls_sni.as_ref().map(|range| range.start)),
            tls_sni.as_ref().map_or(0, |range| range.len()),
            u8::from(hello_sni.is_some()),
            coordinate(hello_sni.map(|(offset, _)| offset)),
            hello_sni.map_or(0, |(_, length)| length),
            u8::from(info.record_end.is_some()),
            coordinate(info.record_end),
            u8::from(info.hello_middle.is_some()),
            coordinate(info.hello_middle),
            shape_name(hello_shape(&bytes)),
            u8::from(hello_complete(&bytes)),
            ech,
            ech_id,
        );
    }
}
