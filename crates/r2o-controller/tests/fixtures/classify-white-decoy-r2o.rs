#[path = "../../src/hello.rs"]
mod hello;
#[path = "../../src/trigger.rs"]
mod trigger;

fn print_tls_trigger(label: &str, bytes: Vec<u8>) {
    print!("{label} name=tls:example.com accept=server-hello bytes=");
    for byte in bytes {
        print!("{byte:02x}");
    }
    println!();
}

fn main() {
    for name in ["hcaptcha.com", "video.edge.example.net"] {
        let bytes = hello::r2o_rx_fake_client_hello(name).expect("white ECH ClientHello");
        print!("{name}=");
        for byte in bytes {
            print!("{byte:02x}");
        }
        println!();
    }

    let default_control = hello::modern_client_hello("probe-d2k.invalid-control.example")
        .expect("D2O default CLI control");
    print!("CONTROL_DEFAULT name=control accept=tls-record bytes=");
    for byte in default_control {
        print!("{byte:02x}");
    }
    println!();

    print_tls_trigger(
        "TARGET_DEFAULT",
        hello::modern_client_hello("example.com").expect("default target TLS profile"),
    );
    print_tls_trigger(
        "TARGET_LEGACY",
        hello::legacy_client_hello("example.com").expect("legacy target TLS profile"),
    );

    let custom_control = hello::modern_client_hello("example.com").expect("custom control SNI");
    print!("CONTROL_CUSTOM name=control:example.com accept=tls-record bytes=");
    for byte in custom_control {
        print!("{byte:02x}");
    }
    println!();

    let raw_control = trigger::parse_raw_hex("57 41:06-03").expect("raw control hex");
    print!(
        "TARGET_RAW name=raw:{}B accept=any bytes=",
        raw_control.len()
    );
    for byte in &raw_control {
        print!("{byte:02x}");
    }
    println!();
    for byte in &raw_control {
        print!("{byte:02x}");
    }
    println!();

    print!("CONTROL_RAW name=control accept=tls-record bytes=");
    for byte in raw_control {
        print!("{byte:02x}");
    }
    println!();
}
