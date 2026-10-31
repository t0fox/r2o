#[path = "../../src/hello.rs"]
mod hello;

fn main() {
    for name in ["hcaptcha.com", "video.edge.example.net"] {
        let bytes = hello::r2o_rx_fake_client_hello(name).expect("white ECH ClientHello");
        print!("{name}=");
        for byte in bytes {
            print!("{byte:02x}");
        }
        println!();
    }
}
