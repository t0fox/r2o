//! TG8: Rust resPQ probe против fake MTProto DC.
//!
//! ```text
//! res_pq_probe_client PORT
//! ```

use tokio::net::TcpStream;

use r2o_telegram::dc_discovery::probe_res_pq;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args().nth(1).expect("PORT").parse().unwrap();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    match probe_res_pq(&mut stream).await {
        Ok(_) => println!("ok=1"),
        Err(error) => {
            eprintln!("probe: {error}");
            println!("ok=0");
        }
    }
}
