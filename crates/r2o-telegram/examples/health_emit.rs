//! Записать D2O heartbeat-файл и остаться живым для watchdog-проверки.
//!
//! ```text
//! health_emit PATH [SECONDS] [READY]
//! ```

use std::time::Duration;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .expect("использование: health_emit PATH [SECONDS] [READY]");
    let seconds = args
        .next()
        .map(|value| value.parse::<u64>().expect("SECONDS"))
        .unwrap_or(5);
    let ready = args.next().map(|value| value != "0").unwrap_or(true);
    let writer = r2o_telegram::health::HealthWriter::new(path.into()).expect("heartbeat файл");
    writer.write(false, ready, false).expect("первый heartbeat");
    std::thread::sleep(Duration::from_secs(seconds));
}
