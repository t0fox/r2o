//! Минимальный control-сервер r2o-datapath для live differential с D2O `d2kc`.
//!
//! Использует production `ControlServer` без NFQUEUE: полному `r2o-datapath`
//! нужен CAP_NET_ADMIN, а проверке профиля провода нужен только Unix-сокет.
//!
//! ```text
//! control_v22_harness --control PATH [--wire v22|v48] [--release ID]
//!                      [--send-maxlen N] [--duration-ms N] [--trace PATH]
//! ```

use r2o_datapath::control::ControlServer;
use std::error::Error;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn argument<'a>(args: &'a [String], index: &mut usize, name: &str) -> Result<&'a str, String> {
    *index += 1;
    args.get(*index)
        .map(String::as_str)
        .ok_or_else(|| format!("{name} требует значение"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("control_v22_harness: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut control: Option<PathBuf> = None;
    let mut wire = r2k_core::control::WireProfile::V22;
    let mut release = "dev".to_owned();
    let mut send_maxlen = 1500_u32;
    let mut duration = Duration::from_secs(5);
    let mut trace: Option<PathBuf> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--control" => control = Some(PathBuf::from(argument(&args, &mut index, "--control")?)),
            "--wire" => {
                wire = match argument(&args, &mut index, "--wire")? {
                    "v22" => r2k_core::control::WireProfile::V22,
                    "v48" => r2k_core::control::WireProfile::V48,
                    other => return Err(format!("неизвестный --wire {other}").into()),
                }
            }
            "--release" => release = argument(&args, &mut index, "--release")?.to_owned(),
            "--send-maxlen" => {
                send_maxlen = argument(&args, &mut index, "--send-maxlen")?.parse()?
            }
            "--duration-ms" => {
                duration =
                    Duration::from_millis(argument(&args, &mut index, "--duration-ms")?.parse()?)
            }
            "--trace" => trace = Some(PathBuf::from(argument(&args, &mut index, "--trace")?)),
            other => return Err(format!("неизвестный аргумент {other}").into()),
        }
        index += 1;
    }
    let control = control.ok_or("--control обязателен")?;
    let mut server = ControlServer::open_with_profile(&control, send_maxlen, wire, &release)?;
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        for frame in server.poll()? {
            if let Some(path) = &trace {
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                writeln!(file, "kind=0x{:04x} len={}", frame.kind, frame.body.len())?;
            }
            if (0x0081..=0x0093).contains(&frame.kind) {
                let ack = r2k_core::control::Ack {
                    command: frame.kind,
                    ok: true,
                    reason: r2k_core::control::ACK_OK,
                    trial_id: None,
                    area_id: None,
                    binding_context: None,
                };
                // SET_NAME_BOUND требует binding; для handshake-проверки его
                // отсутствие допустимо — d2kc получит отказ и продолжит.
                let _ = server.send_ack(ack);
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
