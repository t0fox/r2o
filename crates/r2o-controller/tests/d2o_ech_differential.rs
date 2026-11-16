//! Rust-половина C/Rust differential для ECH-контрактов core-net.
//!
//! Скрипт `scripts/r2o-ech-differential.sh` запускает C-фикстуру
//! `tests/d2o_ech_differential.c` (production tls13.c/verify.o) и этот тест;
//! обе стороны печатают одни и те же поля, коды и reason.

#![cfg(unix)]

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::{FromRawFd, OwnedFd};
use std::time::Duration;

use r2o_controller::ech::{R2oEchConfig, r2o_ech_tls_config};
use r2o_controller::fetch::{
    R2oEchProbeOutcome, r2o_verify_probe_ech_on, r2o_verify_probe_ech_origin_on_with_config,
};
use r2o_controller::r2o_tls::{
    r2o_tls_ech_accepted, r2o_tls_ech_client_connection, r2o_tls_ech_client_hello,
};

const CONFIG_HEX: &str = "0045fe0d004137002000200d1bbf3935b6317f6bc0a07894ba03bb3c32dc86758dcf67fef797a98360c97b0004000100010012636c6f7564666c6172652d6563682e636f6d0000";
const PUBLIC_NAME: &str = "cloudflare-ech.com";
const ORIGIN: &str = "echo.test";

fn unhex(input: &str) -> Vec<u8> {
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn config() -> R2oEchConfig {
    R2oEchConfig {
        public_name: PUBLIC_NAME.into(),
        origin_name: "origin.example".into(),
        config_list: unhex(CONFIG_HEX),
    }
}

fn connected_stream() -> TcpStream {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let stream = TcpStream::connect(address).unwrap();
    let _peer = listener.accept().unwrap();
    stream
}

fn bound_stream() -> TcpStream {
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    };
    assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets()),
        },
        sin_zero: [0; 8],
    };
    let rc = unsafe {
        libc::bind(
            fd,
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "bind: {}", std::io::Error::last_os_error());
    TcpStream::from(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn close_after_accept(listener: TcpListener) -> (u16, std::thread::JoinHandle<()>) {
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let thread = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut bytes = [0_u8; 4096];
                    let _ = stream.read(&mut bytes);
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    (port, thread)
}

fn fd_state(outcome: &R2oEchProbeOutcome) -> &'static str {
    if outcome.fd() >= 0 { "open" } else { "closed" }
}

fn print_outcome(label: &str, outcome: &R2oEchProbeOutcome) -> String {
    format!(
        "{label} level={} name={} ech={} status={} complete={} body={} fd={} reason={}\n",
        outcome.level,
        outcome.name_ok,
        u8::from(outcome.ech_accepted),
        outcome.status,
        u8::from(outcome.body_complete),
        outcome.body_bytes,
        fd_state(outcome),
        outcome.reason
    )
}

fn print_reason_prefix(label: &str, outcome: &R2oEchProbeOutcome) -> String {
    let prefix = outcome
        .reason
        .split_once(':')
        .map_or(outcome.reason.as_str(), |(prefix, _)| prefix);
    format!(
        "{label} level={} name={} ech={} status={} complete={} body={} fd={} reason={prefix}\n",
        outcome.level,
        outcome.name_ok,
        u8::from(outcome.ech_accepted),
        outcome.status,
        u8::from(outcome.body_complete),
        outcome.body_bytes,
        fd_state(outcome)
    )
}

fn handle_extension(body: &[u8], wanted: u16) -> Option<&[u8]> {
    let mut cursor = 4 + 2 + 32;
    let session = usize::from(*body.get(cursor)?);
    cursor += 1 + session;
    let ciphers = usize::from(u16::from_be_bytes([
        *body.get(cursor)?,
        *body.get(cursor + 1)?,
    ]));
    cursor += 2 + ciphers;
    let compression = usize::from(*body.get(cursor)?);
    cursor += 1 + compression;
    let extensions = usize::from(u16::from_be_bytes([
        *body.get(cursor)?,
        *body.get(cursor + 1)?,
    ]));
    cursor += 2;
    let end = cursor.checked_add(extensions)?.min(body.len());
    while cursor + 4 <= end {
        let kind = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
        let length = usize::from(u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]));
        cursor += 4;
        if cursor + length > end {
            return None;
        }
        if kind == wanted {
            return Some(&body[cursor..cursor + length]);
        }
        cursor += length;
    }
    None
}

fn hex_list(data: &[u8], start: usize, count: usize) -> String {
    data[start..start + count]
        .chunks_exact(2)
        .map(|pair| format!("{:04x}", u16::from_be_bytes([pair[0], pair[1]])))
        .collect::<Vec<_>>()
        .join(",")
}

fn hello_fields(record: &[u8]) -> String {
    let body = &record[5..];
    let tls13 = record.first() == Some(&22)
        && record.get(5) == Some(&1)
        && handle_extension(body, 0x002b).is_some_and(|data| {
            data.len() >= 1
                && (0..usize::from(data[0]) / 2).any(|index| {
                    data.get(1 + index * 2..3 + index * 2)
                        .is_some_and(|version| version == [0x03, 0x04])
                })
        });
    let tls12 = handle_extension(body, 0x002b).is_some_and(|data| {
        data.len() >= 1
            && (0..usize::from(data[0]) / 2).any(|index| {
                data.get(1 + index * 2..3 + index * 2)
                    .is_some_and(|version| version == [0x03, 0x03])
            })
    });
    let alpn = handle_extension(body, 0x0010)
        .and_then(|data| {
            let length = usize::from(u16::from_be_bytes([data[0], data[1]]));
            let protocol = usize::from(*data.get(2)?);
            (2 + 1 + protocol <= data.len() && length >= 1 + protocol)
                .then(|| String::from_utf8_lossy(&data[3..3 + protocol]).into_owned())
        })
        .unwrap_or_default();
    let sni = handle_extension(body, 0x0000)
        .and_then(|data| {
            let length = usize::from(u16::from_be_bytes([data[3], data[4]]));
            (5 + length <= data.len())
                .then(|| String::from_utf8_lossy(&data[5..5 + length]).into_owned())
        })
        .unwrap_or_default();
    let ech = handle_extension(body, 0xfe0d);
    let ech_id = ech
        .as_ref()
        .and_then(|data| data.get(5).copied())
        .unwrap_or(0);
    let cipher_at = 4 + 2 + 32;
    let session = usize::from(body[cipher_at]);
    let cipher_len_at = cipher_at + 1 + session;
    let cipher_len = usize::from(u16::from_be_bytes([
        body[cipher_len_at],
        body[cipher_len_at + 1],
    ]));
    let ciphers = hex_list(body, cipher_len_at + 2, cipher_len);
    let groups = handle_extension(body, 0x000a)
        .map(|data| {
            let length = usize::from(u16::from_be_bytes([data[0], data[1]]));
            hex_list(data, 2, length)
        })
        .unwrap_or_default();
    let keyshare = handle_extension(body, 0x0033)
        .map(|data| {
            let list = usize::from(u16::from_be_bytes([data[0], data[1]]));
            let mut cursor = 2;
            let end = (2 + list).min(data.len());
            let mut groups = Vec::new();
            while cursor + 4 <= end {
                groups.push(format!(
                    "{:04x}",
                    u16::from_be_bytes([data[cursor], data[cursor + 1]])
                ));
                let size = usize::from(u16::from_be_bytes([data[cursor + 2], data[cursor + 3]]));
                cursor += 4 + size;
            }
            groups.join(",")
        })
        .unwrap_or_default();
    format!(
        "hello tls13={} tls12={} alpn={} sni={} ech={} ech_id={} cipher={} groups={} keyshare={}\n",
        u8::from(tls13),
        u8::from(tls12),
        alpn,
        sni,
        u8::from(ech.is_some()),
        ech_id,
        ciphers,
        groups,
        keyshare
    )
}

/// Живой ECH-сервер проверяется вручную: сеть и текущий HTTPS-RR не входят в
/// детерминированный differential. Запуск:
/// `R2O_ECH_LIVE=1 cargo test ... ech_live_origin -- --ignored`.
#[test]
#[ignore = "живой ECH: нужен сетевой доступ и актуальный HTTPS RR"]
fn ech_live_origin_matches_c_fields() {
    if std::env::var_os("R2O_ECH_LIVE").is_none() {
        return;
    }
    let origin = "crypto.cloudflare.com";
    let address = (origin, 443)
        .to_socket_addrs()
        .unwrap()
        .find(|address| address.is_ipv4())
        .unwrap();
    let config = r2o_controller::ech::resolve_ech_config(origin, None).unwrap();
    let outcome = r2o_controller::fetch::r2o_verify_probe_ech_origin_on(
        None,
        address.ip(),
        address.port(),
        Some(&config.public_name),
        Some(origin),
        Duration::from_secs(8),
        None,
        None,
        None,
    );
    println!(
        "live level={} name={} ech={} status={} complete={} body={} reason={}",
        outcome.level,
        outcome.name_ok,
        u8::from(outcome.ech_accepted),
        outcome.status,
        u8::from(outcome.body_complete),
        outcome.body_bytes,
        outcome.reason
    );
    assert_eq!(config.public_name, PUBLIC_NAME);
    assert!(outcome.ech_accepted);
    assert_eq!(outcome.name_ok, 1);
    assert_eq!(outcome.level, r2o_controller::live::D2K_VER_APPLICATION);
    assert!(outcome.body_complete);
}

#[test]
fn ech_contracts_match_c_fixture() {
    let Some(output_path) = std::env::var_os("R2O_ECH_DIFF_OUTPUT") else {
        return;
    };
    let config = config();
    let ech = r2o_ech_tls_config(&config).unwrap();
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let deadline = Duration::from_secs(1);
    let mut output = String::new();

    let mut outcome = r2o_verify_probe_ech_on(
        Some(connected_stream()),
        ip,
        9,
        Some(ORIGIN),
        None,
        deadline,
        None,
        None,
        None,
    );
    output.push_str(&print_outcome("guard config_null", &outcome));
    outcome.close();

    let mut outcome = r2o_verify_probe_ech_on(
        Some(connected_stream()),
        ip,
        9,
        None,
        Some(&ech),
        deadline,
        None,
        None,
        None,
    );
    output.push_str(&print_outcome("guard origin_null", &outcome));
    outcome.close();

    let mut outcome = r2o_verify_probe_ech_on(
        Some(connected_stream()),
        ip,
        9,
        Some(""),
        Some(&ech),
        deadline,
        None,
        None,
        None,
    );
    output.push_str(&print_outcome("guard origin_empty", &outcome));
    outcome.close();

    let mut outcome = r2o_verify_probe_ech_on(
        Some(connected_stream()),
        ip,
        9,
        Some(ORIGIN),
        Some(&ech),
        deadline,
        None,
        Some(0),
        Some("/../escape.css"),
    );
    output.push_str(&print_outcome("guard path", &outcome));
    outcome.close();

    let mut outcome = r2o_verify_probe_ech_on(
        Some(connected_stream()),
        ip,
        9,
        Some("bad host"),
        Some(&ech),
        deadline,
        None,
        None,
        None,
    );
    output.push_str(&print_outcome("guard host", &outcome));
    outcome.close();

    let mut outcome = r2o_verify_probe_ech_origin_on_with_config(
        Some(connected_stream()),
        ip,
        9,
        None,
        Some("origin.example"),
        Some(&config),
        deadline,
        None,
        None,
        None,
    );
    output.push_str(&print_outcome("origin outer_null", &outcome));
    outcome.close();

    let mut outcome = r2o_verify_probe_ech_origin_on_with_config(
        Some(connected_stream()),
        ip,
        9,
        Some(PUBLIC_NAME),
        None,
        Some(&config),
        deadline,
        None,
        None,
        None,
    );
    output.push_str(&print_outcome("origin origin_null", &outcome));
    outcome.close();

    let mut outcome = r2o_verify_probe_ech_origin_on_with_config(
        Some(connected_stream()),
        ip,
        9,
        Some("other.example"),
        Some("origin.example"),
        Some(&config),
        deadline,
        None,
        None,
        None,
    );
    output.push_str(&print_outcome("origin mismatch", &outcome));
    outcome.close();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let (port, server) = close_after_accept(listener);
    let mut outcome = r2o_verify_probe_ech_on(
        None,
        ip,
        port,
        Some(ORIGIN),
        Some(&ech),
        deadline,
        None,
        None,
        None,
    );
    output.push_str(&print_reason_prefix("ech use_fd_none_tls", &outcome));
    outcome.close();
    server.join().unwrap();

    let refused = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let refused_port = refused.local_addr().unwrap().port();
    drop(refused);
    let mut outcome = r2o_verify_probe_ech_on(
        None,
        ip,
        refused_port,
        Some(ORIGIN),
        Some(&ech),
        deadline,
        None,
        None,
        None,
    );
    output.push_str(&print_outcome("ech use_fd_none_refused", &outcome));
    outcome.close();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let (port, server) = close_after_accept(listener);
    let mut outcome = r2o_verify_probe_ech_on(
        Some(bound_stream()),
        ip,
        port,
        Some(ORIGIN),
        Some(&ech),
        deadline,
        None,
        None,
        None,
    );
    output.push_str(&print_reason_prefix("ech use_fd_bound", &outcome));
    outcome.close();
    server.join().unwrap();

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let (port, server) = close_after_accept(listener);
    let mut outcome = r2o_verify_probe_ech_origin_on_with_config(
        Some(bound_stream()),
        ip,
        port,
        Some(PUBLIC_NAME),
        Some("origin.example"),
        Some(&config),
        deadline,
        None,
        None,
        None,
    );
    output.push_str(&print_reason_prefix("origin use_fd_bound", &outcome));
    outcome.close();
    server.join().unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let error = r2o_tls_ech_client_connection("", roots, ech.clone(), None).unwrap_err();
    output.push_str(&format!("tls origin_empty code=-1 reason={error}\n"));

    let hello = r2o_tls_ech_client_hello(ORIGIN, ech).unwrap();
    output.push_str(&hello_fields(&hello));

    output.push_str(&format!(
        "accepted null={} off={} on={}\n",
        u8::from(r2o_tls_ech_accepted(None)),
        u8::from(r2o_tls_ech_accepted(Some(
            rustls::client::EchStatus::Rejected
        ))),
        u8::from(r2o_tls_ech_accepted(Some(
            rustls::client::EchStatus::Accepted
        )))
    ));

    std::fs::write(output_path, output).unwrap();
}
