//! Локальный DoH-сервер для TG14 differential: TLS с SAN всех четырёх
//! D2O endpoints, HTTP/1.1 и HTTP/2 (ALPN), DNS-wire ответы.
//!
//! ```text
//! doh_test_server MODE CA_PEM PORT_FILE LOG_FILE
//! ```

use std::io::Write as _;
use std::net::IpAddr;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HOSTS: &[&str] = &[
    "d.webshiftvpn.ru",
    "cloudflare-dns.com",
    "dns.google",
    "dns.sb",
];

fn answers(mode: &str, host: &str, qtype: u16) -> Vec<IpAddr> {
    let v4 = |text: &str| text.parse::<IpAddr>().unwrap();
    let v6 = |text: &str| text.parse::<IpAddr>().unwrap();
    match mode {
        "valid" if host == "d.webshiftvpn.ru" => match qtype {
            1 => vec![v4("104.21.1.1")],
            28 => vec![v6("2606:4700::1111")],
            _ => Vec::new(),
        },
        "fallback" if host == "d.webshiftvpn.ru" => Vec::new(),
        "fallback" if host == "cloudflare-dns.com" => match qtype {
            1 => vec![v4("104.21.2.2")],
            28 => vec![v6("2606:4700::2222")],
            _ => Vec::new(),
        },
        "private" if host == "d.webshiftvpn.ru" => match qtype {
            1 => vec![v4("10.0.0.1")],
            28 => vec![v6("fc00::1")],
            _ => Vec::new(),
        },
        "private" if host == "cloudflare-dns.com" => match qtype {
            1 => vec![v4("104.21.2.2")],
            _ => Vec::new(),
        },
        "mixed" if host == "d.webshiftvpn.ru" => match qtype {
            1 => vec![v4("104.21.1.1")],
            28 => vec![v6("fc00::1")],
            _ => Vec::new(),
        },
        "aaaa" if host == "d.webshiftvpn.ru" => match qtype {
            28 => vec![v6("2606:4700::1111")],
            _ => Vec::new(),
        },
        "bad-id" if host == "d.webshiftvpn.ru" => match qtype {
            1 => vec![v4("104.21.1.1")],
            _ => Vec::new(),
        },
        "first-down" if host == "d.webshiftvpn.ru" => Vec::new(),
        "first-down" if host == "cloudflare-dns.com" => match qtype {
            1 => vec![v4("104.21.2.2")],
            28 => vec![v6("2606:4700::2222")],
            _ => Vec::new(),
        },
        _ => match qtype {
            1 => vec![v4("104.21.9.9")],
            28 => vec![v6("2606:4700::9999")],
            _ => Vec::new(),
        },
    }
}

fn question_end(packet: &[u8]) -> Option<usize> {
    let mut offset = 12usize;
    loop {
        let label = *packet.get(offset)? as usize;
        offset += 1;
        if label == 0 {
            break;
        }
        if label & 0xc0 != 0 {
            return None;
        }
        offset = offset.checked_add(label)?;
        if offset > packet.len() {
            return None;
        }
    }
    (offset + 4 <= packet.len()).then_some(offset + 4)
}

fn build_dns_response(mode: &str, host: &str, query: &[u8]) -> Vec<u8> {
    let Some(end) = question_end(query) else {
        return Vec::new();
    };
    let qtype = u16::from_be_bytes([query[end - 4], query[end - 3]]);
    let mut id = u16::from_be_bytes([query[0], query[1]]);
    if mode == "bad-id" && host == "d.webshiftvpn.ru" {
        id = id.wrapping_add(1);
    }
    let records = answers(mode, host, qtype);
    let mut out = Vec::with_capacity(12 + (end - 12) + records.len() * 28);
    out.extend_from_slice(&id.to_be_bytes());
    let rcode = if mode == "nxdomain" && host == "d.webshiftvpn.ru" {
        3u16
    } else {
        0
    };
    out.extend_from_slice(&(0x8180u16 | rcode).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(records.len() as u16).to_be_bytes());
    // NSCOUNT + ARCOUNT.
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[12..end]);
    for address in records {
        out.extend_from_slice(&[0xc0, 0x0c]);
        match address {
            IpAddr::V4(ip) => {
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&60u32.to_be_bytes());
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.extend_from_slice(&28u16.to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&60u32.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&ip.octets());
            }
        }
    }
    out
}

fn log_line(log: &mut std::fs::File, action: &str, host: &str, extra: &str) {
    let _ = writeln!(log, "{action} host={host} {extra}");
    let _ = log.flush();
}

async fn serve_h1(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    mode: String,
    host: String,
    log: Arc<std::sync::Mutex<std::fs::File>>,
) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    };
    let headers = String::from_utf8_lossy(&buffer[..header_end]).to_ascii_lowercase();
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buffer.len() < header_end + content_length {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    }
    let query = &buffer[header_end..header_end + content_length];
    let qtype = question_end_direct(query)
        .map(|_| u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]))
        .unwrap_or(0);
    log_line(
        &mut log.lock().unwrap(),
        "req",
        &host,
        &format!("alpn=h1 type={qtype}"),
    );
    let body = build_dns_response(&mode, &host, query);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(&body).await;
    let _ = stream.shutdown().await;
}

fn question_end_direct(packet: &[u8]) -> Option<usize> {
    question_end(packet)
}

async fn serve_h2(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    mode: String,
    log: Arc<std::sync::Mutex<std::fs::File>>,
) {
    let mut connection = match h2::server::handshake(stream).await {
        Ok(connection) => connection,
        Err(_) => return,
    };
    while let Some(request) = connection.accept().await {
        let Ok((request, mut respond)) = request else {
            return;
        };
        let host = request
            .uri()
            .authority()
            .map(|authority| authority.host().to_string())
            .or_else(|| {
                request
                    .headers()
                    .get("host")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let mut body = request.into_body();
        let mut query = Vec::new();
        while let Some(chunk) = body.data().await {
            let Ok(chunk) = chunk else {
                return;
            };
            let len = chunk.len();
            query.extend_from_slice(&chunk);
            let _ = body.flow_control().release_capacity(len);
        }
        let qtype = question_end_direct(&query)
            .map(|_| u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]))
            .unwrap_or(0);
        log_line(
            &mut log.lock().unwrap(),
            "req",
            &host,
            &format!("alpn=h2 type={qtype}"),
        );
        let response_body = build_dns_response(&mode, &host, &query);
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/dns-message")
            .header(http::header::CONTENT_LENGTH, response_body.len())
            .body(())
            .unwrap();
        let Ok(mut send) = respond.send_response(response, false) else {
            return;
        };
        let _ = send.send_data(bytes::Bytes::from(response_body), true);
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args[0].clone();
    let ca_path = args[1].clone();
    let port_path = args[2].clone();
    let log_path = args[3].clone();

    let mut ca_params = CertificateParams::new(Vec::new());
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "r2o TG14 test CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.use_authority_key_identifier_extension = true;
    let ca = rcgen::Certificate::from_params(ca_params).unwrap();
    std::fs::write(&ca_path, ca.serialize_pem().unwrap()).unwrap();

    let sans = HOSTS
        .iter()
        .map(|host| host.to_string())
        .collect::<Vec<_>>();
    let mut server_params = CertificateParams::new(sans);
    server_params
        .distinguished_name
        .push(DnType::CommonName, "r2o TG14 DoH");
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.use_authority_key_identifier_extension = true;
    let server = rcgen::Certificate::from_params(server_params).unwrap();
    let cert_der = CertificateDer::from(server.serialize_der_with_signer(&ca).unwrap());
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.serialize_private_key_der()));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let config = Arc::new(config);

    let listener = TcpListener::bind(("0.0.0.0", 443)).await.unwrap();
    std::fs::write(&port_path, "443").unwrap();
    let log = Arc::new(std::sync::Mutex::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap(),
    ));

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let config = Arc::clone(&config);
        let mode = mode.clone();
        let log = Arc::clone(&log);
        tokio::spawn(async move {
            let acceptor =
                tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
            let Ok(start) = acceptor.await else {
                return;
            };
            let Some(host) = start.client_hello().server_name().map(str::to_string) else {
                return;
            };
            let offered = start
                .client_hello()
                .alpn()
                .map(|protocols| {
                    protocols
                        .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            log_line(
                &mut log.lock().unwrap(),
                "sni",
                &host,
                &format!("offered_alpn={offered:?}"),
            );
            if mode == "first-down" && host == "d.webshiftvpn.ru" {
                // Разрыв до TLS: оба клиента должны перейти к следующему endpoint.
                return;
            }
            let Ok(tls) = start.into_stream(config).await else {
                return;
            };
            if tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()) {
                serve_h2(tls, mode, log).await;
            } else {
                serve_h1(tls, mode, host, log).await;
            }
        });
    }
}
