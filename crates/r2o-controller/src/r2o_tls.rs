use std::io::Write;

const R2O_TLS13_CLIENT_HELLO_MAX: usize = 4096;

/// d2o records the peer name separately and does not gate the TLS result on
/// certificate trust or handshake-signature verification.
#[derive(Debug)]
struct R2oD2oServerCertVerifier {
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
    verify_finished: bool,
}

impl rustls::client::danger::ServerCertVerifier for R2oD2oServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }

    fn requires_server_finished_verification(&self) -> bool {
        self.verify_finished
    }
}

/// Создать измерительное TLS-соединение с необязательной длиной ClientHello.
///
/// Для TCP `wire_len` включает пятибайтовый заголовок записи; для QUIC — нет.
pub fn r2o_tls_client_connection(
    name: &str,
    tls12: bool,
    wire_len: Option<usize>,
    _roots: rustls::RootCertStore,
) -> Result<rustls::ClientConnection, String> {
    // C `ch12_build` (`tls12.c`) не добавляет ALPN вовсе: TLS 1.2-сессия
    // донора — только ECDHE+AES128-GCM и SNI. TLS 1.3-путь по-прежнему
    // предлагает `http/1.1` (`d2k_tls_connect`).
    let alpn = if tls12 {
        Vec::new()
    } else {
        vec![b"http/1.1".to_vec()]
    };
    r2o_tls_client_connection_with_alpn(name, tls12, wire_len, _roots, &alpn)
}

/// Создать измерительное соединение с ALPN, снятым с клиентского приветствия.
pub fn r2o_tls_client_connection_with_alpn(
    name: &str,
    tls12: bool,
    wire_len: Option<usize>,
    _roots: rustls::RootCertStore,
    alpn_protocols: &[Vec<u8>],
) -> Result<rustls::ClientConnection, String> {
    let versions = if tls12 {
        &[&rustls::version::TLS12][..]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12][..]
    };
    let mut provider = rustls::crypto::ring::default_provider();
    let verifier = R2oD2oServerCertVerifier {
        algorithms: provider.signature_verification_algorithms.clone(),
        verify_finished: false,
    };
    provider.cipher_suites = if tls12 {
        vec![
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ]
    } else {
        vec![
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ]
    };
    provider.kx_groups = if tls12 {
        vec![
            rustls::crypto::ring::kx_group::X25519,
            rustls::crypto::ring::kx_group::SECP256R1,
            rustls::crypto::ring::kx_group::SECP384R1,
        ]
    } else {
        vec![
            rustls::crypto::ring::kx_group::X25519,
            rustls::crypto::ring::kx_group::SECP256R1,
        ]
    };
    let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_protocol_versions(versions)
        .map_err(|error| format!("не удалось настроить TLS-версии: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols.to_vec();
    config.r2o_client_hello_wire_len = wire_len;
    let server_name = rustls::pki_types::ServerName::try_from(name.to_owned())
        .map_err(|_| "имя цели недопустимо для TLS SNI".to_owned())?;
    rustls::ClientConnection::new(std::sync::Arc::new(config), server_name)
        .map_err(|error| format!("не удалось начать TLS-рукопожатие: {error}"))
}

/// Вернуть список клиента, если он отсутствует или не содержит HTTP поверх TLS.
/// `Some([])` означает ClientHello без ALPN; ошибочная форма и HTTP-протоколы
/// оставляют прежнюю HTTP-проверку.
/// C `d2k_alpn_is_http`: три HTTP-протокола в списке ALPN.
fn alpn_is_http(name: &[u8]) -> bool {
    matches!(name, b"http/1.1" | b"http/1.0" | b"h2")
}

pub fn r2o_tls_client_hello_non_http_alpn(client_hello: &[u8]) -> Option<Vec<Vec<u8>>> {
    if client_hello.len() < 9
        || client_hello[0] != 22
        || client_hello[1] != 3
        || client_hello[5] != 1
    {
        return None;
    }
    let record_length = usize::from(u16::from_be_bytes([client_hello[3], client_hello[4]]));
    let record_end = 5_usize.checked_add(record_length)?;
    if record_end != client_hello.len() {
        return None;
    }
    let handshake_length = (usize::from(client_hello[6]) << 16)
        | (usize::from(client_hello[7]) << 8)
        | usize::from(client_hello[8]);
    if handshake_length.checked_add(9)? != record_end {
        return None;
    }
    let end = record_end;
    let mut offset = 9_usize.checked_add(2 + 32)?;
    offset = r2o_tls_skip_vector(client_hello, offset, end, 1)?;
    offset = r2o_tls_skip_vector(client_hello, offset, end, 2)?;
    offset = r2o_tls_skip_vector(client_hello, offset, end, 1)?;
    if offset == end {
        // C `d2k_hello_alpn`: расширений нет вовсе — rc 0, клиент без ALPN.
        return Some(Vec::new());
    }
    let (extensions_length, extensions_start) = r2o_tls_u16(client_hello, offset, end)?;
    let extensions_end = extensions_start.checked_add(extensions_length)?;
    if extensions_end > end {
        return None;
    }
    let mut extension = extensions_start;
    let mut alpn = None;
    while extension < extensions_end {
        let (kind, value) = r2o_tls_u16(client_hello, extension, extensions_end)?;
        let (length, data) = r2o_tls_u16(client_hello, value, extensions_end)?;
        let extension_end = data.checked_add(length)?;
        if extension_end > extensions_end {
            return None;
        }
        if kind == 0x0010 {
            let (list_length, mut protocol) = r2o_tls_u16(client_hello, data, extension_end)?;
            let list_end = protocol.checked_add(list_length)?;
            if list_end != extension_end {
                return None;
            }
            let mut protocols = Vec::new();
            while protocol < list_end {
                let length = usize::from(*client_hello.get(protocol)?);
                protocol += 1;
                if length == 0 {
                    return None;
                }
                let protocol_end = protocol.checked_add(length)?;
                if protocol_end > list_end {
                    return None;
                }
                let name = &client_hello[protocol..protocol_end];
                if alpn_is_http(name) {
                    return None;
                }
                protocols.push(name.to_vec());
                protocol = protocol_end;
            }
            if protocols.is_empty() {
                return None;
            }
            alpn = Some(protocols);
        }
        extension = extension_end;
    }
    Some(alpn.unwrap_or_default())
}

/// Повторить сохранённый ClientHello и применить донорский критерий ServerHello.
pub fn r2o_tls_replay_client_hello(
    stream: &mut std::net::TcpStream,
    client_hello: &[u8],
    timeout: std::time::Duration,
) -> std::io::Result<bool> {
    use std::io::Write;

    if client_hello.len() < 6 {
        return Ok(false);
    }
    let timeout = if timeout.is_zero() {
        std::time::Duration::from_secs(3)
    } else {
        timeout
    };
    stream.set_write_timeout(Some(timeout))?;
    if stream.write_all(client_hello).is_err() {
        return Ok(false);
    }
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "timeout overflow"))?;
    // C `d2k_verify_replay_on` (`core/verify.c:1530-1549`): ServerHello
    // узнаётся по шести байтам записи (`22 03 03 00 01 02`), а не разбором
    // TLS1.3-расширений. Закрытого ключа клиента нет, поэтому глубже
    // доказательство и не идёт.
    use std::io::Read;

    let mut buf = [0_u8; 16];
    let mut have = 0;
    while have < 7 && !(have >= 6 && buf[0] == 22) {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut buf[have..]) {
            Ok(0) => break,
            Ok(length) => have += length,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                break;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(have >= 6 && buf[0] == 22 && buf[1] == 3 && buf[5] == 2)
}

fn r2o_tls_be16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset.checked_add(1)?)?,
    ]))
}

/// C `d2k_t13_sh_version`: версия ServerHello из supported_versions.
fn r2o_t13_sh_version(server_hello: &[u8]) -> u16 {
    let mut cursor = 4 + 2 + 32;
    let Some(&session_len) = server_hello.get(cursor) else {
        return 0;
    };
    let legacy = r2o_tls_be16(server_hello, 4).unwrap_or(0);
    cursor += 1 + usize::from(session_len);
    if cursor + 3 > server_hello.len() {
        return 0;
    }
    cursor += 3;
    if cursor + 2 > server_hello.len() {
        return legacy;
    }
    let Some(extensions_len) = r2o_tls_be16(server_hello, cursor) else {
        return legacy;
    };
    let extensions_end = cursor
        .checked_add(2 + usize::from(extensions_len))
        .unwrap_or(server_hello.len())
        .min(server_hello.len());
    cursor += 2;
    while cursor + 4 <= extensions_end {
        let Some(kind) = r2o_tls_be16(server_hello, cursor) else {
            break;
        };
        let Some(length) = r2o_tls_be16(server_hello, cursor + 2) else {
            break;
        };
        cursor += 4;
        if cursor + usize::from(length) > extensions_end {
            break;
        }
        if kind == 0x002b && length == 2 {
            return r2o_tls_be16(server_hello, cursor).unwrap_or(legacy);
        }
        cursor += usize::from(length);
    }
    legacy
}

/// C `d2k_t13_sh_parse`: cipher 0x1301 и X25519 key_share.
fn r2o_t13_sh_parse(server_hello: &[u8]) -> Result<[u8; 32], String> {
    if server_hello.len() < 4 {
        return Err("ServerHello обрезан".into());
    }
    let mut cursor = 4 + 2 + 32;
    let Some(&session_len) = server_hello.get(cursor) else {
        return Err("ServerHello обрезан".into());
    };
    cursor += 1 + usize::from(session_len);
    if cursor + 3 > server_hello.len() {
        return Err("ServerHello обрезан".into());
    }
    let suite = r2o_tls_be16(server_hello, cursor).unwrap_or(0);
    cursor += 3;
    if suite != 0x1301 {
        return Err(format!(
            "сервер выбрал шифр 0x{suite:04x}, а поддержан только 0x1301"
        ));
    }
    if cursor + 2 > server_hello.len() {
        return Err("ServerHello без расширений".into());
    }
    let extensions_len = r2o_tls_be16(server_hello, cursor).unwrap_or(0);
    cursor += 2;
    let extensions_end = cursor
        .checked_add(usize::from(extensions_len))
        .unwrap_or(server_hello.len())
        .min(server_hello.len());
    while cursor + 4 <= extensions_end {
        let Some(kind) = r2o_tls_be16(server_hello, cursor) else {
            break;
        };
        let Some(length) = r2o_tls_be16(server_hello, cursor + 2) else {
            break;
        };
        cursor += 4;
        if cursor + usize::from(length) > extensions_end {
            break;
        }
        if kind == 0x0033
            && length >= 36
            && r2o_tls_be16(server_hello, cursor) == Some(0x001d)
            && r2o_tls_be16(server_hello, cursor + 2) == Some(32)
        {
            let key = server_hello
                .get(cursor + 4..cursor + 36)
                .ok_or_else(|| "ServerHello обрезан".to_owned())?;
            return key.try_into().map_err(|_| "ServerHello обрезан".to_owned());
        }
        cursor += usize::from(length);
    }
    Err("сервер не прислал ключ X25519 — TLS 1.3 не согласован".into())
}

/// C `d2k_t13_flight_next`: следующее handshake-сообщение флайта.
fn r2o_t13_flight_next<'a>(buffer: &'a [u8], offset: &mut usize) -> Option<(u8, &'a [u8])> {
    let start = *offset;
    let header = buffer.get(start..start.checked_add(4)?)?;
    let length =
        (usize::from(header[1]) << 16) | (usize::from(header[2]) << 8) | usize::from(header[3]);
    let body_start = start.checked_add(4)?;
    let end = body_start.checked_add(length)?;
    let body = buffer.get(body_start..end)?;
    *offset = end;
    Some((header[0], body))
}

pub(crate) fn r2o_hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut block_key = [0_u8; 64];
    if key.len() > block_key.len() {
        block_key[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0_u8; 64];
    let mut opad = [0_u8; 64];
    for index in 0..64 {
        ipad[index] = block_key[index] ^ 0x36;
        opad[index] = block_key[index] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn r2o_hkdf_expand_label(
    secret: &[u8; 32],
    label: &str,
    context: &[u8],
    out_len: usize,
) -> Option<Vec<u8>> {
    if out_len == 0 || out_len > 255 * 32 || context.len() > 32 {
        return None;
    }
    let full_label = format!("tls13 {label}");
    if full_label.len() > 255 {
        return None;
    }
    let mut info = Vec::with_capacity(4 + full_label.len() + context.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let mut output = Vec::with_capacity(out_len);
    let mut previous = Vec::new();
    let mut counter = 1_u8;
    while output.len() < out_len {
        let mut message = info.clone();
        message.extend_from_slice(&previous);
        message.push(counter);
        let block = r2o_hmac_sha256(secret, &message);
        output.extend_from_slice(&block);
        previous = block.to_vec();
        counter = counter.wrapping_add(1);
    }
    output.truncate(out_len);
    Some(output)
}

/// C `d2k_t13_derive_secret`: Derive-Secret с Transcript-Hash.
pub fn r2o_t13_derive_secret(secret: &[u8; 32], label: &str, messages: &[u8]) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};

    let transcript_hash = Sha256::digest(messages);
    r2o_hkdf_expand_label(secret, label, &transcript_hash, 32)?
        .try_into()
        .ok()
}

/// C `d2k_t13_schedule_hs`: early→handshake secret, c/s hs traffic.
pub fn r2o_t13_schedule_hs(
    shared: &[u8; 32],
    transcript: &[u8],
) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
    let zero = [0_u8; 32];
    let early = r2o_hmac_sha256(&zero, &zero);
    let derived = r2o_t13_derive_secret(&early, "derived", &[])?;
    let handshake = r2o_hmac_sha256(&derived, shared);
    let client = r2o_t13_derive_secret(&handshake, "c hs traffic", transcript)?;
    let server = r2o_t13_derive_secret(&handshake, "s hs traffic", transcript)?;
    Some((client, server, handshake))
}

/// C `d2k_t13_schedule_ap`: master secret, c/s ap traffic.
pub fn r2o_t13_schedule_ap(
    handshake: &[u8; 32],
    transcript: &[u8],
) -> Option<([u8; 32], [u8; 32])> {
    let zero = [0_u8; 32];
    let derived = r2o_t13_derive_secret(handshake, "derived", &[])?;
    let master = r2o_hmac_sha256(&derived, &zero);
    let client = r2o_t13_derive_secret(&master, "c ap traffic", transcript)?;
    let server = r2o_t13_derive_secret(&master, "s ap traffic", transcript)?;
    Some((client, server))
}

/// C `d2k_t13_finished_mac`: Finished MAC над Transcript-Hash.
pub fn r2o_t13_finished_mac(secret: &[u8; 32], transcript: &[u8]) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};

    let finished_key = r2o_hkdf_expand_label(secret, "finished", &[], 32)?;
    let finished_key: [u8; 32] = finished_key.try_into().ok()?;
    let transcript_hash = Sha256::digest(transcript);
    Some(r2o_hmac_sha256(&finished_key, &transcript_hash))
}

fn r2o_tls_u16(bytes: &[u8], offset: usize, end: usize) -> Option<(usize, usize)> {
    let field_end = offset.checked_add(2)?;
    if field_end > end {
        return None;
    }
    Some((
        usize::from(u16::from_be_bytes([bytes[offset], bytes[offset + 1]])),
        field_end,
    ))
}

fn r2o_tls_skip_vector(bytes: &[u8], offset: usize, end: usize, prefix: usize) -> Option<usize> {
    let (length, data) = match prefix {
        1 => (usize::from(*bytes.get(offset)?), offset.checked_add(1)?),
        2 => r2o_tls_u16(bytes, offset, end)?,
        _ => return None,
    };
    let vector_end = data.checked_add(length)?;
    (vector_end <= end).then_some(vector_end)
}

/// Создать TLS 1.3 измерительное соединение с ECH по правилам d2o.
pub fn r2o_tls_ech_client_connection(
    name: &str,
    _roots: rustls::RootCertStore,
    ech: rustls::client::EchConfig,
    wire_len: Option<usize>,
) -> Result<rustls::ClientConnection, String> {
    let mut provider = rustls::crypto::ring::default_provider();
    let verifier = R2oD2oServerCertVerifier {
        algorithms: provider.signature_verification_algorithms.clone(),
        verify_finished: true,
    };
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = vec![
        rustls::crypto::ring::kx_group::X25519,
        rustls::crypto::ring::kx_group::SECP256R1,
    ];
    let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_ech(rustls::client::EchMode::Enable(ech))
        .map_err(|error| format!("не удалось включить ECH: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.r2o_client_hello_wire_len = wire_len;
    let server_name = rustls::pki_types::ServerName::try_from(name.to_owned())
        .map_err(|_| "имя цели недопустимо для внутреннего TLS SNI".to_owned())?;
    rustls::ClientConnection::new(std::sync::Arc::new(config), server_name)
        .map_err(|error| format!("не удалось начать ECH-рукопожатие: {error}"))
}

/// Собрать зашифрованный ClientHello, чтобы классификатор проверял ту же форму.
pub fn r2o_tls_ech_client_hello(
    name: &str,
    ech: rustls::client::EchConfig,
) -> Result<Vec<u8>, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut connection = r2o_tls_ech_client_connection(name, roots, ech, None)?;
    let mut hello = Vec::with_capacity(2048);
    connection
        .write_tls(&mut hello)
        .map_err(|error| format!("не удалось собрать ECH ClientHello: {error}"))?;
    if hello.len() < 6 || hello[0] != 22 || hello[5] != 1 {
        return Err("Rustls не собрал полный TLS ClientHello с ECH".into());
    }
    Ok(hello)
}

/// Параметры сборки клиентского приветствия TLS 1.3.
pub struct R2oTls13ClientHelloOptions<'a> {
    pub server_name: Option<&'a str>,
    pub public_key: &'a [u8; 32],
    pub random: &'a [u8; 32],
    pub session_id_len: usize,
    pub offer_tls12: bool,
    pub alpn: Option<&'a str>,
    pub alpn_wire: Option<&'a [u8]>,
    pub extra_extensions: &'a [u8],
    pub pad_to: usize,
}

/// Собрать сообщение ClientHello с согласованной формой и длиной.
///
/// `pad_to` задаёт длину сообщения рукопожатия без пятибайтового заголовка
/// TLS-записи. Если до цели меньше места для заголовка расширения padding,
/// сообщение остаётся естественной длины.
pub fn r2o_tls13_client_hello(
    options: &R2oTls13ClientHelloOptions<'_>,
) -> Result<Vec<u8>, &'static str> {
    if options.session_id_len > 32 {
        return Err("длина TLS session ID превышает 32 байта");
    }
    if options.pad_to > R2O_TLS13_CLIENT_HELLO_MAX {
        return Err("запрошенная длина ClientHello превышает 4096 байт");
    }
    if options.extra_extensions.len() > R2O_TLS13_CLIENT_HELLO_MAX {
        return Err("дополнительные TLS-расширения превышают 4096 байт");
    }
    if options
        .server_name
        .is_some_and(|name| name.as_bytes().contains(&0))
    {
        return Err("имя SNI содержит нулевой байт");
    }

    let mut hello = Vec::with_capacity(R2O_TLS13_CLIENT_HELLO_MAX);
    hello.extend_from_slice(&[1, 0, 0, 0]);
    hello.extend_from_slice(&0x0303_u16.to_be_bytes());
    hello.extend_from_slice(options.random);
    hello.push(options.session_id_len as u8);
    hello.extend_from_slice(&options.random[..options.session_id_len]);

    if options.offer_tls12 {
        push_u16(&mut hello, 6);
        push_u16(&mut hello, 0x1301);
        push_u16(&mut hello, 0xc02b);
        push_u16(&mut hello, 0xc02f);
    } else {
        push_u16(&mut hello, 2);
        push_u16(&mut hello, 0x1301);
    }
    hello.extend_from_slice(&[1, 0]);

    let extensions_length_offset = hello.len();
    push_u16(&mut hello, 0);
    let extensions_start = hello.len();

    if let Some(name) = options
        .server_name
        .filter(|name| !name.is_empty() && name.len() < 256)
    {
        let mut value = Vec::with_capacity(name.len() + 5);
        push_u16(&mut value, (name.len() + 3) as u16);
        value.push(0);
        push_u16(&mut value, name.len() as u16);
        value.extend_from_slice(name.as_bytes());
        push_extension(&mut hello, 0x0000, &value)?;
    }

    push_extension(&mut hello, 0x000b, &[1, 0])?;
    if options.offer_tls12 {
        push_extension(&mut hello, 0x000a, &[0, 4, 0, 0x1d, 0, 0x17])?;
    } else {
        push_extension(&mut hello, 0x000a, &[0, 2, 0, 0x1d])?;
    }
    push_extension(
        &mut hello,
        0x000d,
        &[0, 18, 4, 3, 5, 3, 6, 3, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1],
    )?;
    if options.offer_tls12 {
        push_extension(&mut hello, 0x002b, &[4, 3, 4, 3, 3])?;
    } else {
        push_extension(&mut hello, 0x002b, &[2, 3, 4])?;
    }

    if let Some(protocols) = options.alpn_wire.filter(|protocols| !protocols.is_empty()) {
        if protocols.len() > 256 {
            return Err("список ALPN превышает 256 байт");
        }
        let mut value = Vec::with_capacity(protocols.len() + 2);
        push_u16(&mut value, protocols.len() as u16);
        value.extend_from_slice(protocols);
        push_extension(&mut hello, 0x0010, &value)?;
    } else if let Some(protocol) = options.alpn.filter(|protocol| !protocol.is_empty()) {
        if protocol.len() > 255 {
            return Err("имя ALPN превышает 255 байт");
        }
        let mut value = Vec::with_capacity(protocol.len() + 3);
        push_u16(&mut value, (protocol.len() + 1) as u16);
        value.push(protocol.len() as u8);
        value.extend_from_slice(protocol.as_bytes());
        push_extension(&mut hello, 0x0010, &value)?;
    }

    push_extension(&mut hello, 0x002d, &[1, 1])?;
    if hello
        .len()
        .checked_add(options.extra_extensions.len())
        .and_then(|length| length.checked_add(42))
        .is_none_or(|length| length > R2O_TLS13_CLIENT_HELLO_MAX)
    {
        return Err("ClientHello с дополнительными расширениями превышает 4096 байт");
    }
    hello.extend_from_slice(options.extra_extensions);

    let mut key_share = Vec::with_capacity(38);
    push_u16(&mut key_share, 36);
    push_u16(&mut key_share, 0x001d);
    push_u16(&mut key_share, 32);
    key_share.extend_from_slice(options.public_key);
    push_extension(&mut hello, 0x0033, &key_share)?;

    if options.pad_to > hello.len() + 4 {
        let padding_length = options.pad_to - hello.len() - 4;
        if padding_length <= usize::from(u16::MAX) {
            let padding_length = padding_length as u16;
            push_u16(&mut hello, 0x0015);
            push_u16(&mut hello, padding_length);
            hello.resize(hello.len() + usize::from(padding_length), 0);
        }
    }

    let extensions_length = hello.len() - extensions_start;
    let extensions_length =
        u16::try_from(extensions_length).map_err(|_| "блок TLS-расширений превышает 65535 байт")?;
    hello[extensions_length_offset..extensions_length_offset + 2]
        .copy_from_slice(&extensions_length.to_be_bytes());

    let body_length = hello.len() - 4;
    let body_length = u32::try_from(body_length)
        .ok()
        .filter(|length| *length <= 0x00ff_ffff)
        .ok_or("тело ClientHello превышает 24-битную длину")?;
    hello[1] = (body_length >> 16) as u8;
    hello[2] = (body_length >> 8) as u8;
    hello[3] = body_length as u8;

    if hello.len() > R2O_TLS13_CLIENT_HELLO_MAX {
        return Err("ClientHello превышает 4096 байт");
    }
    Ok(hello)
}

fn push_extension(output: &mut Vec<u8>, kind: u16, value: &[u8]) -> Result<(), &'static str> {
    let length = u16::try_from(value.len()).map_err(|_| "TLS-расширение превышает 65535 байт")?;
    push_u16(output, kind);
    push_u16(output, length);
    output.extend_from_slice(value);
    Ok(())
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

// --- TLS 1.2 client (C `tls12.c`) -----------------------------------------

const TLS12_REC_MAX: usize = 18_432;
const TLS12_TR_MAX: usize = TLS12_REC_MAX * 4;
const TLS12_HS_PSEUDO_CCS: u8 = 0xfe;

/// C `ch12_build` (`core/tls12.c:415-485`): старая форма ClientHello без
/// `supported_versions` и ALPN, с двумя шифрнаборами, группами
/// X25519/P-256/P-384, форматами точек и четырьмя sigalg. `want_wire` — полная
/// длина записи; набивка доводит её до этой длины, как padding extension 21.
pub fn r2o_tls12_client_hello(
    sni: Option<&str>,
    random: &[u8; 32],
    want_wire: usize,
) -> Result<Vec<u8>, String> {
    let sni = sni.unwrap_or("");
    let sni_len = if sni.is_empty() { 0 } else { sni.len() };
    if sni_len >= 256 {
        // C добавляет SNI только при `0 < len < 256`, остальное — без SNI.
    }
    let sni_bytes = if (1..256).contains(&sni_len) {
        &sni.as_bytes()[..sni_len]
    } else {
        &[][..]
    };
    if sni_bytes.len() > 255 {
        return Err("SNI длиннее 255 байт".into());
    }

    let mut out = Vec::with_capacity(512 + sni_bytes.len());
    out.extend_from_slice(&[0x16, 0x03, 0x03, 0, 0]); // record header
    out.extend_from_slice(&[0x01, 0, 0, 0]); // handshake header
    let body_start = out.len();
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(random);
    out.push(0); // session_id пуст
    out.extend_from_slice(&4_u16.to_be_bytes());
    out.extend_from_slice(&0xc02b_u16.to_be_bytes()); // ECDHE_ECDSA_AES128_GCM_SHA256
    out.extend_from_slice(&0xc02f_u16.to_be_bytes()); // ECDHE_RSA_AES128_GCM_SHA256
    out.extend_from_slice(&[1, 0]); // compression: null

    let extensions_length_offset = out.len();
    out.extend_from_slice(&0_u16.to_be_bytes());
    let extensions_start = out.len();

    if !sni_bytes.is_empty() {
        push_u16(&mut out, 0);
        push_u16(&mut out, (sni_bytes.len() + 5) as u16);
        push_u16(&mut out, (sni_bytes.len() + 3) as u16);
        out.push(0);
        push_u16(&mut out, sni_bytes.len() as u16);
        out.extend_from_slice(sni_bytes);
    }

    push_u16(&mut out, 10);
    push_u16(&mut out, 8);
    push_u16(&mut out, 6);
    push_u16(&mut out, 0x001d);
    push_u16(&mut out, 0x0017);
    push_u16(&mut out, 0x0018);

    push_u16(&mut out, 11);
    push_u16(&mut out, 2);
    out.extend_from_slice(&[1, 0]);

    push_u16(&mut out, 13);
    push_u16(&mut out, 10);
    push_u16(&mut out, 8);
    for algorithm in [0x0403_u16, 0x0804, 0x0401, 0x0203] {
        push_u16(&mut out, algorithm);
    }

    if want_wire > 0 {
        let now = out.len() + 2; // + длина расширений
        if want_wire > now + 4 && want_wire - now - 4 < 65_535 {
            let pad = want_wire - now - 4;
            if out.len() + 4 + pad + 16 <= 512 + sni_bytes.len() + 65_519 {
                push_u16(&mut out, 21);
                push_u16(&mut out, pad as u16);
                out.resize(out.len() + pad, 0);
            }
        }
    }

    let extensions_len = out.len() - extensions_start;
    out[extensions_length_offset..extensions_length_offset + 2]
        .copy_from_slice(&(extensions_len as u16).to_be_bytes());
    let body_len = out.len() - body_start;
    out[5] = 0x01; // ClientHello
    out[6..9].copy_from_slice(&(body_len as u32).to_be_bytes()[1..]);
    out[3..5].copy_from_slice(&((4 + body_len) as u16).to_be_bytes());
    Ok(out)
}

/// C `tls12_finish` + сессия `d2k_tls12`: продолжение после сохранённого
/// ServerHello/флайта. В production TLS1.2 ведёт rustls; этот API повторяет
/// донорский контракт для downgrade-проверок и C/Rust differential.
pub struct R2oTls12Session {
    app: crate::tls12::Tls12AppReader,
    writer: crate::tls12::Tls12RecordWriter,
    peer_name: Option<bool>,
    client_random: [u8; 32],
    server_random: [u8; 32],
}

impl R2oTls12Session {
    pub fn peer_name(&self) -> Option<bool> {
        self.peer_name
    }

    pub fn client_random(&self) -> [u8; 32] {
        self.client_random
    }

    pub fn server_random(&self) -> [u8; 32] {
        self.server_random
    }

    pub fn read(
        &mut self,
        stream: &mut impl std::io::Read,
        buffer: &mut [u8],
    ) -> Result<usize, String> {
        self.app.read(stream, buffer)
    }

    pub fn write(&mut self, stream: &mut impl std::io::Write, data: &[u8]) -> Result<(), String> {
        crate::tls12::tls12_write(stream, &mut self.writer, data)
    }
}

fn tls12_default_timeout(timeout: std::time::Duration) -> std::time::Duration {
    if timeout.is_zero() {
        std::time::Duration::from_millis(5000)
    } else {
        timeout
    }
}

fn tls12_remaining(deadline: std::time::Instant) -> Result<std::time::Duration, String> {
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    if left.is_zero() {
        Err("не дождались TLS1.2-рукопожатия за отведённое время".into())
    } else {
        Ok(left)
    }
}

fn tls12_set_deadline(
    stream: &std::net::TcpStream,
    deadline: std::time::Instant,
) -> Result<(), String> {
    let left = tls12_remaining(deadline)?;
    stream
        .set_read_timeout(Some(left))
        .and_then(|()| stream.set_write_timeout(Some(left)))
        .map_err(|error| format!("TLS1.2 timeout: {error}"))
}

fn tls12_read_message(
    reader: &mut crate::tls12::Tls12RecordReader,
    stream: &mut std::net::TcpStream,
    hs: &mut Vec<u8>,
    offset: &mut usize,
    deadline: std::time::Instant,
) -> Result<(u8, Vec<u8>), String> {
    loop {
        if hs.len().saturating_sub(*offset) >= 4 {
            let length = (usize::from(hs[*offset + 1]) << 16)
                | (usize::from(hs[*offset + 2]) << 8)
                | usize::from(hs[*offset + 3]);
            if hs.len().saturating_sub(*offset) >= 4 + length {
                let start = *offset;
                *offset += 4 + length;
                return Ok((hs[start], hs[start..start + 4 + length].to_vec()));
            }
        }
        tls12_set_deadline(stream, deadline)?;
        let mut payload = Vec::new();
        let (content_type, length) = reader.read_record(stream, &mut payload, TLS12_REC_MAX)?;
        match content_type {
            21 => {
                let level = payload.first().copied().unwrap_or(0);
                let description = payload.get(1).copied().unwrap_or(0);
                return Err(format!(
                    "сервер прислал тревогу {description} уровня {level}"
                ));
            }
            20 => return Ok((TLS12_HS_PSEUDO_CCS, Vec::new())),
            22 => {}
            other => return Err(format!("запись типа {other} посреди рукопожатия")),
        }
        if payload.len() != length {
            return Err("TLS1.2: неверная длина handshake-записи".into());
        }
        if *offset > 0 {
            hs.drain(..*offset);
            *offset = 0;
        }
        if hs.len() + payload.len() > TLS12_TR_MAX {
            return Err("рукопожатие длиннее предела".into());
        }
        hs.extend_from_slice(&payload);
    }
}

fn tls12_expand_shared(shared: &[u8]) -> Result<[u8; 32], String> {
    if shared.len() > 32 {
        return Err(format!("ECDHE-секрет длиной {} вместо 32", shared.len()));
    }
    let mut out = [0_u8; 32];
    out[32 - shared.len()..].copy_from_slice(shared);
    Ok(out)
}

fn tls12_finish(
    stream: &mut std::net::TcpStream,
    sni: &str,
    deadline: std::time::Instant,
    c_random: [u8; 32],
    transcript: &mut crate::tls12::Tls12Transcript,
    hs: &mut Vec<u8>,
) -> Result<R2oTls12Session, String> {
    let mut reader = crate::tls12::Tls12RecordReader::new([0; 4], [0; 16], 0, false);
    let mut offset = 0_usize;
    let mut s_random = [0_u8; 32];
    let mut suite = 0_u16;
    let mut peer_pub: Option<Vec<u8>> = None;
    let mut group = 0_u16;
    let mut peer_name = None;

    loop {
        let (kind, msg) = tls12_read_message(&mut reader, stream, hs, &mut offset, deadline)?;
        if kind == TLS12_HS_PSEUDO_CCS {
            return Err("смена шифра раньше ServerHelloDone".into());
        }
        if msg.len() < 4 {
            return Err("рукопожатие TLS1.2 обрезано".into());
        }
        transcript.add(&msg);
        let body = &msg[4..];
        match kind {
            2 => {
                if body.len() < 2 + 32 + 1 {
                    return Err("ServerHello обрезан".into());
                }
                s_random.copy_from_slice(&body[2..34]);
                let session_len = usize::from(body[34]);
                let cursor = 34 + 1 + session_len;
                if cursor + 2 > body.len() {
                    return Err("ServerHello обрезан на шифре".into());
                }
                suite = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
                if !matches!(suite, 0xc02b | 0xc02f) {
                    return Err(format!(
                        "сервер выбрал шифрнабор 0x{suite:04x} — зонд умеет только ECDHE+AES128-GCM-SHA256"
                    ));
                }
            }
            11 => {
                if !sni.is_empty() {
                    peer_name = crate::response::https_certificate_name_matches(body, sni);
                }
            }
            12 => {
                if body.len() < 4 {
                    return Err("ServerKeyExchange обрезан".into());
                }
                if body[0] != 3 {
                    return Err(format!(
                        "сервер предложил не именованную кривую ({})",
                        body[0]
                    ));
                }
                group = u16::from_be_bytes([body[1], body[2]]);
                let want = match group {
                    0x001d => 32,
                    0x0017 => 65,
                    _ => 0,
                };
                if want == 0 {
                    return Err(format!(
                        "сервер выбрал группу 0x{group:04x} — зонд умеет X25519 и secp256r1"
                    ));
                }
                if body[3] as usize != want || body.len() < 4 + want {
                    return Err(format!(
                        "открытый ключ сервера длиной {} вместо {want}",
                        body[3]
                    ));
                }
                peer_pub = Some(body[4..4 + want].to_vec());
            }
            13 => {
                return Err("сервер требует клиентский сертификат — зонду его негде взять".into());
            }
            14 => break,
            _ => {}
        }
    }

    let peer_pub = peer_pub.ok_or_else(|| "флайт сервера неполон".to_owned())?;
    if suite == 0 {
        return Err("флайт сервера неполон".into());
    }

    let kx: &'static dyn rustls::crypto::SupportedKxGroup = match group {
        0x001d => rustls::crypto::ring::kx_group::X25519,
        0x0017 => rustls::crypto::ring::kx_group::SECP256R1,
        _ => return Err("неподдерживаемая группа TLS1.2".into()),
    };
    let active = kx
        .start()
        .map_err(|error| format!("ECDHE не начался: {error}"))?;
    let our_pub = active.pub_key().to_vec();
    let shared = active
        .complete(&peer_pub)
        .map_err(|error| format!("ECDHE не сошёлся: {error}"))?;
    let shared = tls12_expand_shared(shared.secret_bytes())?;

    let mut seed = [0_u8; 64];
    seed[..32].copy_from_slice(&c_random);
    seed[32..].copy_from_slice(&s_random);
    let master = crate::tls12::d2k_tls12_prf_for_test(&shared, "master secret", &seed, 48);
    seed[..32].copy_from_slice(&s_random);
    seed[32..].copy_from_slice(&c_random);
    let key_block = crate::tls12::d2k_tls12_prf_for_test(&master, "key expansion", &seed, 40);
    let c_key: [u8; 16] = key_block[..16].try_into().expect("fixed key length");
    let s_key: [u8; 16] = key_block[16..32].try_into().expect("fixed key length");
    let c_salt: [u8; 4] = key_block[32..36].try_into().expect("fixed salt length");
    let s_salt: [u8; 4] = key_block[36..40].try_into().expect("fixed salt length");

    let mut cke = Vec::with_capacity(4 + 1 + our_pub.len());
    cke.extend_from_slice(&[16, 0, 0, (1 + our_pub.len()) as u8]);
    cke.push(our_pub.len() as u8);
    cke.extend_from_slice(&our_pub);
    tls12_send_plain(stream, 22, &cke)?;
    transcript.add(&cke);

    tls12_send_plain(stream, 20, &[1])?;
    let hash = {
        use sha2::Digest;
        sha2::Sha256::digest(transcript.as_slice())
    };
    let verify = crate::tls12::d2k_tls12_prf_for_test(&master, "client finished", &hash, 12);
    let mut finished = vec![20, 0, 0, 12];
    finished.extend_from_slice(&verify);
    let mut writer = crate::tls12::Tls12RecordWriter::new(c_salt, c_key, 0);
    let wire = writer.seal(22, &finished)?;
    stream
        .write_all(&wire)
        .map_err(|error| format!("запись Finished не ушла: {error}"))?;
    transcript.add(&finished);

    let mut server_reader = crate::tls12::Tls12RecordReader::new(s_salt, s_key, 0, true);
    let mut shs = Vec::new();
    let mut shs_offset = 0_usize;
    let mut seen_ccs = false;
    loop {
        tls12_set_deadline(stream, deadline)?;
        let (kind, msg) = tls12_read_message(
            &mut server_reader,
            stream,
            &mut shs,
            &mut shs_offset,
            deadline,
        )?;
        if kind == TLS12_HS_PSEUDO_CCS {
            seen_ccs = true;
            shs.clear();
            shs_offset = 0;
            continue;
        }
        if kind == 4 {
            continue;
        }
        if kind == 20 {
            if msg.len() != 16 {
                return Err(format!("Finished сервера длиной {} вместо 16", msg.len()));
            }
            break;
        }
        if !seen_ccs {
            return Err("сервер прислал сообщение до CCS".into());
        }
    }

    Ok(R2oTls12Session {
        app: crate::tls12::Tls12AppReader::new(server_reader),
        writer,
        peer_name,
        client_random: c_random,
        server_random: s_random,
    })
}

fn tls12_send_plain(
    stream: &mut std::net::TcpStream,
    content_type: u8,
    body: &[u8],
) -> Result<(), String> {
    if body.len() > TLS12_REC_MAX {
        return Err("запись TLS1.2 длиннее предела".into());
    }
    let mut wire = Vec::with_capacity(5 + body.len());
    wire.push(content_type);
    wire.extend_from_slice(&[3, 3]);
    wire.extend_from_slice(&(body.len() as u16).to_be_bytes());
    wire.extend_from_slice(body);
    stream
        .write_all(&wire)
        .map_err(|error| format!("TLS1.2-запись не ушла: {error}"))
}

/// C `d2k_tls12_connect`: собрать ch12, отправить и довести рукопожатие.
pub fn r2o_tls12_connect(
    stream: &mut std::net::TcpStream,
    sni: &str,
    timeout: std::time::Duration,
    want_wire: usize,
) -> Result<R2oTls12Session, String> {
    let timeout = tls12_default_timeout(timeout);
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "TLS1.2 timeout слишком велик".to_owned())?;
    tls12_set_deadline(stream, deadline)?;
    let mut random = [0_u8; 32];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut random)
        .map_err(|error| format!("нет случайных байт: {error:?}"))?;
    let hello = r2o_tls12_client_hello(Some(sni), &random, want_wire)?;
    stream
        .write_all(&hello)
        .map_err(|error| format!("ClientHello не ушёл: {error}"))?;
    let mut transcript = crate::tls12::Tls12Transcript::new(TLS12_TR_MAX);
    transcript.add(&hello[5..]);
    let mut hs = Vec::new();
    tls12_finish(stream, sni, deadline, random, &mut transcript, &mut hs)
}

/// C `d2k_tls12_resume`: продолжить рукопожатие по уже прочитанному флайту
/// сервера после TLS1.3 ClientHello, на который сервер ответил TLS1.2.
pub fn r2o_tls12_resume(
    stream: &mut std::net::TcpStream,
    sni: &str,
    timeout: std::time::Duration,
    c_random: [u8; 32],
    ch_msg: &[u8],
    srv: &[u8],
) -> Result<R2oTls12Session, String> {
    if ch_msg.len() > TLS12_TR_MAX || srv.len() > TLS12_TR_MAX {
        return Err("рукопожатие длиннее предела".into());
    }
    let timeout = tls12_default_timeout(timeout);
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "TLS1.2 timeout слишком велик".to_owned())?;
    tls12_set_deadline(stream, deadline)?;
    let mut transcript = crate::tls12::Tls12Transcript::new(TLS12_TR_MAX);
    transcript.add(ch_msg);
    let mut hs = srv.to_vec();
    tls12_finish(stream, sni, deadline, c_random, &mut transcript, &mut hs)
}

#[cfg(test)]
mod tls12_client_tests {
    use super::{
        R2oTls13ClientHelloOptions, r2o_tls12_client_hello, r2o_tls12_connect, r2o_tls12_resume,
        r2o_tls13_client_hello,
    };
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    fn server_config() -> (ServerConfig, CertificateDer<'static>) {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("сертификат localhost");
        let certificate_der = CertificateDer::from(certificate.serialize_der().unwrap());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.serialize_private_key_der(),
        ));
        let config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der.clone()], private_key)
            .unwrap();
        (config, certificate_der)
    }

    fn serve(config: ServerConfig, listener: TcpListener, expected_request: &'static [u8]) {
        let (socket, _) = listener.accept().expect("принять TLS1.2-соединение");
        let connection = ServerConnection::new(Arc::new(config)).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).expect("прочитать запрос");
            request.push(byte[0]);
        }
        assert!(request.starts_with(expected_request), "request={request:?}");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .unwrap();
        stream.flush().unwrap();
    }

    fn read_http_ok(session: &mut super::R2oTls12Session, stream: &mut TcpStream) -> Vec<u8> {
        let mut response = Vec::new();
        let mut buffer = [0_u8; 256];
        for _ in 0..16 {
            let read = session.read(stream, &mut buffer).expect("прочитать ответ");
            if read == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..read]);
            if response.ends_with(b"ok") {
                break;
            }
        }
        response
    }

    #[test]
    fn ch12_build_matches_donor_shape_and_padding() {
        let random = [0x41; 32];
        let hello = r2o_tls12_client_hello(Some("example.test"), &random, 0).unwrap();
        assert_eq!(&hello[0..3], &[0x16, 3, 3]);
        assert_eq!(
            usize::from(u16::from_be_bytes([hello[3], hello[4]])),
            hello.len() - 5
        );
        assert_eq!(hello[5], 1);
        let body_len =
            (usize::from(hello[6]) << 16) | (usize::from(hello[7]) << 8) | usize::from(hello[8]);
        assert_eq!(body_len + 9, hello.len());
        assert_eq!(&hello[9..11], &[3, 3]);
        assert_eq!(&hello[11..43], &random);
        // session_id, cipher suites, compression
        assert_eq!(hello[43], 0);
        assert_eq!(&hello[44..46], &[0, 4]);
        assert_eq!(&hello[46..50], &[0xc0, 0x2b, 0xc0, 0x2f]);
        assert_eq!(&hello[50..52], &[1, 0]);
        let ext_len = u16::from_be_bytes([hello[52], hello[53]]) as usize;
        assert_eq!(52 + 2 + ext_len, hello.len());
        // C `ch12_build` считает `now` с уже зарезервированным полем длины
        // расширений и потому даёт на два байта меньше `want_wire`; это
        // донорская арифметика, а не округление.
        let padded = r2o_tls12_client_hello(Some("example.test"), &random, 700).unwrap();
        assert_eq!(padded.len(), 698);
        assert_eq!(&padded[0..3], &[0x16, 3, 3]);
        assert_eq!(usize::from(u16::from_be_bytes([padded[3], padded[4]])), 693);
        let pad_len = 698 - hello.len() - 4;
        assert_eq!(
            &padded[hello.len()..hello.len() + 4],
            &[0, 21, (pad_len >> 8) as u8, pad_len as u8]
        );
        assert!(padded[hello.len() + 4..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn ch12_build_c_differential_matches_donor_bytes() {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        let random = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let max_sni = "a".repeat(247);
        let cases: [(&str, Option<&str>, usize); 8] = [
            ("none", None, 0),
            ("empty", Some(""), 0),
            ("short", Some("a"), 0),
            ("example", Some("example.test"), 0),
            ("example-600", Some("example.test"), 600),
            ("example-700", Some("example.test"), 700),
            (
                "long-sni",
                Some("very-long-name-for-the-tls12-clienthello.example"),
                1200,
            ),
            ("max-sni", Some(&max_sni), 0),
        ];
        let mut output = String::new();
        for (name, sni, want_wire) in cases {
            let hello = r2o_tls12_client_hello(sni, &random, want_wire).unwrap();
            output.push_str(&format!(
                "case={name} len={} hex={}\n",
                hello.len(),
                hex(&hello)
            ));
        }
        if let Ok(path) = std::env::var("R2O_TLS12_CH12_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert!(output.contains("case=example len=107 "));
        assert!(output.contains("case=example-700 len=698 "));
    }

    #[test]
    fn tls12_connect_completes_and_reports_donor_peer_name() {
        let (config, _) = server_config();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || serve(config, listener, b"GET / HTTP/1.1\r\n"));
        let mut stream = TcpStream::connect(address).unwrap();
        let mut session =
            r2o_tls12_connect(&mut stream, "localhost", Duration::from_secs(3), 0).unwrap();
        assert_eq!(session.peer_name(), Some(true));
        session
            .write(&mut stream, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let response = read_http_ok(&mut session, &mut stream);
        assert!(
            response.starts_with(b"HTTP/1.1 200 OK"),
            "response={response:?}"
        );
        server.join().unwrap();
    }

    fn read_server_flight(stream: &mut TcpStream) -> Vec<u8> {
        let mut handshake = Vec::new();
        loop {
            let mut header = [0_u8; 5];
            stream
                .read_exact(&mut header)
                .expect("прочитать TLS-запись сервера");
            assert_eq!(header[0], 22, "сервер шлёт handshake");
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            let mut body = vec![0_u8; length];
            stream.read_exact(&mut body).expect("прочитать тело записи");
            handshake.extend_from_slice(&body);
            let mut offset = 0_usize;
            while handshake.len().saturating_sub(offset) >= 4 {
                let size = (usize::from(handshake[offset + 1]) << 16)
                    | (usize::from(handshake[offset + 2]) << 8)
                    | usize::from(handshake[offset + 3]);
                if handshake.len().saturating_sub(offset) < 4 + size {
                    break;
                }
                if handshake[offset] == 14 {
                    return handshake;
                }
                offset += 4 + size;
            }
        }
    }

    #[test]
    fn tls12_resume_after_tls13_client_hello_completes_downgrade() {
        let (config, _) = server_config();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || serve(config, listener, b"GET / HTTP/1.1\r\n"));
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let random = [0x55; 32];
        let ch = r2o_tls13_client_hello(&R2oTls13ClientHelloOptions {
            server_name: Some("localhost"),
            public_key: &[7; 32],
            random: &random,
            session_id_len: 0,
            offer_tls12: true,
            alpn: Some("http/1.1"),
            alpn_wire: None,
            extra_extensions: &[],
            pad_to: 0,
        })
        .unwrap();
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(ch.len() as u16).to_be_bytes());
        record.extend_from_slice(&ch);
        stream.write_all(&record).unwrap();
        let flight = read_server_flight(&mut stream);
        let mut session = r2o_tls12_resume(
            &mut stream,
            "localhost",
            Duration::from_secs(3),
            random,
            &ch,
            &flight,
        )
        .expect("TLS1.2 resume после TLS1.3 ClientHello");
        assert_eq!(session.peer_name(), Some(true));
        session
            .write(&mut stream, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let response = read_http_ok(&mut session, &mut stream);
        assert!(
            response.starts_with(b"HTTP/1.1 200 OK"),
            "response={response:?}"
        );
        server.join().unwrap();
    }
}

#[cfg(test)]
mod alpn_tests {
    use super::{alpn_is_http, r2o_tls_client_connection, r2o_tls_client_hello_non_http_alpn};

    #[test]
    fn alpn_is_http_matches_c() {
        assert!(alpn_is_http(b"http/1.1"));
        assert!(alpn_is_http(b"http/1.0"));
        assert!(alpn_is_http(b"h2"));
        assert!(!alpn_is_http(b"h3"));
        assert!(!alpn_is_http(b"HTTP/1.1"));
        assert!(!alpn_is_http(b""));
    }

    fn extension(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&kind.to_be_bytes());
        output.extend_from_slice(&(value.len() as u16).to_be_bytes());
        output.extend_from_slice(value);
        output
    }

    fn alpn(names: &[&[u8]]) -> Vec<u8> {
        let mut wire = Vec::new();
        for name in names {
            wire.push(name.len() as u8);
            wire.extend_from_slice(name);
        }
        let mut value = Vec::new();
        value.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        value.extend_from_slice(&wire);
        extension(0x0010, &value)
    }

    /// ClientHello с точными record/handshake длинами; `extensions=None`
    /// оставляет законное приветствие без блока расширений.
    fn client_hello(extensions: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[1; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        if let Some(extensions) = extensions {
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(extensions);
        }
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        record.push(1);
        record.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn tls12_client_hello_omits_alpn_like_donor_ch12_build() {
        let mut connection =
            r2o_tls_client_connection("example.test", true, None, rustls::RootCertStore::empty())
                .unwrap();
        let mut wire = Vec::new();
        connection.write_tls(&mut wire).unwrap();
        assert_eq!(
            r2o_tls_client_hello_non_http_alpn(&wire),
            Some(Vec::new()),
            "C ch12_build не добавляет ALPN"
        );
    }

    #[test]
    fn non_http_alpn_decision_matches_c_scheduler() {
        // C `d2k_hello_alpn` rc 0 → не-HTTP клиент без ALPN.
        assert_eq!(
            r2o_tls_client_hello_non_http_alpn(&client_hello(None)),
            Some(Vec::new())
        );
        let sni_only = extension(0x0000, &[0, 3, 0, 0, 0]);
        assert_eq!(
            r2o_tls_client_hello_non_http_alpn(&client_hello(Some(&sni_only))),
            Some(Vec::new())
        );
        let mqtt = alpn(&[b"mqtt"]);
        let mut mqtt_ech = mqtt.clone();
        mqtt_ech.extend_from_slice(&extension(0xfe0d, &[0, 0, 1, 0, 0]));
        assert_eq!(
            r2o_tls_client_hello_non_http_alpn(&client_hello(Some(&mqtt_ech))),
            Some(vec![b"mqtt".to_vec()])
        );
        assert_eq!(
            r2o_tls_client_hello_non_http_alpn(&client_hello(Some(&alpn(&[b"h2"])))),
            None
        );
        assert_eq!(
            r2o_tls_client_hello_non_http_alpn(&client_hello(Some(&alpn(&[b"h2", b"mqtt"])))),
            None
        );
        assert_eq!(
            r2o_tls_client_hello_non_http_alpn(&client_hello(Some(&alpn(&[])))),
            None
        );
    }
}

#[cfg(test)]
mod tls13_schedule_tests {
    use super::{
        r2o_t13_derive_secret, r2o_t13_finished_mac, r2o_t13_schedule_ap, r2o_t13_schedule_hs,
    };

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn inputs() -> ([u8; 32], [u8; 32], [u8; 64]) {
        let mut secret = [0_u8; 32];
        let mut shared = [0_u8; 32];
        let mut transcript = [0_u8; 64];
        for index in 0..32 {
            secret[index] = index as u8;
            shared[index] = 0x20 + index as u8;
        }
        for index in 0..64 {
            transcript[index] = 0x40 + index as u8;
        }
        (secret, shared, transcript)
    }

    #[test]
    fn tls13_schedule_matches_c_vectors() {
        let (secret, shared, transcript) = inputs();
        // Векторы сняты с C `d2k_t13_*` (D2O a378e230, tls13core.c/crypto.c).
        assert_eq!(
            hex(&r2o_t13_derive_secret(&secret, "test label", &transcript).unwrap()),
            "2865f62df6d615f6423154285aa323e4263d7a6f3855789ba9d00a2a04d24ef0"
        );
        let (c_hs, s_hs, handshake) = r2o_t13_schedule_hs(&shared, &transcript).unwrap();
        assert_eq!(
            hex(&c_hs),
            "5b7ac7e4c5faa7b2ca933859fe444b1ef9d4f07004cab4498cbae80fbc60c786"
        );
        assert_eq!(
            hex(&s_hs),
            "b618551ff9ae877176c8368202b9463d2eeb6b33202f969c53ee7939b70ba2d9"
        );
        assert_eq!(
            hex(&handshake),
            "a07aa32e1f50d12a76d9fe57d188e01e88f1076aa240f59107dd9a6054aac7aa"
        );
        let (c_ap, s_ap) = r2o_t13_schedule_ap(&handshake, &transcript).unwrap();
        assert_eq!(
            hex(&c_ap),
            "f6b10070fbd8d0de2a7c3646ac42169c1ee314fb6e5e73e7dd71e9f3deb776c0"
        );
        assert_eq!(
            hex(&s_ap),
            "25c9ce29ef4faace0f8cb22cd9e4cd6eedd03620228161259142b1b88f8c45e9"
        );
        assert_eq!(
            hex(&r2o_t13_finished_mac(&secret, &transcript).unwrap()),
            "56184596c40690edb1403adb73b148b88ce3f7922fdde490ff8bcfc830769eda"
        );
    }
}

#[cfg(test)]
mod server_hello_tests {
    use super::{
        r2o_t13_flight_next, r2o_t13_sh_parse, r2o_t13_sh_version, r2o_tls_replay_client_hello,
    };
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    fn server_hello(
        cipher: [u8; 2],
        key_share: Option<[u8; 32]>,
        supported_version: Option<[u8; 2]>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42; 32]);
        body.push(0);
        body.extend_from_slice(&cipher);
        body.push(0);
        let mut extensions = Vec::new();
        if let Some(version) = supported_version {
            extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02]);
            extensions.extend_from_slice(&version);
        }
        if let Some(key) = key_share {
            extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
            extensions.extend_from_slice(&key);
        }
        if !extensions.is_empty() {
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);
        }
        let mut message = Vec::with_capacity(4 + body.len());
        message.push(2);
        let len = body.len();
        message.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        message.extend_from_slice(&body);
        message
    }

    fn replay_response(server_hello: Vec<u8>) -> bool {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut hello = [0_u8; 6];
            stream.read_exact(&mut hello).unwrap();
            let len = server_hello.len();
            let mut record = vec![22, 3, 3, (len >> 8) as u8, len as u8];
            record.extend_from_slice(&server_hello);
            stream.write_all(&record).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        let result =
            r2o_tls_replay_client_hello(&mut client, &[22, 3, 1, 0, 1, 0], Duration::from_secs(1))
                .unwrap();
        server.join().unwrap();
        result
    }

    #[test]
    fn tls13_server_hello_version_and_parse_match_c() {
        let valid = server_hello([0x13, 0x01], Some([0x11; 32]), Some([0x03, 0x04]));
        assert_eq!(r2o_t13_sh_version(&valid), 0x0304);
        assert_eq!(r2o_t13_sh_parse(&valid).unwrap(), [0x11; 32]);

        let tls12 = server_hello([0x13, 0x01], None, None);
        assert_eq!(r2o_t13_sh_version(&tls12), 0x0303);
        assert!(r2o_t13_sh_parse(&tls12).is_err());

        let missing_key = server_hello([0x13, 0x01], None, Some([0x03, 0x04]));
        assert_eq!(r2o_t13_sh_version(&missing_key), 0x0304);
        assert!(r2o_t13_sh_parse(&missing_key).is_err());
        assert_eq!(r2o_t13_sh_version(&valid[..10]), 0);
    }

    #[test]
    fn tls13_flight_next_matches_c() {
        let flight = [2, 0, 0, 1, 0xaa, 8, 0, 0, 2, 0xbb, 0xcc];
        let mut offset = 0;
        assert_eq!(
            r2o_t13_flight_next(&flight, &mut offset),
            Some((2, &[0xaa][..]))
        );
        assert_eq!(
            r2o_t13_flight_next(&flight, &mut offset),
            Some((8, &[0xbb, 0xcc][..]))
        );
        assert_eq!(r2o_t13_flight_next(&flight, &mut offset), None);
        let mut offset = 0;
        assert_eq!(r2o_t13_flight_next(&flight[..4], &mut offset), None);
    }

    #[test]
    fn replay_accepts_any_server_hello_record_like_c() {
        // C `d2k_verify_replay_on` смотрит только на шесть байт записи
        // (`22 03 03 00 01 02`), cipher/key_share не разбирает — ключей
        // клиента для продолжения рукопожатия всё равно нет.
        assert!(replay_response(server_hello(
            [0x13, 0x01],
            Some([0x11; 32]),
            Some([0x03, 0x04])
        )));
        assert!(replay_response(server_hello([0x13, 0x01], None, None)));
        assert!(replay_response(server_hello(
            [0x13, 0x02],
            Some([0x11; 32]),
            Some([0x03, 0x04])
        )));
        assert!(replay_response(server_hello(
            [0x13, 0x01],
            None,
            Some([0x03, 0x04])
        )));
    }
}
