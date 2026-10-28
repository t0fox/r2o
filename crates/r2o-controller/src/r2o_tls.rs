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
    r2o_tls_client_connection_with_alpn(name, tls12, wire_len, _roots, &[b"http/1.1".to_vec()])
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
    let (extensions_length, extensions_start) = r2o_tls_u16(client_hello, offset, end)?;
    let extensions_end = extensions_start.checked_add(extensions_length)?;
    if extensions_end != end {
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
        if kind == 0xfe0d {
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
                if [b"http/1.1".as_slice(), b"http/1.0", b"h2"]
                    .iter()
                    .any(|http| name == *http)
                {
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
    use std::io::{Read, Write};

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
    let mut response = [0_u8; 7];
    let mut have = 0;
    while have < 7 && !(have >= 6 && response[0] == 22) {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(&mut response[have..]) {
            Ok(0) => break,
            Ok(length) => have += length,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ) =>
            {
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            Err(_) => break,
        }
    }
    Ok(have >= 6 && response[0] == 22 && response[1] == 3 && response[5] == 2)
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
