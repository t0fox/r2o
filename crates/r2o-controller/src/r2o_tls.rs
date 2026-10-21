const R2O_TLS13_CLIENT_HELLO_MAX: usize = 4096;

/// Создать проверяемое TLS-соединение с необязательной длиной ClientHello.
///
/// Для TCP `wire_len` включает пятибайтовый заголовок записи; для QUIC — нет.
pub fn r2o_tls_client_connection(
    name: &str,
    tls12: bool,
    wire_len: Option<usize>,
    roots: rustls::RootCertStore,
) -> Result<rustls::ClientConnection, String> {
    let versions = if tls12 {
        &[&rustls::version::TLS12][..]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12][..]
    };
    let mut provider = rustls::crypto::ring::default_provider();
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
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.r2o_client_hello_wire_len = wire_len;
    let server_name = rustls::pki_types::ServerName::try_from(name.to_owned())
        .map_err(|_| "имя цели недопустимо для TLS SNI".to_owned())?;
    rustls::ClientConnection::new(std::sync::Arc::new(config), server_name)
        .map_err(|error| format!("не удалось начать TLS-рукопожатие: {error}"))
}

/// Создать TLS 1.3 соединение с ECH и корнями системно поддерживаемых серверов.
pub fn r2o_tls_ech_client_connection(
    name: &str,
    roots: rustls::RootCertStore,
    ech: rustls::client::EchConfig,
) -> Result<rustls::ClientConnection, String> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
    provider.kx_groups = vec![
        rustls::crypto::ring::kx_group::X25519,
        rustls::crypto::ring::kx_group::SECP256R1,
    ];
    let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_ech(rustls::client::EchMode::Enable(ech))
        .map_err(|error| format!("не удалось включить ECH: {error}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
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
    let mut connection = r2o_tls_ech_client_connection(name, roots, ech)?;
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
