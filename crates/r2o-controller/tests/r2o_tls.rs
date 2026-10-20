use r2o_controller::r2o_tls::{
    R2oTls13ClientHelloOptions, r2o_tls_client_connection, r2o_tls13_client_hello,
};

fn r2o_test_client_hello_body(wire: &[u8]) -> Option<&[u8]> {
    if wire.len() < 9 || wire[0] != 22 || wire[5] != 1 {
        return None;
    }
    let record_len = usize::from(u16::from_be_bytes([wire[3], wire[4]]));
    let record_end = 5_usize.checked_add(record_len)?;
    if record_end > wire.len() {
        return None;
    }
    let message = &wire[5..record_end];
    let body_len = (usize::from(*message.get(1)?) << 16)
        | (usize::from(*message.get(2)?) << 8)
        | usize::from(*message.get(3)?);
    if message.len() != body_len.checked_add(4)? {
        return None;
    }
    Some(&message[4..])
}

fn r2o_test_client_hello_cipher_suites(wire: &[u8]) -> Option<Vec<u16>> {
    let hello = r2o_test_client_hello_body(wire)?;
    let session_id_len = usize::from(*hello.get(34)?);
    let mut offset = 35_usize.checked_add(session_id_len)?;
    let suites_len = usize::from(u16::from_be_bytes([
        *hello.get(offset)?,
        *hello.get(offset + 1)?,
    ]));
    offset = offset.checked_add(2)?;
    if suites_len % 2 != 0 || offset.checked_add(suites_len)? > hello.len() {
        return None;
    }
    Some(
        hello[offset..offset + suites_len]
            .chunks_exact(2)
            .map(|suite| u16::from_be_bytes([suite[0], suite[1]]))
            .collect(),
    )
}

fn r2o_test_client_hello_extension(wire: &[u8], wanted: u16) -> Option<&[u8]> {
    let hello = r2o_test_client_hello_body(wire)?;
    let session_id_len = usize::from(*hello.get(34)?);
    let mut offset = 35_usize.checked_add(session_id_len)?;
    let suites_len = usize::from(u16::from_be_bytes([
        *hello.get(offset)?,
        *hello.get(offset + 1)?,
    ]));
    offset = offset.checked_add(2 + suites_len)?;
    let compression_len = usize::from(*hello.get(offset)?);
    offset = offset.checked_add(1 + compression_len)?;
    let extensions_len = usize::from(u16::from_be_bytes([
        *hello.get(offset)?,
        *hello.get(offset + 1)?,
    ]));
    offset = offset.checked_add(2)?;
    let extensions_end = offset.checked_add(extensions_len)?;
    if extensions_end > hello.len() {
        return None;
    }
    while offset.checked_add(4)? <= extensions_end {
        let kind = u16::from_be_bytes([*hello.get(offset)?, *hello.get(offset + 1)?]);
        let length = usize::from(u16::from_be_bytes([
            *hello.get(offset + 2)?,
            *hello.get(offset + 3)?,
        ]));
        let value = offset.checked_add(4)?;
        let end = value.checked_add(length)?;
        if end > extensions_end {
            return None;
        }
        if kind == wanted {
            return hello.get(value..end);
        }
        offset = end;
    }
    None
}

fn r2o_test_client_hello_groups(wire: &[u8]) -> Option<Vec<u16>> {
    let extension = r2o_test_client_hello_extension(wire, 0x000a)?;
    let groups_len = usize::from(u16::from_be_bytes([
        *extension.first()?,
        *extension.get(1)?,
    ]));
    if groups_len % 2 != 0 || groups_len.checked_add(2)? != extension.len() {
        return None;
    }
    Some(
        extension[2..]
            .chunks_exact(2)
            .map(|group| u16::from_be_bytes([group[0], group[1]]))
            .collect(),
    )
}

#[test]
fn клиентское_рукопожатие_предлагает_http11_alpn() {
    let roots = rustls::RootCertStore::empty();
    let mut connection = r2o_tls_client_connection("example.com", false, None, roots).unwrap();
    let mut wire = Vec::new();
    connection.write_tls(&mut wire).unwrap();

    let alpn = [
        0x00, 0x10, 0x00, 0x0b, 0x00, 0x09, 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
    ];
    assert!(wire.windows(alpn.len()).any(|window| window == alpn));
}

#[test]
fn клиентское_рукопожатие_предлагает_наборы_донора() {
    let mut auto =
        r2o_tls_client_connection("example.com", false, None, rustls::RootCertStore::empty())
            .unwrap();
    let mut auto_wire = Vec::new();
    auto.write_tls(&mut auto_wire).unwrap();
    assert_eq!(
        r2o_test_client_hello_cipher_suites(&auto_wire).unwrap(),
        [0x1301, 0xc02b, 0xc02f, 0x00ff]
    );
    assert_eq!(
        r2o_test_client_hello_groups(&auto_wire).unwrap(),
        [0x001d, 0x0017]
    );

    let mut tls12 =
        r2o_tls_client_connection("example.com", true, None, rustls::RootCertStore::empty())
            .unwrap();
    let mut tls12_wire = Vec::new();
    tls12.write_tls(&mut tls12_wire).unwrap();
    assert_eq!(
        r2o_test_client_hello_cipher_suites(&tls12_wire).unwrap(),
        [0xc02b, 0xc02f, 0x00ff]
    );
    assert_eq!(
        r2o_test_client_hello_groups(&tls12_wire).unwrap(),
        [0x001d, 0x0017, 0x0018]
    );
}

fn r2o_test_padding_extension(bytes: &[u8]) -> Option<&[u8]> {
    let mut offset = 4 + 2 + 32;
    let session_id_len = usize::from(*bytes.get(offset)?);
    offset = offset.checked_add(1 + session_id_len)?;
    let cipher_suites_len = usize::from(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]));
    offset = offset.checked_add(2 + cipher_suites_len)?;
    let compression_len = usize::from(*bytes.get(offset)?);
    offset = offset.checked_add(1 + compression_len)?;
    let extensions_len = usize::from(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]));
    let extensions_end = offset.checked_add(2 + extensions_len)?;
    offset += 2;

    while offset.checked_add(4)? <= extensions_end {
        let kind = u16::from_be_bytes([*bytes.get(offset)?, *bytes.get(offset + 1)?]);
        let length = usize::from(u16::from_be_bytes([
            *bytes.get(offset + 2)?,
            *bytes.get(offset + 3)?,
        ]));
        let value = offset.checked_add(4)?;
        let end = value.checked_add(length)?;
        if end > extensions_end {
            return None;
        }
        if kind == 0x0015 {
            return bytes.get(value..end);
        }
        offset = end;
    }
    None
}

#[test]
fn приветствие_добивается_до_заданной_длины_сообщения() {
    let public_key = [0x11; 32];
    let random = [0x22; 32];
    let hello = r2o_tls13_client_hello(&R2oTls13ClientHelloOptions {
        server_name: Some("example.com"),
        public_key: &public_key,
        random: &random,
        session_id_len: 32,
        offer_tls12: true,
        alpn: Some("http/1.1"),
        alpn_wire: None,
        extra_extensions: &[],
        pad_to: 1275,
    })
    .unwrap();

    assert_eq!(hello.len(), 1275);
    assert_eq!(hello[0], 1);
    assert_eq!(
        u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize,
        1271
    );
    assert_eq!(hello, include_bytes!("fixtures/r2o_tls13_client_hello.bin"));
    let padding = r2o_test_padding_extension(&hello).unwrap();
    assert!(!padding.is_empty());
    assert!(padding.iter().all(|byte| *byte == 0));
}

#[test]
fn приветствие_отвергает_session_id_длиннее_допустимого() {
    let public_key = [0x11; 32];
    let random = [0x22; 32];
    let result = r2o_tls13_client_hello(&R2oTls13ClientHelloOptions {
        server_name: Some("example.com"),
        public_key: &public_key,
        random: &random,
        session_id_len: 33,
        offer_tls12: true,
        alpn: Some("http/1.1"),
        alpn_wire: None,
        extra_extensions: &[],
        pad_to: 0,
    });

    assert!(result.is_err());
}
