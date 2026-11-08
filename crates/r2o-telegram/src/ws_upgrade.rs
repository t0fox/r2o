//! WebSocket upgrade по D2O `ws.c`: генерация запроса и строгая проверка
//! ответа (Sec-WebSocket-Accept, Connection token-list, subprotocol, лимит
//! заголовка 16 КиБ). Кадры остаются на tungstenite.

use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// C `TG_WS_UPGRADE_MAX_HEADER`.
pub const MAX_UPGRADE_HEADER: usize = 16 * 1024;
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Debug)]
pub struct Upgrade {
    request: Vec<u8>,
    key: String,
    expected_accept: String,
    subprotocol: Option<String>,
}

impl Upgrade {
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn expected_accept(&self) -> &str {
        &self.expected_accept
    }

    pub fn subprotocol(&self) -> Option<&str> {
        self.subprotocol.as_deref()
    }

    /// Разобрать статус ответа. Для 101 проверяются все обязательные поля,
    /// как C `validate_upgrade_response`. Для другого статуса возвращается он
    /// сам (вызывающий код обрабатывает redirect/HTTP-ошибку).
    pub fn validate_response(&self, header: &[u8]) -> Result<u16, String> {
        if header.is_empty() || header.len() > MAX_UPGRADE_HEADER {
            return Err("неверная длина заголовка WebSocket".to_string());
        }
        if header
            .iter()
            .any(|byte| (*byte < 0x20 && !matches!(*byte, b'\r' | b'\n' | b'\t')) || *byte == 0x7f)
        {
            return Err("управляющий символ в ответе WebSocket".to_string());
        }
        let text = std::str::from_utf8(header)
            .map_err(|_| "ответ WebSocket не является UTF-8".to_string())?;
        let line_end = text
            .find("\r\n")
            .ok_or_else(|| "нет строки статуса WebSocket".to_string())?;
        let status_line = &text[..line_end];
        let mut parts = status_line.split(' ');
        let version = parts.next().unwrap_or_default();
        let code = parts
            .next()
            .ok_or_else(|| "нет кода статуса WebSocket".to_string())?
            .parse::<u16>()
            .map_err(|_| "неверный код статуса WebSocket".to_string())?;
        if code != 101 {
            return Ok(code);
        }
        if version != "HTTP/1.1" && version != "HTTP/1.0" {
            return Err("неверная версия HTTP в WebSocket upgrade".to_string());
        }

        let mut upgrade = None;
        let mut connection = None;
        let mut accept = None;
        let mut protocol = None;
        for line in text[line_end + 2..].split("\r\n") {
            if line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                return Err("неверная строка заголовка WebSocket".to_string());
            };
            let value = value.trim_matches([' ', '\t']);
            if name.eq_ignore_ascii_case("upgrade") {
                upgrade = Some(value);
            } else if name.eq_ignore_ascii_case("connection") {
                connection = Some(value);
            } else if name.eq_ignore_ascii_case("sec-websocket-accept") {
                accept = Some(value);
            } else if name.eq_ignore_ascii_case("sec-websocket-protocol") {
                protocol = Some(value);
            }
        }
        if !upgrade.is_some_and(|value| value.eq_ignore_ascii_case("websocket")) {
            return Err("нет Upgrade: websocket".to_string());
        }
        if !connection.is_some_and(header_has_token_upgrade) {
            return Err("нет токена Upgrade в Connection".to_string());
        }
        if accept != Some(self.expected_accept.as_str()) {
            return Err("неверный Sec-WebSocket-Accept".to_string());
        }
        if let Some(required) = &self.subprotocol
            && protocol != Some(required.as_str())
        {
            return Err("сервер не выбрал запрошенный subprotocol".to_string());
        }
        Ok(101)
    }
}

fn header_has_token_upgrade(value: &str) -> bool {
    value.split(',').any(|token| {
        token
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case("upgrade")
    })
}

fn has_http_control(value: &str) -> bool {
    value
        .bytes()
        .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
}

/// C `tg_ws_upgrade_start_ex`.
pub fn begin(
    host: &str,
    path: &str,
    subprotocol: Option<&str>,
    origin: Option<&str>,
    user_agent: Option<&str>,
) -> Result<Upgrade, String> {
    if host.is_empty()
        || !path.starts_with('/')
        || has_http_control(host)
        || has_http_control(path)
        || host.contains([' ', '\t'])
        || path.contains([' ', '\t'])
    {
        return Err("неверные host/path WebSocket".to_string());
    }
    if subprotocol.is_some_and(|value| {
        value.is_empty()
            || has_http_control(value)
            || value.contains([' ', '\t', ','])
            || value.len() >= 64
    }) || origin.is_some_and(|value| value.is_empty() || has_http_control(value))
        || user_agent.is_some_and(|value| value.is_empty() || has_http_control(value))
    {
        return Err("неверные параметры WebSocket upgrade".to_string());
    }

    let random: [u8; 16] = rand::random();
    let key = base64::engine::general_purpose::STANDARD.encode(random);
    let source = format!("{key}{GUID}");
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, source.as_bytes());
    let expected_accept = base64::engine::general_purpose::STANDARD.encode(digest.as_ref());

    let mut request = String::new();
    request.push_str(&format!("GET {path} HTTP/1.1\r\n"));
    request.push_str(&format!("Host: {host}\r\n"));
    request.push_str("Upgrade: websocket\r\n");
    request.push_str("Connection: Upgrade\r\n");
    request.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    request.push_str("Sec-WebSocket-Version: 13\r\n");
    if let Some(subprotocol) = subprotocol {
        request.push_str(&format!("Sec-WebSocket-Protocol: {subprotocol}\r\n"));
    }
    if let Some(origin) = origin {
        request.push_str(&format!("Origin: {origin}\r\n"));
    }
    if let Some(user_agent) = user_agent {
        request.push_str(&format!("User-Agent: {user_agent}\r\n"));
    }
    request.push_str("\r\n");
    if request.len() >= 1024 {
        return Err("запрос WebSocket upgrade слишком длинный".to_string());
    }

    Ok(Upgrade {
        request: request.into_bytes(),
        key,
        expected_accept,
        subprotocol: subprotocol.map(str::to_string),
    })
}

/// Писать запрос и читать заголовок ответа до `\r\n\r\n` (не более 16 КиБ).
/// Возвращает статус и байты после заголовка для tungstenite.
pub async fn perform<S>(stream: &mut S, upgrade: &Upgrade) -> Result<(u16, Vec<u8>), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(upgrade.request())
        .await
        .map_err(|error| format!("передача WebSocket upgrade: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("flush WebSocket upgrade: {error}"))?;

    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("чтение WebSocket upgrade: {error}"))?;
        if read == 0 {
            return Err("соединение закрыто до завершения WebSocket upgrade".to_string());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_len = position + 4;
            if header_len > MAX_UPGRADE_HEADER {
                return Err("заголовок WebSocket превышает 16 КиБ".to_string());
            }
            let header = buffer[..header_len].to_vec();
            let leftover = buffer[header_len..].to_vec();
            let status = upgrade.validate_response(&header)?;
            return Ok((status, leftover));
        }
        if buffer.len() > MAX_UPGRADE_HEADER {
            return Err("заголовок WebSocket превышает 16 КиБ".to_string());
        }
    }
}

/// Общий deadline для тестового/диагностического вызова.
pub async fn perform_with_timeout<S>(
    stream: &mut S,
    upgrade: &Upgrade,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(timeout, perform(stream, upgrade))
        .await
        .map_err(|_| "истёк тайм-аут WebSocket upgrade".to_string())?
}

#[cfg(test)]
mod tests {
    use super::{MAX_UPGRADE_HEADER, begin};

    #[test]
    fn d2o_upgrade_validation_accepts_token_list_and_rejects_bad_accept() {
        let upgrade = begin("relay.test", "/ws", Some("binary"), None, None).unwrap();
        let mut header = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: binary\r\n\r\n",
            upgrade.expected_accept()
        )
        .into_bytes();
        assert_eq!(upgrade.validate_response(&header), Ok(101));

        let text = String::from_utf8(header.clone()).unwrap();
        header = text
            .replace(upgrade.expected_accept(), "invalid")
            .into_bytes();
        assert!(upgrade.validate_response(&header).is_err());

        let mut oversized = vec![b'a'; MAX_UPGRADE_HEADER + 1];
        oversized[..12].copy_from_slice(b"HTTP/1.1 101");
        assert!(upgrade.validate_response(&oversized).is_err());
    }

    #[test]
    fn d2o_upgrade_rejects_control_chars_and_bad_parameters() {
        assert!(begin("bad host", "/ws", None, None, None).is_err());
        assert!(begin("relay.test", "ws", None, None, None).is_err());
        assert!(begin("relay.test", "/ws", Some("bad,proto"), None, None).is_err());
        let upgrade = begin("relay.test", "/ws", None, None, None).unwrap();
        let header = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Test: bad\x01value\r\n\r\n";
        assert!(upgrade.validate_response(header).is_err());
    }
}
