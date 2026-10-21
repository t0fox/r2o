//! Разрешение HTTPS-записей и выбор совместимой конфигурации ECH.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

use hpke::aead::{AeadCtxR, AeadCtxS, AesGcm128};
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as HpkeKem, OpModeR, OpModeS, Serializable};
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem as RustlsHpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;

const R2O_ECH_DNS_TIMEOUT: Duration = Duration::from_millis(1500);
const R2O_ECH_DNS_PACKET_MAX: usize = 4096;
const R2O_ECH_CONFIG_WIRE_MAX: usize = 512;
const R2O_SO_MARK: libc::c_int = 36;

static R2O_ECH_HPKE: R2oEchHpke = R2oEchHpke;
static R2O_ECH_HPKE_SUITES: [&'static dyn Hpke; 1] = [&R2O_ECH_HPKE];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oEchConfig {
    pub public_name: String,
    pub origin_name: String,
    pub config_list: Vec<u8>,
}

#[derive(Debug)]
struct R2oEchHpke;

struct R2oEchHpkeSealer(AeadCtxS<AesGcm128, HkdfSha256, X25519HkdfSha256>);

struct R2oEchHpkeOpener(AeadCtxR<AesGcm128, HkdfSha256, X25519HkdfSha256>);

impl std::fmt::Debug for R2oEchHpkeSealer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("R2oEchHpkeSealer")
    }
}

impl std::fmt::Debug for R2oEchHpkeOpener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("R2oEchHpkeOpener")
    }
}

impl HpkeSealer for R2oEchHpkeSealer {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.0.seal(plaintext, aad).map_err(r2o_ech_hpke_error)
    }
}

impl HpkeOpener for R2oEchHpkeOpener {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.0.open(ciphertext, aad).map_err(r2o_ech_hpke_error)
    }
}

impl Hpke for R2oEchHpke {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), rustls::Error> {
        let (enc, mut sealer) = self.setup_sealer(info, pub_key)?;
        Ok((enc, sealer.seal(aad, plaintext)?))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), rustls::Error> {
        let pub_key = <X25519HkdfSha256 as HpkeKem>::PublicKey::from_bytes(&pub_key.0)
            .map_err(r2o_ech_hpke_error)?;
        let (enc, sealer) = hpke::setup_sender::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &pub_key,
            info,
        )
        .map_err(r2o_ech_hpke_error)?;
        Ok((
            EncapsulatedSecret(enc.to_bytes().to_vec()),
            Box::new(R2oEchHpkeSealer(sealer)),
        ))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, rustls::Error> {
        self.setup_opener(enc, info, secret_key)?
            .open(aad, ciphertext)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, rustls::Error> {
        let enc = <X25519HkdfSha256 as HpkeKem>::EncappedKey::from_bytes(&enc.0)
            .map_err(r2o_ech_hpke_error)?;
        let secret_key =
            <X25519HkdfSha256 as HpkeKem>::PrivateKey::from_bytes(secret_key.secret_bytes())
                .map_err(r2o_ech_hpke_error)?;
        let opener = hpke::setup_receiver::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &secret_key,
            &enc,
            info,
        )
        .map_err(r2o_ech_hpke_error)?;
        Ok(Box::new(R2oEchHpkeOpener(opener)))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), rustls::Error> {
        let (secret_key, public_key) = X25519HkdfSha256::gen_keypair();
        Ok((
            HpkePublicKey(public_key.to_bytes().to_vec()),
            HpkePrivateKey::from(secret_key.to_bytes().to_vec()),
        ))
    }

    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: RustlsHpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::AES_128_GCM,
            },
        }
    }
}

fn r2o_ech_hpke_error(error: impl std::fmt::Display) -> rustls::Error {
    rustls::Error::General(format!("ошибка ECH HPKE: {error}"))
}

/// Разобрать DNS-конфигурацию ECH тем же HPKE-набором, что и донор.
pub fn r2o_ech_tls_config(config: &R2oEchConfig) -> Result<rustls::client::EchConfig, String> {
    let list = rustls::pki_types::EchConfigListBytes::from(config.config_list.clone());
    rustls::client::EchConfig::new(list, &R2O_ECH_HPKE_SUITES)
        .map_err(|error| format!("не удалось выбрать конфигурацию ECH: {error}"))
}

/// Найти в HTTPS RR конфигурацию, совместимую с TLS-клиентом донора.
pub fn resolve_ech_config(name: &str, mark: Option<u32>) -> Result<R2oEchConfig, String> {
    let name = r2o_ech_normalize_name(name)?;
    let resolver = r2o_ech_system_resolver()?;
    r2o_ech_query_resolver(&name, resolver, mark)
}

fn r2o_ech_system_resolver() -> Result<SocketAddr, String> {
    let contents = std::fs::read_to_string("/etc/resolv.conf")
        .map_err(|error| format!("не удалось прочитать /etc/resolv.conf: {error}"))?;
    let address = contents
        .lines()
        .filter_map(|line| line.split('#').next())
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == "nameserver")
                .then(|| fields.next())
                .flatten()
        })
        .ok_or_else(|| "в /etc/resolv.conf нет DNS-сервера".to_owned())?
        .parse::<IpAddr>()
        .map_err(|error| format!("адрес DNS-сервера в /etc/resolv.conf неверен: {error}"))?;
    Ok(SocketAddr::new(address, 53))
}

fn r2o_ech_query_resolver(
    name: &str,
    resolver: SocketAddr,
    mark: Option<u32>,
) -> Result<R2oEchConfig, String> {
    let mut transaction_id = [0_u8; 2];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut transaction_id)
        .map_err(|_| "не удалось создать DNS transaction ID".to_owned())?;
    let query = r2o_ech_https_query(name, transaction_id)?;
    let bind = match resolver {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket =
        UdpSocket::bind(bind).map_err(|error| format!("не удалось открыть DNS-сокет: {error}"))?;
    if let Some(mark) = mark.filter(|mark| *mark != 0) {
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                R2O_SO_MARK,
                (&mark as *const u32).cast(),
                std::mem::size_of_val(&mark) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(format!(
                "не удалось назначить DNS-сокету SO_MARK: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    socket
        .connect(resolver)
        .map_err(|error| format!("не удалось выбрать DNS-сервер {resolver}: {error}"))?;
    socket
        .set_read_timeout(Some(R2O_ECH_DNS_TIMEOUT))
        .map_err(|error| format!("не удалось настроить срок DNS-ответа: {error}"))?;
    socket
        .set_write_timeout(Some(R2O_ECH_DNS_TIMEOUT))
        .map_err(|error| format!("не удалось настроить срок DNS-запроса: {error}"))?;
    socket
        .send(&query)
        .map_err(|error| format!("не удалось отправить HTTPS-запрос DNS: {error}"))?;
    let mut reply = [0_u8; R2O_ECH_DNS_PACKET_MAX];
    let length = socket
        .recv(&mut reply)
        .map_err(|error| format!("не получен HTTPS-ответ DNS: {error}"))?;
    r2o_ech_parse_https_reply(name, transaction_id, &reply[..length])
}

fn r2o_ech_normalize_name(name: &str) -> Result<String, String> {
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return Err("имя ECH должно быть ASCII-именем длиной до 253 байт".into());
    }
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    if name.is_empty()
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("имя ECH содержит недопустимую DNS-метку".into());
    }
    Ok(name)
}

fn r2o_ech_https_query(name: &str, transaction_id: [u8; 2]) -> Result<Vec<u8>, String> {
    let name = r2o_ech_normalize_name(name)?;
    let mut query = Vec::with_capacity(12 + name.len() + 6);
    query.extend_from_slice(&transaction_id);
    query.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 65, 0, 1]);
    Ok(query)
}

fn r2o_ech_parse_https_reply(
    expected_name: &str,
    transaction_id: [u8; 2],
    reply: &[u8],
) -> Result<R2oEchConfig, String> {
    if reply.len() < 12
        || reply[..2] != transaction_id
        || reply[2] & 0x80 == 0
        || reply[2] & 0x7a != 0
        || reply[3] & 15 != 0
        || r2o_ech_u16(reply, 4)? != 1
    {
        return Err("ответ HTTPS DNS имеет неверный заголовок".into());
    }
    let expected_name = r2o_ech_normalize_name(expected_name)?;
    let mut cursor = 12;
    let (question, next) = r2o_ech_dns_name(reply, cursor)?;
    cursor = next;
    if question != expected_name
        || r2o_ech_u16(reply, cursor)? != 65
        || r2o_ech_u16(reply, cursor + 2)? != 1
    {
        return Err("ответ HTTPS DNS не соответствует запросу".into());
    }
    cursor += 4;
    let answers = usize::from(r2o_ech_u16(reply, 6)?);
    if answers > 64 {
        return Err("ответ HTTPS DNS превышает предел в 64 записи".into());
    }
    for _ in 0..answers {
        let (owner, next) = r2o_ech_dns_name(reply, cursor)?;
        cursor = next;
        let data_length = usize::from(r2o_ech_u16(reply, cursor + 8)?);
        let record_end = cursor
            .checked_add(10)
            .and_then(|start| start.checked_add(data_length))
            .filter(|end| *end <= reply.len())
            .ok_or_else(|| "запись HTTPS выходит за границы DNS-ответа".to_owned())?;
        let record_type = r2o_ech_u16(reply, cursor)?;
        let class = r2o_ech_u16(reply, cursor + 2)?;
        cursor += 10;
        if record_type != 65 || class != 1 || owner != expected_name {
            cursor = record_end;
            continue;
        }
        if data_length < 3 || r2o_ech_u16(reply, cursor)? == 0 {
            cursor = record_end;
            continue;
        }
        cursor += 2;
        let (target, next) = r2o_ech_dns_name(reply, cursor)?;
        cursor = next;
        if cursor > record_end {
            return Err("имя цели HTTPS выходит за границы записи".into());
        }
        if !target.is_empty() && target != expected_name {
            cursor = record_end;
            continue;
        }
        let mut last_key = None;
        let mut compatible_port = true;
        let mut config = None;
        while cursor < record_end {
            if record_end - cursor < 4 {
                return Err("параметр HTTPS обрезан".into());
            }
            let key = r2o_ech_u16(reply, cursor)?;
            let length = usize::from(r2o_ech_u16(reply, cursor + 2)?);
            cursor += 4;
            let end = cursor
                .checked_add(length)
                .filter(|end| *end <= record_end)
                .ok_or_else(|| "значение параметра HTTPS выходит за границы".to_owned())?;
            if last_key.is_some_and(|previous| key <= previous) {
                return Err("параметры HTTPS не отсортированы или повторяются".into());
            }
            last_key = Some(key);
            if key == 3 && (length != 2 || r2o_ech_u16(reply, cursor)? != 443) {
                compatible_port = false;
            }
            if key == 5 {
                config = r2o_ech_select_config(&reply[cursor..end]);
            }
            cursor = end;
        }
        if compatible_port {
            if let Some(mut config) = config {
                config.origin_name = expected_name.clone();
                return Ok(config);
            }
        }
    }
    Err("HTTPS RR не содержит совместимой ECH-конфигурации".into())
}

fn r2o_ech_select_config(configs: &[u8]) -> Option<R2oEchConfig> {
    if configs.len() < 2 || usize::from(r2o_ech_u16(configs, 0).ok()?) != configs.len() - 2 {
        return None;
    }
    let mut cursor = 2;
    while cursor < configs.len() {
        let start = cursor;
        if configs.len() - cursor < 4 {
            return None;
        }
        let version = r2o_ech_u16(configs, cursor).ok()?;
        let config_end = cursor
            .checked_add(4)
            .and_then(|offset| {
                offset.checked_add(usize::from(r2o_ech_u16(configs, cursor + 2).ok()?))
            })
            .filter(|end| *end <= configs.len())?;
        cursor += 4;
        if version != 0xfe0d {
            cursor = config_end;
            continue;
        }
        if config_end - cursor < 5 {
            return None;
        }
        cursor += 1;
        let kem = r2o_ech_u16(configs, cursor).ok()?;
        cursor += 2;
        let key_length = usize::from(r2o_ech_u16(configs, cursor).ok()?);
        cursor += 2;
        let key_end = cursor
            .checked_add(key_length)
            .filter(|end| *end <= config_end)?;
        cursor = key_end;
        let suites_length = usize::from(r2o_ech_u16(configs, cursor).ok()?);
        cursor += 2;
        if suites_length == 0 || suites_length % 4 != 0 {
            return None;
        }
        let suites_end = cursor
            .checked_add(suites_length)
            .filter(|end| *end <= config_end)?;
        let compatible_suite = configs[cursor..suites_end]
            .chunks_exact(4)
            .any(|suite| suite == [0, 1, 0, 1]);
        cursor = suites_end;
        if config_end - cursor < 2 {
            return None;
        }
        cursor += 1;
        let name_length = usize::from(configs[cursor]);
        cursor += 1;
        let name_end = cursor
            .checked_add(name_length)
            .filter(|end| *end <= config_end)?;
        let public_name = std::str::from_utf8(&configs[cursor..name_end]).ok()?;
        let public_name = r2o_ech_public_name(public_name)?;
        cursor = name_end;
        if config_end - cursor < 2 {
            return None;
        }
        let extensions_length = usize::from(r2o_ech_u16(configs, cursor).ok()?);
        cursor += 2;
        if extensions_length != config_end - cursor {
            return None;
        }
        let mut mandatory_unknown = false;
        while cursor < config_end {
            if config_end - cursor < 4 {
                return None;
            }
            let extension = r2o_ech_u16(configs, cursor).ok()?;
            let length = usize::from(r2o_ech_u16(configs, cursor + 2).ok()?);
            cursor += 4;
            cursor = cursor
                .checked_add(length)
                .filter(|end| *end <= config_end)?;
            mandatory_unknown |= extension & 0x8000 != 0;
        }
        if kem == 0x20
            && key_length == 32
            && compatible_suite
            && !mandatory_unknown
            && config_end - start <= R2O_ECH_CONFIG_WIRE_MAX
        {
            let wire = &configs[start..config_end];
            let mut config_list = Vec::with_capacity(wire.len() + 2);
            config_list.extend_from_slice(&(wire.len() as u16).to_be_bytes());
            config_list.extend_from_slice(wire);
            return Some(R2oEchConfig {
                public_name,
                origin_name: String::new(),
                config_list,
            });
        }
        cursor = config_end;
    }
    None
}

fn r2o_ech_public_name(name: &str) -> Option<String> {
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return None;
    }
    if name.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }
    Some(name.to_owned())
}

fn r2o_ech_dns_name(message: &[u8], start: usize) -> Result<(String, usize), String> {
    let mut cursor = start;
    let mut after = None;
    let mut labels = Vec::new();
    let mut jumps = 0;
    loop {
        let length = *message
            .get(cursor)
            .ok_or_else(|| "имя DNS выходит за границы ответа".to_owned())?;
        cursor += 1;
        if length == 0 {
            return Ok((labels.join("."), after.unwrap_or(cursor)));
        }
        if length & 0xc0 == 0xc0 {
            let low = *message
                .get(cursor)
                .ok_or_else(|| "указатель DNS обрезан".to_owned())?;
            let target = (usize::from(length & 0x3f) << 8) | usize::from(low);
            after.get_or_insert(cursor + 1);
            jumps += 1;
            if target >= message.len() || target >= cursor - 1 {
                return Err("указатель DNS зациклен или выходит за границы".into());
            }
            if jumps > 16 {
                return Err("имя DNS превышает предел переходов по указателям".into());
            }
            cursor = target;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err("DNS-метка имеет неверный тип".into());
        }
        let end = cursor
            .checked_add(usize::from(length))
            .filter(|end| *end <= message.len())
            .ok_or_else(|| "DNS-метка выходит за границы ответа".to_owned())?;
        let label = &message[cursor..end];
        if !label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err("DNS-имя содержит недопустимый символ".into());
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        if labels.len() > 127 {
            return Err("DNS-имя содержит слишком много меток".into());
        }
        cursor = end;
    }
}

fn r2o_ech_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "поле DNS обрезано".to_owned())?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    use super::{
        Hpke, R2O_ECH_HPKE, R2oEchConfig, r2o_ech_dns_name, r2o_ech_https_query,
        r2o_ech_parse_https_reply, r2o_ech_query_resolver, r2o_ech_select_config,
    };
    use std::net::UdpSocket;
    use std::thread;
    use std::time::Duration;

    const CONFIG_HEX: &str = "0045fe0d004137002000200d1bbf3935b6317f6bc0a07894ba03bb3c32dc86758dcf67fef797a98360c97b0004000100010012636c6f7564666c6172652d6563682e636f6d0000";

    fn r2o_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn rustls_принимает_донорскую_конфигурацию_ech() {
        let config = r2o_ech_select_config(&r2o_hex(CONFIG_HEX)).unwrap();
        assert_eq!(config.public_name, "cloudflare-ech.com");
        assert!(super::r2o_ech_tls_config(&config).is_ok());
    }

    #[test]
    fn r2o_собирает_ech_clienthello_для_автоклассификатора() {
        let mut config = r2o_ech_select_config(&r2o_hex(CONFIG_HEX)).unwrap();
        config.origin_name = config.public_name.clone();
        let ech = super::r2o_ech_tls_config(&config).unwrap();
        let hello = crate::r2o_tls::r2o_tls_ech_client_hello(&config.public_name, ech).unwrap();
        let shape = r2k_core::tls::parse(&hello);

        assert!(shape.is_client_hello);
        assert!(shape.is_tls13);
        assert!(shape.ech_offer);
        assert_eq!(
            shape.sni_range.as_ref().map(|range| &hello[range.clone()]),
            Some(config.public_name.as_bytes())
        );
        assert!(crate::classify::Trigger::tls_client_hello(&config.public_name, &hello).is_ok());
    }

    #[test]
    fn чисто_rust_hpke_отправляет_и_принимает_сообщение() {
        let (public_key, private_key) = R2O_ECH_HPKE.generate_key_pair().unwrap();
        let (enc, ciphertext) = R2O_ECH_HPKE
            .seal(b"ECH test", b"aad", b"ClientHelloInner", &public_key)
            .unwrap();
        let plaintext = R2O_ECH_HPKE
            .open(&enc, b"ECH test", b"aad", &ciphertext, &private_key)
            .unwrap();
        assert_eq!(plaintext, b"ClientHelloInner");
    }

    fn r2o_dns_reply(query: &[u8], config: &[u8]) -> Vec<u8> {
        let mut reply = query.to_vec();
        reply[2..4].copy_from_slice(&[0x81, 0x80]);
        reply[6..8].copy_from_slice(&1_u16.to_be_bytes());
        reply[8..12].fill(0);
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 65, 0, 1, 0, 0, 0, 60]);
        let data_length = 2 + 1 + 4 + config.len();
        reply.extend_from_slice(&(data_length as u16).to_be_bytes());
        reply.extend_from_slice(&[0, 1, 0]);
        reply.extend_from_slice(&[0, 5]);
        reply.extend_from_slice(&(config.len() as u16).to_be_bytes());
        reply.extend_from_slice(config);
        reply
    }

    #[test]
    fn r2o_выбирает_совместимую_конфигурацию_из_записи_донора() {
        let config = r2o_ech_select_config(&r2o_hex(CONFIG_HEX)).unwrap();
        assert_eq!(config.public_name, "cloudflare-ech.com");
        assert_eq!(config.config_list, r2o_hex(CONFIG_HEX));
    }

    #[test]
    fn r2o_отклоняет_обрезанные_и_неподдерживаемые_конфигурации() {
        let config = r2o_hex(CONFIG_HEX);
        for end in 0..config.len() {
            assert!(r2o_ech_select_config(&config[..end]).is_none());
        }
        let mut unsupported = config;
        unsupported[7] = 0;
        unsupported[8] = 0x21;
        assert!(r2o_ech_select_config(&unsupported).is_none());
    }

    #[test]
    fn r2o_проверяет_dns_запрос_владельца_и_ech_ответа() {
        let config = r2o_hex(CONFIG_HEX);
        let query = r2o_ech_https_query("Witness.Example.", [0x12, 0x34]).unwrap();
        assert_eq!(&query[..2], &[0x12, 0x34]);
        assert_eq!(&query[query.len() - 4..], &[0, 65, 0, 1]);
        let reply = r2o_dns_reply(&query, &config);
        let result = r2o_ech_parse_https_reply("witness.example", [0x12, 0x34], &reply).unwrap();
        assert_eq!(
            result,
            R2oEchConfig {
                public_name: "cloudflare-ech.com".into(),
                origin_name: "witness.example".into(),
                config_list: config,
            }
        );
        assert!(r2o_ech_parse_https_reply("other.example", [0x12, 0x34], &reply).is_err());
        assert!(r2o_ech_parse_https_reply("witness.example", [0, 1], &reply).is_err());
    }

    #[test]
    fn r2o_ограничивает_dns_указатели_сжатия() {
        assert!(r2o_ech_dns_name(&[0xc0, 0], 0).is_err());
        assert!(r2o_ech_dns_name(&[0xc0, 2, 0], 0).is_err());
    }

    #[test]
    fn r2o_получает_https_rr_через_ограниченный_udp_запрос() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let resolver = server.local_addr().unwrap();
        let config = r2o_hex(CONFIG_HEX);
        let worker = thread::spawn(move || {
            let mut query = [0_u8; 512];
            let (length, peer) = server.recv_from(&mut query).unwrap();
            let query = &query[..length];
            assert_eq!(&query[query.len() - 4..], &[0, 65, 0, 1]);
            server
                .send_to(&r2o_dns_reply(query, &config), peer)
                .unwrap();
        });
        let result = r2o_ech_query_resolver("witness.example", resolver, None).unwrap();
        worker.join().unwrap();
        assert_eq!(result.public_name, "cloudflare-ech.com");
    }
}
