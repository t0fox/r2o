//! Ограниченный разбор Binding по RFC 5389 и сигнатуры голосовых пакетов Discord.

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const MAGIC_COOKIE: u32 = 0x2112_a442;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const HEADER_LEN: usize = 20;
const TXID_LEN: usize = 12;
const DISCORD_MEDIA_PORTS: std::ops::RangeInclusive<u16> = 50_000..=50_099;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappedAddress {
    V4 { address: [u8; 4], port: u16 },
    V6 { address: [u8; 16], port: u16 },
}

/// Собрать Binding Request без атрибутов с заданным вызывающим кодом ID транзакции.
pub fn binding_request(txid: [u8; TXID_LEN]) -> [u8; HEADER_LEN] {
    let mut request = [0; HEADER_LEN];
    request[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    request[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    request[8..].copy_from_slice(&txid);
    request
}

/// Разобрать Binding Response для этой транзакции. Для корректного ответа без
/// XOR-MAPPED-ADDRESS вернуть `Ok(None)` согласно контракту эталона на C.
pub fn parse_binding_response(
    packet: &[u8],
    txid: &[u8; TXID_LEN],
) -> Result<Option<MappedAddress>, &'static str> {
    if packet.len() < HEADER_LEN
        || read_u16(packet, 0)? != BINDING_RESPONSE
        || read_u32(packet, 4)? != MAGIC_COOKIE
        || packet.get(8..HEADER_LEN) != Some(txid.as_slice())
    {
        return Err("неверный STUN Binding Response");
    }
    let attributes_len = usize::from(read_u16(packet, 2)?);
    let attributes_end = HEADER_LEN
        .checked_add(attributes_len)
        .filter(|end| *end <= packet.len())
        .ok_or("объявленные STUN-атрибуты выходят за пакет")?;

    let mut offset = HEADER_LEN;
    while attributes_end - offset >= 4 {
        let kind = read_u16(packet, offset)?;
        let length = usize::from(read_u16(packet, offset + 2)?);
        let value_start = offset + 4;
        let value_end = value_start
            .checked_add(length)
            .filter(|end| *end <= attributes_end);
        let Some(value_end) = value_end else {
            break;
        };
        if kind == XOR_MAPPED_ADDRESS {
            return parse_xor_mapped(&packet[value_start..value_end], txid).map(Some);
        }
        let step = 4 + ((length + 3) & !3);
        let Some(next) = offset
            .checked_add(step)
            .filter(|end| *end <= attributes_end)
        else {
            break;
        };
        offset = next;
    }
    Ok(None)
}

pub fn is_binding_request(packet: &[u8]) -> bool {
    is_binding(packet, BINDING_REQUEST)
}

/// Текущий запрос Discord IP Discovery содержит ровно 74 байта и нулевые поля
/// адреса и порта. Сигнатуру нужно проверять строго.
pub fn is_discord_ip_discovery_request(packet: &[u8]) -> bool {
    packet.len() == 74
        && packet[..4] == [0, 1, 0, 70]
        && packet[8..72].iter().all(|byte| *byte == 0)
}

/// Проверить полный Discord IP Discovery ответ для выбранного SSRC.
pub fn is_discord_ip_discovery_response(packet: &[u8], ssrc: &[u8; 4]) -> bool {
    if packet.len() != 74
        || packet[..4] != [0, 2, 0, 70]
        || packet[4..8] != ssrc[..]
        || packet[72..74] == [0, 0]
    {
        return false;
    }
    let Some(address_end) = packet[8..72].iter().position(|byte| *byte == 0) else {
        return false;
    };
    if address_end == 0 {
        return false;
    }
    std::str::from_utf8(&packet[8..8 + address_end])
        .ok()
        .and_then(|text| text.parse::<std::net::Ipv4Addr>().ok())
        .is_some()
}

/// Распознать голосовой класс Discord, исключая обычный STUN вне проверенного
/// диапазона медиапортов.
pub fn is_discord_voice_request(packet: &[u8], destination_port: u16) -> bool {
    is_discord_ip_discovery_request(packet)
        || (DISCORD_MEDIA_PORTS.contains(&destination_port) && is_binding_request(packet))
}

fn is_binding(packet: &[u8], expected_type: u16) -> bool {
    if packet.len() < HEADER_LEN {
        return false;
    }
    let Ok(kind) = read_u16(packet, 0) else {
        return false;
    };
    let Ok(length) = read_u16(packet, 2) else {
        return false;
    };
    packet[0] & 0xc0 == 0
        && length % 4 == 0
        && HEADER_LEN + usize::from(length) <= packet.len()
        && read_u32(packet, 4) == Ok(MAGIC_COOKIE)
        && kind == expected_type
}

fn parse_xor_mapped(value: &[u8], txid: &[u8; TXID_LEN]) -> Result<MappedAddress, &'static str> {
    if value.len() < 8 {
        return Err("неверный XOR-MAPPED-ADDRESS");
    }
    let port = read_u16(value, 2)? ^ (MAGIC_COOKIE >> 16) as u16;
    match value[1] {
        1 => {
            let cookie = MAGIC_COOKIE.to_be_bytes();
            let mut address = [0; 4];
            for (index, byte) in address.iter_mut().enumerate() {
                *byte = value[4 + index] ^ cookie[index];
            }
            Ok(MappedAddress::V4 { address, port })
        }
        2 if value.len() >= 20 => {
            let mut key = [0; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(txid);
            let mut address = [0; 16];
            for (index, byte) in address.iter_mut().enumerate() {
                *byte = value[4 + index] ^ key[index];
            }
            Ok(MappedAddress::V6 { address, port })
        }
        _ => Err("неверное семейство XOR-MAPPED-ADDRESS"),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, &'static str> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or("обрезанное поле STUN")?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or("обрезанное поле STUN")?;
    Ok(u32::from_be_bytes(value.try_into().expect("fixed width")))
}
