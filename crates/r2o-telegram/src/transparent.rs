//! Средства Linux для прозрачного проксирования. После чтения 64-байтового
//! заголовка obfuscated2 поток остаётся непрозрачным: Telegram WSS передаёт
//! MTProto как единый поток байтов, поэтому границы WebSocket-кадров не должны
//! менять или повторно шифровать данные.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;

use tokio::net::TcpStream;

use cipher::StreamCipher;

use crate::crypto::{AesCtr256, DC_IDX_POS, HANDSHAKE_LEN, PROTO_TAG_POS, ProtoTag, make_cipher};

/// Метаданные obfuscated2: DC может отсутствовать в прямом подключении.
pub struct ClientInit {
    pub dc: Option<u32>,
    pub is_media: bool,
    pub proto: crate::crypto::ProtoTag,
    /// Рукопожатие расшифровано официальным `secret` из dcOption.
    pub used_official_secret: bool,
}

/// Максимум секретов, как C `TG_TRANSPARENT_MAX_SECRETS`.
pub const MAX_HANDSHAKE_SECRETS: usize = 16;

/// Решение прозрачного маршрута, эквивалентное C `tg_transparent_select_route`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransparentSelection {
    /// Прямой TCP к исходному адресу: official secret, CDN/tcpo-only,
    /// либо неизвестное назначение без DC-hint.
    DirectTcp { dc: u32, is_media: bool },
    /// WSS/CF-маршрут к найденному dcOption.
    Wss { dc: u32, is_media: bool },
    /// Неизвестное назначение с DC-hint: WSS не выбирается.
    Reject,
}

/// Выбрать direct/DD или WSS по найденному dcOption и данным рукопожатия.
pub fn select_transparent_route(
    init: &ClientInit,
    endpoint: Option<&crate::dc_map::DcEndpoint>,
) -> TransparentSelection {
    let Some(endpoint) = endpoint else {
        return if init.dc.is_none() {
            TransparentSelection::DirectTcp {
                dc: 0,
                is_media: init.is_media,
            }
        } else {
            TransparentSelection::Reject
        };
    };
    let is_media = init.is_media || endpoint.media_only;
    if init.used_official_secret || endpoint.cdn || endpoint.tcpo_only {
        TransparentSelection::DirectTcp {
            dc: endpoint.id,
            is_media,
        }
    } else {
        TransparentSelection::Wss {
            dc: endpoint.id,
            is_media,
        }
    }
}

/// Проверить исходный порт по списку общей политики перехвата.
pub fn supports_destination_port(port: u16, configured_ports: &[u16]) -> bool {
    port != 0 && port != 80 && configured_ports.contains(&port)
}

/// C `tg_listener_is_self_dial_addr`: порт 80/0 и непубличный адрес.
pub fn is_self_dial_destination(destination: std::net::SocketAddr) -> bool {
    destination.port() == 0
        || destination.port() == 80
        || !crate::dc_map::is_public_address(destination.ip())
}

/// C `destination_allowed`: лимиты политики, порт, CIDR и self-dial.
pub fn destination_allowed(
    destination: std::net::SocketAddr,
    allowed_ports: &[u16],
    allowed_cidrs: &[String],
) -> bool {
    !allowed_ports.is_empty()
        && allowed_ports.len() <= 32
        && !allowed_cidrs.is_empty()
        && allowed_cidrs.len() <= 64
        && supports_destination_port(destination.port(), allowed_ports)
        && is_telegram_destination(destination.ip(), allowed_cidrs)
        && !is_self_dial_destination(destination)
}

/// Проверить исходный IP по CIDR общей политики перехвата.
pub fn is_telegram_destination(ip: IpAddr, cidrs: &[String]) -> bool {
    cidrs.iter().any(|cidr| cidr_contains(cidr, ip))
}

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let (network_text, prefix_text) = cidr.split_once('/').unwrap_or((cidr, ""));
    let Ok(network) = network_text.parse::<IpAddr>() else {
        return false;
    };
    let prefix = if prefix_text.is_empty() {
        match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    } else if let Ok(prefix) = prefix_text.parse::<u8>() {
        prefix
    } else {
        return false;
    };

    match (network, ip) {
        (IpAddr::V4(network), IpAddr::V4(ip)) if prefix <= 32 => {
            prefix_matches(&ip.octets(), &network.octets(), prefix)
        }
        (IpAddr::V6(network), IpAddr::V6(ip)) if prefix <= 128 => {
            prefix_matches(&ip.octets(), &network.octets(), prefix)
        }
        _ => false,
    }
}

fn prefix_matches(address: &[u8], network: &[u8], prefix: u8) -> bool {
    let full_bytes = usize::from(prefix / 8);
    let remaining_bits = prefix % 8;
    if address[..full_bytes] != network[..full_bytes] {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    let mask = u8::MAX << (8 - remaining_bits);
    address[full_bytes] & mask == network[full_bytes] & mask
}

/// Сохранить исходный порт при выборе TCP fallback-хоста.
pub fn tcp_fallback_target(host: &str, original: SocketAddr) -> (String, u16) {
    (host.to_string(), original.port())
}

pub fn dc_route_for_destination(ip: IpAddr) -> Option<(u32, bool)> {
    crate::config::default_dc_route_for_ip(ip)
}

/// Создать парные потоковые шифры прямого obfuscated2-соединения.
pub fn direct_stream_ciphers(init: &[u8; HANDSHAKE_LEN]) -> (AesCtr256, AesCtr256) {
    let key = &init[8..40];
    let iv = &init[40..56];
    let mut decrypt = make_cipher(key, iv);
    let mut encrypt = make_cipher(key, iv);
    let mut handshake = [0u8; HANDSHAKE_LEN];
    decrypt.apply_keystream(&mut handshake);
    encrypt.apply_keystream(&mut handshake);
    (decrypt, encrypt)
}

/// Получить исходный адрес назначения, сохранённый nftables REDIRECT.
pub fn original_destination(stream: &TcpStream) -> io::Result<SocketAddr> {
    #[cfg(target_os = "linux")]
    {
        let peer = stream.peer_addr()?;
        let mapped_v4 =
            matches!(peer, SocketAddr::V6(addr) if addr.ip().to_ipv4_mapped().is_some());
        if peer.is_ipv4() || mapped_v4 {
            match original_destination_v4(stream) {
                Ok(addr) => Ok(addr.into()),
                Err(v4_error) => original_destination_v6(stream).map_err(|_| v4_error),
            }
        } else {
            original_destination_v6(stream)
                .or_else(|_| original_destination_v4(stream).map(Into::into))
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "для прозрачного режима в Linux требуется SO_ORIGINAL_DST",
        ))
    }
}

#[cfg(target_os = "linux")]
fn original_destination_v4(stream: &TcpStream) -> io::Result<SocketAddrV4> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // Значение SO_ORIGINAL_DST из linux/netfilter_ipv4.h.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            80,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if (addr.sin_family as libc::c_int) != libc::AF_INET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "исходный адрес назначения не является IPv4",
        ));
    }
    Ok(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    ))
}

#[cfg(target_os = "linux")]
fn original_destination_v6(stream: &TcpStream) -> io::Result<SocketAddr> {
    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    // IP6T_SO_ORIGINAL_DST из linux/netfilter_ipv6/ip6_tables.h.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_IPV6,
            80,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if (addr.sin6_family as libc::c_int) != libc::AF_INET6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "исходный адрес назначения не является IPv6",
        ));
    }
    Ok(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(addr.sin6_addr.s6_addr),
        u16::from_be(addr.sin6_port),
        addr.sin6_flowinfo,
        addr.sin6_scope_id,
    )))
}

/// Распознать obfuscated2; DC ID присутствует только в MTProxy-рукопожатии.
pub fn parse_client_init(init: &[u8; HANDSHAKE_LEN]) -> Option<ClientInit> {
    let mut decoded = *init;
    make_cipher(&init[8..40], &init[40..56]).apply_keystream(&mut decoded);
    let proto = ProtoTag::from_bytes(&decoded[PROTO_TAG_POS..PROTO_TAG_POS + 4])?;
    let dc_idx = i16::from_le_bytes([decoded[DC_IDX_POS], decoded[DC_IDX_POS + 1]]);
    let raw_dc = dc_idx.unsigned_abs() as u32;
    Some(ClientInit {
        dc: (1..=999).contains(&raw_dc).then_some(raw_dc),
        is_media: dc_idx < 0,
        proto,
        used_official_secret: false,
    })
}

/// Разобрать рукопожатие, используя только секреты точных официальных DC-опций.
pub fn parse_client_init_with_secrets(
    init: &[u8; HANDSHAKE_LEN],
    secrets: &[Vec<u8>],
) -> Option<ClientInit> {
    if let Some(parsed) = parse_client_init(init) {
        return Some(parsed);
    }
    // C `parse_client_handshake`: больше 16 секретов — отказ, без перебора.
    if secrets.len() > MAX_HANDSHAKE_SECRETS {
        return None;
    }

    let mut parsed: Option<ClientInit> = None;
    for secret in secrets {
        let Some(handshake) = crate::crypto::parse_handshake(init, secret) else {
            continue;
        };
        let candidate = ClientInit {
            dc: (1..=999)
                .contains(&handshake.dc_id)
                .then_some(handshake.dc_id),
            is_media: handshake.is_media,
            proto: handshake.proto,
            used_official_secret: true,
        };
        if let Some(previous) = &parsed {
            if previous.dc != candidate.dc
                || previous.is_media != candidate.is_media
                || previous.proto != candidate.proto
            {
                return None;
            }
        } else {
            parsed = Some(candidate);
        }
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::{ClientInit, TransparentSelection, select_transparent_route};
    use crate::crypto::ProtoTag;
    use crate::dc_map::DcEndpoint;
    use std::net::IpAddr;

    fn endpoint(tcpo_only: bool, cdn: bool, media_only: bool) -> DcEndpoint {
        DcEndpoint {
            id: 2,
            address: "149.154.167.51".parse::<IpAddr>().unwrap(),
            port: 443,
            ipv6: false,
            media_only,
            tcpo_only,
            cdn,
            is_static: true,
            this_port_only: false,
            secret: None,
            last_seen: 1_800_000_000,
        }
    }

    fn init(dc: Option<u32>, is_media: bool, used_official_secret: bool) -> ClientInit {
        ClientInit {
            dc,
            is_media,
            proto: ProtoTag::Intermediate,
            used_official_secret,
        }
    }

    #[test]
    fn official_secret_and_tcpo_only_force_direct_tcp() {
        let listed = endpoint(false, false, false);
        assert_eq!(
            select_transparent_route(&init(Some(2), false, true), Some(&listed)),
            TransparentSelection::DirectTcp {
                dc: 2,
                is_media: false
            }
        );
        let tcpo = endpoint(true, false, true);
        assert_eq!(
            select_transparent_route(&init(Some(2), false, false), Some(&tcpo)),
            TransparentSelection::DirectTcp {
                dc: 2,
                is_media: true
            }
        );
        let cdn = endpoint(false, true, false);
        assert_eq!(
            select_transparent_route(&init(Some(2), false, false), Some(&cdn)),
            TransparentSelection::DirectTcp {
                dc: 2,
                is_media: false
            }
        );
    }

    #[test]
    fn destination_policy_rejects_bad_ports_cidrs_and_self_dial() {
        let ports = [443u16, 5222];
        let cidrs = vec!["149.154.0.0/16".to_string()];
        assert!(super::destination_allowed(
            "149.154.167.51:443".parse().unwrap(),
            &ports,
            &cidrs
        ));
        assert!(!super::destination_allowed(
            "149.154.167.51:80".parse().unwrap(),
            &ports,
            &cidrs
        ));
        assert!(!super::destination_allowed(
            "149.154.167.51:0".parse().unwrap(),
            &[0, 443],
            &cidrs
        ));
        assert!(!super::destination_allowed(
            "8.8.8.8:443".parse().unwrap(),
            &ports,
            &cidrs
        ));
        // CIDR намеренно широкий: self-dial обязан отсечь приватный адрес.
        assert!(!super::destination_allowed(
            "10.0.0.1:443".parse().unwrap(),
            &ports,
            &["0.0.0.0/0".to_string()]
        ));
    }

    #[test]
    fn official_secret_is_reported_and_more_than_16_candidates_reject() {
        let packet: [u8; crate::crypto::HANDSHAKE_LEN] = hex::decode(
            "0001020304050607000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f0001020304050607\
             08090a0b0c0d0e0f7c380b6e418caed2",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let secret = hex::decode("101112131415161718191a1b1c1d1e1f").unwrap();
        let parsed = super::parse_client_init_with_secrets(&packet, &[secret.clone()])
            .expect("секретное рукопожатие");
        assert_eq!(parsed.dc, Some(4));
        assert!(parsed.is_media);
        assert!(parsed.used_official_secret);

        let mut many = vec![secret];
        for index in 0..16u8 {
            many.push(vec![0x40 + index]);
        }
        assert!(
            super::parse_client_init_with_secrets(&packet, &many).is_none(),
            "C отвергает более 16 кандидатов до разбора"
        );
    }

    #[test]
    fn regular_listed_endpoint_uses_wss_and_unknown_hint_is_rejected() {
        let listed = endpoint(false, false, false);
        assert_eq!(
            select_transparent_route(&init(Some(2), false, false), Some(&listed)),
            TransparentSelection::Wss {
                dc: 2,
                is_media: false
            }
        );
        assert_eq!(
            select_transparent_route(&init(Some(4), false, false), None),
            TransparentSelection::Reject
        );
        assert_eq!(
            select_transparent_route(&init(None, true, false), None),
            TransparentSelection::DirectTcp {
                dc: 0,
                is_media: true
            }
        );
    }
}
