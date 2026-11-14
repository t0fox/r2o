use crate::{discovery::DiscoveryTarget, fetch::FetchOptions};
use r2k_core::control::{
    HelloEvent, R2oTcpFinRetryEvent, R2oTcpRstAfterAppEvent, R2oTcpSilenceEvent, R2oTcpStallEvent,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

const R2O_LATE_RX_CACHE_CAPACITY: usize = 128;
/// Точный flow-ключ живёт минуту: именно столько D2O считает поздний RST
/// связанным с исходным ClientHello.
const R2O_LATE_RX_EXACT_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// Связь «недавний SNI -> серверный IP» хранится дольше: она нужна только
/// как безопасный fallback, когда точного ClientHello для потока нет.
/// Совпадение проверяется и по IP, и по порту, поэтому смена адреса
/// автоматически отбрасывает устаревшую запись.
const R2O_LATE_RX_FALLBACK_TTL: std::time::Duration = std::time::Duration::from_secs(600);
/// Минимальный отрыв самого свежего имени от второго, чтобы считать
/// привязку к серверному IP однозначной для recheck без полного ClientHello.
const R2O_RECENT_TARGET_GAP: std::time::Duration = std::time::Duration::from_secs(5);

pub struct R2oLateRxInput {
    pub options: FetchOptions,
    pub discovery_target: Option<DiscoveryTarget>,
    pub alternate_path: Option<String>,
}

#[derive(Default)]
pub struct R2oLateRxCache {
    entries: HashMap<[u8; r2k_core::control::KEY_LEN], (HelloEvent, Instant)>,
}

impl R2oLateRxCache {
    /// Сохранить только пригодное TCP ClientHello для короткой парной RX-проверки.
    pub fn capture(&mut self, hello: &HelloEvent, now: Instant) -> bool {
        self.expire(now);
        self.entries.remove(&hello.key);
        let Some(shape) = hello.shape.filter(|shape| {
            matches!(
                *shape,
                r2k_core::control::SHAPE_MODERN
                    | r2k_core::control::SHAPE_LEGACY
                    | r2k_core::control::SHAPE_ECH_TCP
            )
        }) else {
            return false;
        };
        if hello.key[37] != 6 || !matches!(hello.key[0], 4 | 6) {
            return false;
        }
        let Some(wire_len) = hello.r2o_wire_len else {
            return false;
        };
        let Some(raw_host) = hello
            .host
            .as_deref()
            .and_then(|host| std::str::from_utf8(host).ok())
        else {
            return false;
        };
        let Ok(host) = crate::domain::normalize(raw_host) else {
            return false;
        };
        let validation = FetchOptions {
            name: host.clone(),
            ip: None,
            port: 443,
            path: "/".into(),
            deadline: std::time::Duration::from_secs(6),
            tls12: shape == r2k_core::control::SHAPE_LEGACY,
            wire_len: Some(wire_len),
            mark: None,
        };
        if validation.validate().is_err() {
            return false;
        }
        let candidate = HelloEvent {
            key: hello.key,
            host: Some(host.into_bytes()),
            shape: Some(shape),
            r2o_wire_len: Some(wire_len),
            quic_snapshot: None,
            tcp_has_timestamp: hello.tcp_has_timestamp,
        };
        if self.entries.len() >= R2O_LATE_RX_CACHE_CAPACITY
            && !self.entries.contains_key(&candidate.key)
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, captured))| *captured)
                .map(|(key, _)| *key)
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(candidate.key, (candidate, now));
        true
    }

    pub fn take_for_rst(
        &mut self,
        reset: &R2oTcpRstAfterAppEvent,
        mark: Option<u32>,
        now: Instant,
    ) -> Option<R2oLateRxInput> {
        self.take_for_flow(&reset.key, reset.client_is_low, mark, now)
    }

    /// Fallback для RST после TLS app-data, когда точного ClientHello потока
    /// нет. Ищет недавний HelloEvent по серверному IP и порту. Если тому же
    /// endpoint соответствует несколько имён, fallback отказывается угадывать.
    pub fn take_for_rst_fallback(
        &mut self,
        reset: &R2oTcpRstAfterAppEvent,
        mark: Option<u32>,
        now: Instant,
    ) -> Option<R2oLateRxInput> {
        self.expire(now);
        let (family, server_ip, server_port) =
            r2o_server_endpoint(&reset.key, reset.client_is_low)?;
        let mut candidates: HashMap<
            String,
            (Instant, [u8; r2k_core::control::KEY_LEN], HelloEvent),
        > = HashMap::new();
        for (key, (hello, captured)) in self.entries.iter() {
            if now.saturating_duration_since(*captured) >= R2O_LATE_RX_FALLBACK_TTL
                || hello.key[0] != family
                || hello.key[37] != 6
                || !r2o_cached_hello_matches_server(key, server_ip, server_port)
            {
                continue;
            }
            let Some(host) = r2o_cached_hello_host(hello) else {
                continue;
            };
            let candidate = (*captured, *key, hello.clone());
            match candidates.get(&host) {
                Some((seen, _, _)) if *seen >= *captured => {}
                _ => {
                    candidates.insert(host, candidate);
                }
            }
        }
        if candidates.len() != 1 {
            return None;
        }
        let (host, (_, key, hello)) = candidates.into_iter().next()?;
        let mut target = DiscoveryTarget::from_event(&hello)?;
        target.endpoint = std::net::SocketAddr::new(server_ip, server_port).to_string();
        let shape = hello.shape?;
        let options = FetchOptions {
            name: host,
            ip: Some(server_ip),
            port: server_port,
            path: "/".into(),
            deadline: std::time::Duration::from_secs(6),
            tls12: shape == r2k_core::control::SHAPE_LEGACY,
            wire_len: hello.r2o_wire_len,
            mark,
        };
        options.validate().ok()?;
        self.entries.remove(&key);
        Some(R2oLateRxInput {
            discovery_target: Some(target),
            options,
            alternate_path: None,
        })
    }

    pub fn take_for_tcp_stall(
        &mut self,
        event: &R2oTcpStallEvent,
        mark: Option<u32>,
        now: Instant,
    ) -> Option<R2oLateRxInput> {
        self.take_for_flow(&event.key, event.client_is_low, mark, now)
    }

    /// Цель для recheck планового позднего RST, когда полного ClientHello нет.
    /// Берётся самое свежее имя на серверном endpoint, но только если оно
    /// заметно свежее остальных имён на том же IP.
    pub fn recent_target_for_rst(
        &self,
        reset: &R2oTcpRstAfterAppEvent,
        now: Instant,
    ) -> Option<DiscoveryTarget> {
        self.recent_target_for_endpoint(&reset.key, reset.client_is_low, now)
    }

    /// То же для планового зависания TCP.
    pub fn recent_target_for_tcp_stall(
        &self,
        event: &R2oTcpStallEvent,
        now: Instant,
    ) -> Option<DiscoveryTarget> {
        self.recent_target_for_endpoint(&event.key, event.client_is_low, now)
    }

    fn recent_target_for_endpoint(
        &self,
        key: &[u8; r2k_core::control::KEY_LEN],
        client_is_low: bool,
        now: Instant,
    ) -> Option<DiscoveryTarget> {
        let (_, server_ip, server_port) = r2o_server_endpoint(key, client_is_low)?;
        let mut latest: HashMap<String, (Instant, HelloEvent)> = HashMap::new();
        for (entry_key, (hello, captured)) in self.entries.iter() {
            if now.saturating_duration_since(*captured) >= R2O_LATE_RX_FALLBACK_TTL
                || hello.key[0] != key[0]
                || hello.key[37] != 6
                || !r2o_cached_hello_matches_server(entry_key, server_ip, server_port)
            {
                continue;
            }
            let Some(host) = r2o_cached_hello_host(hello) else {
                continue;
            };
            let replace = latest.get(&host).is_none_or(|(seen, _)| *seen < *captured);
            if replace {
                latest.insert(host, (*captured, hello.clone()));
            }
        }
        let mut ordered: Vec<_> = latest.into_values().collect();
        ordered.sort_by(|left, right| right.0.cmp(&left.0));
        let (newest_seen, newest_hello) = ordered.first()?;
        let independent = ordered.len() == 1
            || ordered.get(1).is_some_and(|(second_seen, _)| {
                newest_seen.saturating_duration_since(*second_seen) >= R2O_RECENT_TARGET_GAP
            });
        if !independent {
            return None;
        }
        let mut target = DiscoveryTarget::from_event(newest_hello)?;
        target.endpoint = std::net::SocketAddr::new(server_ip, server_port).to_string();
        Some(target)
    }

    pub fn take_for_fin_retry(
        &mut self,
        event: &R2oTcpFinRetryEvent,
        mark: Option<u32>,
        now: Instant,
    ) -> Option<R2oLateRxInput> {
        self.take_for_flow(&event.key, event.client_is_low, mark, now)
    }

    pub fn discovery_target_for_tcp_silence(
        &mut self,
        event: &R2oTcpSilenceEvent,
        now: Instant,
    ) -> Option<DiscoveryTarget> {
        if !event.planned {
            return None;
        }
        self.expire(now);
        let (hello, captured) = self.entries.get(&event.key)?;
        if hello.key != event.key
            || now.saturating_duration_since(*captured) >= R2O_LATE_RX_EXACT_TTL
        {
            return None;
        }
        DiscoveryTarget::from_event(hello)
    }

    fn take_for_flow(
        &mut self,
        key: &[u8; r2k_core::control::KEY_LEN],
        client_is_low: bool,
        mark: Option<u32>,
        now: Instant,
    ) -> Option<R2oLateRxInput> {
        self.expire(now);
        let (hello, captured) = self.entries.remove(key)?;
        if hello.key != *key || now.saturating_duration_since(captured) >= R2O_LATE_RX_EXACT_TTL {
            return None;
        }
        let (_, ip, port) = r2o_server_endpoint(&hello.key, client_is_low)?;
        let host = r2o_cached_hello_host(&hello)?;
        let discovery_target = DiscoveryTarget::from_event(&hello);
        let options = FetchOptions {
            name: host,
            ip: Some(ip),
            port,
            path: "/".into(),
            deadline: std::time::Duration::from_secs(6),
            tls12: hello.shape == Some(r2k_core::control::SHAPE_LEGACY),
            wire_len: hello.r2o_wire_len,
            mark,
        };
        options.validate().ok()?;
        Some(R2oLateRxInput {
            discovery_target,
            options,
            alternate_path: None,
        })
    }

    fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, (_, captured)| {
            now.saturating_duration_since(*captured) < R2O_LATE_RX_FALLBACK_TTL
        });
    }
}

fn r2o_cached_hello_host(hello: &HelloEvent) -> Option<String> {
    let raw = hello
        .host
        .as_deref()
        .and_then(|host| std::str::from_utf8(host).ok())?;
    crate::domain::normalize(raw).ok()
}

/// Определить серверный конец TCP-потока по ориентации клиента.
fn r2o_server_endpoint(
    key: &[u8; r2k_core::control::KEY_LEN],
    client_is_low: bool,
) -> Option<(u8, IpAddr, u16)> {
    let family = key[0];
    let (address, port_bytes) = if client_is_low {
        (&key[17..], &key[35..37])
    } else {
        (&key[1..], &key[33..35])
    };
    let ip = match family {
        4 => IpAddr::V4(std::net::Ipv4Addr::new(
            address[0], address[1], address[2], address[3],
        )),
        6 => IpAddr::V6(std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(&address[..16]).ok()?,
        )),
        _ => return None,
    };
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    (port != 0 && port != 80).then_some((family, ip, port))
}

/// Совпадает ли любой конец сохранённого HelloEvent с серверным endpoint RST.
/// Клиентская сторона неизвестна, поэтому проверяются оба конца ключа.
fn r2o_cached_hello_matches_server(
    key: &[u8; r2k_core::control::KEY_LEN],
    server_ip: IpAddr,
    server_port: u16,
) -> bool {
    let family = key[0];
    if family != 4 && family != 6 {
        return false;
    }
    let low_port = u16::from_be_bytes([key[33], key[34]]);
    let high_port = u16::from_be_bytes([key[35], key[36]]);
    let matches = |address: &[u8], port: u16| {
        if port != server_port {
            return false;
        }
        match (family, server_ip) {
            (4, IpAddr::V4(ip)) => address.get(..4) == Some(ip.octets().as_slice()),
            (6, IpAddr::V6(ip)) => address.get(..16) == Some(ip.octets().as_slice()),
            _ => false,
        }
    };
    matches(&key[1..], low_port) || matches(&key[17..], high_port)
}

#[cfg(test)]
mod tests {
    use super::{R2O_LATE_RX_CACHE_CAPACITY, R2oLateRxCache};
    use r2k_core::control::{
        HelloEvent, R2oTcpFinRetryEvent, R2oTcpRstAfterAppEvent, R2oTcpSilenceEvent,
        R2oTcpStallEvent, SHAPE_ECH_TCP, SHAPE_LEGACY, SHAPE_MODERN,
    };
    use std::time::{Duration, Instant};

    fn flow_key(client_is_low: bool) -> [u8; r2k_core::control::KEY_LEN] {
        let mut key = [0; r2k_core::control::KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 7]);
        key[17..21].copy_from_slice(&[198, 51, 100, 9]);
        key[33..35].copy_from_slice(&if client_is_low { 52_001u16 } else { 443u16 }.to_be_bytes());
        key[35..37].copy_from_slice(&if client_is_low { 443u16 } else { 52_001u16 }.to_be_bytes());
        key[37] = 6;
        key
    }

    fn hello(shape: u8, client_is_low: bool, wire_len: Option<usize>) -> HelloEvent {
        HelloEvent {
            key: flow_key(client_is_low),
            host: Some(b"Example.COM".to_vec()),
            shape: Some(shape),
            r2o_wire_len: wire_len,
            quic_snapshot: None,
            tcp_has_timestamp: None,
        }
    }

    #[test]
    fn парный_замер_использует_серверный_конец_позднего_rst() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let hello = hello(SHAPE_MODERN, true, Some(812));
        assert!(cache.capture(&hello, now));
        let reset = R2oTcpRstAfterAppEvent {
            key: hello.key,
            client_is_low: true,
            planned: true,
        };

        let input = cache.take_for_rst(&reset, None, now).unwrap();

        assert_eq!(input.options.name, "example.com");
        assert_eq!(input.options.ip.unwrap().to_string(), "198.51.100.9");
        assert_eq!(input.options.port, 443);
        assert_eq!(input.options.wire_len, Some(812));
        assert!(!input.options.tls12);
        assert!(input.alternate_path.is_none());
        assert_eq!(input.discovery_target.unwrap().endpoint, "198.51.100.9:443");
        assert!(cache.take_for_rst(&reset, None, now).is_none());
    }

    #[test]
    fn парный_замер_учитывает_направление_ipv6_и_tls12() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let mut hello = hello(SHAPE_LEGACY, false, Some(701));
        hello.key[0] = 6;
        hello.key[1..17].copy_from_slice(
            &"2001:db8::20"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        hello.key[17..33].copy_from_slice(
            &"2001:db8::30"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        assert!(cache.capture(&hello, now));
        let reset = R2oTcpRstAfterAppEvent {
            key: hello.key,
            client_is_low: false,
            planned: true,
        };

        let input = cache.take_for_rst(&reset, None, now).unwrap();

        assert_eq!(input.options.ip.unwrap().to_string(), "2001:db8::20");
        assert_eq!(input.options.port, 443);
        assert!(input.options.tls12);
    }

    #[test]
    fn rst_fallback_находит_единственный_недавний_sni_по_серверному_ip() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let hello = hello(SHAPE_MODERN, true, Some(812));
        assert!(cache.capture(&hello, now));

        let mut reset_key = hello.key;
        reset_key[33..35].copy_from_slice(&52_002u16.to_be_bytes());
        let reset = R2oTcpRstAfterAppEvent {
            key: reset_key,
            client_is_low: true,
            planned: true,
        };
        assert!(cache.take_for_rst(&reset, None, now).is_none());

        let input = cache.take_for_rst_fallback(&reset, Some(46), now).unwrap();
        assert_eq!(input.options.name, "example.com");
        assert_eq!(input.options.ip.unwrap().to_string(), "198.51.100.9");
        assert_eq!(input.options.port, 443);
        assert_eq!(input.options.wire_len, Some(812));
        assert_eq!(input.options.mark, Some(46));
        assert_eq!(input.discovery_target.unwrap().endpoint, "198.51.100.9:443");
        assert!(cache.take_for_rst_fallback(&reset, None, now).is_none());
    }

    #[test]
    fn rst_fallback_не_угадывает_при_нескольких_sni_на_том_же_ip() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let first = hello(SHAPE_MODERN, true, Some(812));
        assert!(cache.capture(&first, now));
        let mut second = hello(SHAPE_MODERN, true, Some(701));
        second.key[33..35].copy_from_slice(&52_003u16.to_be_bytes());
        second.host = Some(b"other.example".to_vec());
        assert!(cache.capture(&second, now));

        let mut reset_key = first.key;
        reset_key[33..35].copy_from_slice(&52_004u16.to_be_bytes());
        let reset = R2oTcpRstAfterAppEvent {
            key: reset_key,
            client_is_low: true,
            planned: true,
        };
        assert!(
            cache.take_for_rst_fallback(&reset, None, now).is_none(),
            "неоднозначный IP не должен снимать привязку"
        );
    }

    #[test]
    fn rst_fallback_проверяет_порт_и_срок_жизни_связи() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let hello = hello(SHAPE_MODERN, true, Some(812));
        assert!(cache.capture(&hello, now));

        let mut wrong_port = hello.key;
        wrong_port[33..35].copy_from_slice(&52_002u16.to_be_bytes());
        wrong_port[35..37].copy_from_slice(&8443u16.to_be_bytes());
        let reset = R2oTcpRstAfterAppEvent {
            key: wrong_port,
            client_is_low: true,
            planned: true,
        };
        assert!(cache.take_for_rst_fallback(&reset, None, now).is_none());

        let mut right_port = hello.key;
        right_port[33..35].copy_from_slice(&52_002u16.to_be_bytes());
        let reset = R2oTcpRstAfterAppEvent {
            key: right_port,
            client_is_low: true,
            planned: true,
        };
        assert!(
            cache
                .take_for_rst_fallback(&reset, None, now + Duration::from_secs(601))
                .is_none(),
            "связь SNI/IP старше fallback-срока не используется"
        );
    }

    #[test]
    fn rst_fallback_выбирает_самое_свежее_sni_для_recheck_без_clienthello() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let first = hello(SHAPE_MODERN, true, Some(812));
        assert!(cache.capture(&first, now));
        let mut second = hello(SHAPE_ECH_TCP, true, Some(701));
        second.key[33..35].copy_from_slice(&52_003u16.to_be_bytes());
        second.host = Some(b"gateway.example.com".to_vec());
        assert!(cache.capture(&second, now + Duration::from_secs(10)));

        let mut reset_key = first.key;
        reset_key[33..35].copy_from_slice(&52_004u16.to_be_bytes());
        let reset = R2oTcpRstAfterAppEvent {
            key: reset_key,
            client_is_low: true,
            planned: true,
        };
        let target = cache
            .recent_target_for_rst(&reset, now + Duration::from_secs(11))
            .unwrap();
        assert_eq!(target.host, "gateway.example.com");
        assert_eq!(target.endpoint, "198.51.100.9:443");
        assert_eq!(target.shape, SHAPE_ECH_TCP);
    }

    #[test]
    fn rst_fallback_не_выбирает_свежее_sni_при_близких_конкурентах() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let first = hello(SHAPE_MODERN, true, Some(812));
        assert!(cache.capture(&first, now));
        let mut second = hello(SHAPE_MODERN, true, Some(701));
        second.key[33..35].copy_from_slice(&52_003u16.to_be_bytes());
        second.host = Some(b"other.example".to_vec());
        assert!(cache.capture(&second, now + Duration::from_secs(1)));

        let mut reset_key = first.key;
        reset_key[33..35].copy_from_slice(&52_004u16.to_be_bytes());
        let reset = R2oTcpRstAfterAppEvent {
            key: reset_key,
            client_is_low: true,
            planned: true,
        };
        assert!(
            cache
                .recent_target_for_rst(&reset, now + Duration::from_secs(2))
                .is_none()
        );
        assert!(
            cache
                .recent_target_for_rst(&reset, now + Duration::from_secs(601))
                .is_none()
        );
    }

    #[test]
    fn tcp_зависание_забирает_только_свежий_clienthello_того_же_потока() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let hello = hello(SHAPE_MODERN, true, Some(812));
        assert!(cache.capture(&hello, now));
        let event = R2oTcpStallEvent {
            key: hello.key,
            client_is_low: true,
            elapsed_ms: 2_500,
            estimated_packets: 25,
            planned: false,
            server_hello: false,
        };

        let input = cache.take_for_tcp_stall(&event, Some(17), now).unwrap();
        assert_eq!(input.options.name, "example.com");
        assert_eq!(input.options.ip.unwrap().to_string(), "198.51.100.9");
        assert_eq!(input.options.mark, Some(17));
        assert!(input.discovery_target.is_some());
        assert!(cache.take_for_tcp_stall(&event, Some(17), now).is_none());
    }

    #[test]
    fn парная_проверка_fin_retry_поддерживает_обе_формы_исполнения() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let hello = hello(SHAPE_MODERN, true, Some(812));
        assert!(cache.capture(&hello, now));

        let planned = R2oTcpFinRetryEvent {
            key: hello.key,
            client_is_low: true,
            planned: true,
        };
        assert!(cache.take_for_fin_retry(&planned, None, now).is_some());
        assert!(cache.capture(&hello, now));

        let unplanned = R2oTcpFinRetryEvent {
            planned: false,
            ..planned
        };
        let input = cache.take_for_fin_retry(&unplanned, None, now).unwrap();
        assert_eq!(input.options.name, "example.com");
        assert_eq!(input.options.wire_len, Some(812));
    }

    #[test]
    fn молчание_перепроверяет_только_плановый_поток_и_не_забирает_clienthello() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let hello = hello(SHAPE_MODERN, true, Some(812));
        assert!(cache.capture(&hello, now));

        let event = R2oTcpSilenceEvent {
            key: hello.key,
            client_is_low: true,
            planned: false,
            elapsed_ms: 1000,
        };
        assert!(
            cache
                .discovery_target_for_tcp_silence(&event, now)
                .is_none()
        );

        let planned = R2oTcpSilenceEvent {
            planned: true,
            ..event
        };
        let target = cache
            .discovery_target_for_tcp_silence(&planned, now)
            .unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.endpoint, "198.51.100.9:443");
        assert_eq!(
            cache
                .discovery_target_for_tcp_silence(&planned, now)
                .unwrap(),
            target
        );

        let mut foreign = planned.clone();
        foreign.key = flow_key(true);
        foreign.key[4] = 8;
        assert!(
            cache
                .discovery_target_for_tcp_silence(&foreign, now)
                .is_none()
        );
        assert!(
            cache
                .discovery_target_for_tcp_silence(&planned, now + Duration::from_secs(61))
                .is_none()
        );
    }

    #[test]
    fn кэш_отвергает_чужой_rst_и_снимок_старше_минуты() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let hello = hello(SHAPE_MODERN, true, Some(812));
        assert!(cache.capture(&hello, now));
        let mut foreign = flow_key(true);
        foreign[4] = 8;
        assert!(
            cache
                .take_for_rst(
                    &R2oTcpRstAfterAppEvent {
                        key: foreign,
                        client_is_low: true,
                        planned: false,
                    },
                    None,
                    now,
                )
                .is_none()
        );
        assert!(
            cache
                .take_for_rst(
                    &R2oTcpRstAfterAppEvent {
                        key: hello.key,
                        client_is_low: true,
                        planned: false,
                    },
                    None,
                    now + Duration::from_secs(61),
                )
                .is_none()
        );
    }

    #[test]
    fn кэш_принимает_ech_как_tls13_и_отвергает_события_без_длины_clienthello() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let ech = hello(r2k_core::control::SHAPE_ECH_TCP, true, Some(812));
        assert!(cache.capture(&ech, now));
        let input = cache
            .take_for_rst(
                &R2oTcpRstAfterAppEvent {
                    key: ech.key,
                    client_is_low: true,
                    planned: true,
                },
                None,
                now,
            )
            .unwrap();
        assert!(!input.options.tls12);
        assert_eq!(input.options.wire_len, Some(812));
        assert_eq!(
            input.discovery_target.unwrap().shape,
            r2k_core::control::SHAPE_ECH_TCP
        );
        assert!(!cache.capture(&hello(SHAPE_MODERN, true, None), now));
    }

    #[test]
    fn кэш_ограничивает_число_потоков() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let mut first_key = None;
        for entry in 0..=R2O_LATE_RX_CACHE_CAPACITY {
            let mut hello = hello(SHAPE_MODERN, true, Some(812));
            hello.key[4] = entry as u8;
            first_key.get_or_insert(hello.key);
            assert!(cache.capture(&hello, now + Duration::from_millis(entry as u64)));
        }
        assert!(
            cache
                .take_for_rst(
                    &R2oTcpRstAfterAppEvent {
                        key: first_key.unwrap(),
                        client_is_low: true,
                        planned: false,
                    },
                    None,
                    now + Duration::from_secs(1),
                )
                .is_none()
        );
        assert_eq!(cache.entries.len(), R2O_LATE_RX_CACHE_CAPACITY);
    }
}
