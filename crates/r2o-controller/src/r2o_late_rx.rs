use crate::{discovery::DiscoveryTarget, fetch::FetchOptions};
use r2k_core::control::{
    HelloEvent, R2oTcpFinRetryEvent, R2oTcpRstAfterAppEvent, R2oTcpStallEvent,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

const R2O_LATE_RX_CACHE_CAPACITY: usize = 128;
const R2O_LATE_RX_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

pub struct R2oLateRxInput {
    pub options: FetchOptions,
    pub discovery_target: Option<DiscoveryTarget>,
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
                r2k_core::control::SHAPE_MODERN | r2k_core::control::SHAPE_LEGACY
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

    pub fn take_for_tcp_stall(
        &mut self,
        event: &R2oTcpStallEvent,
        mark: Option<u32>,
        now: Instant,
    ) -> Option<R2oLateRxInput> {
        self.take_for_flow(&event.key, event.client_is_low, mark, now)
    }

    pub fn take_for_fin_retry(
        &mut self,
        event: &R2oTcpFinRetryEvent,
        mark: Option<u32>,
        now: Instant,
    ) -> Option<R2oLateRxInput> {
        if event.planned {
            return None;
        }
        self.take_for_flow(&event.key, event.client_is_low, mark, now)
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
        if hello.key != *key || now.saturating_duration_since(captured) >= R2O_LATE_RX_CACHE_TTL {
            return None;
        }
        let family = hello.key[0];
        let (address, port_bytes) = if client_is_low {
            (&hello.key[17..], &hello.key[35..37])
        } else {
            (&hello.key[1..], &hello.key[33..35])
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
        if port == 0 || port == 80 {
            return None;
        }
        let host = std::str::from_utf8(hello.host.as_deref()?).ok()?.to_owned();
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
        })
    }

    fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, (_, captured)| {
            now.saturating_duration_since(*captured) < R2O_LATE_RX_CACHE_TTL
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{R2O_LATE_RX_CACHE_CAPACITY, R2oLateRxCache};
    use r2k_core::control::{
        HelloEvent, R2oTcpFinRetryEvent, R2oTcpRstAfterAppEvent, R2oTcpStallEvent, SHAPE_LEGACY,
        SHAPE_MODERN,
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
        };

        let input = cache.take_for_rst(&reset, None, now).unwrap();

        assert_eq!(input.options.name, "example.com");
        assert_eq!(input.options.ip.unwrap().to_string(), "198.51.100.9");
        assert_eq!(input.options.port, 443);
        assert_eq!(input.options.wire_len, Some(812));
        assert!(!input.options.tls12);
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
        };

        let input = cache.take_for_rst(&reset, None, now).unwrap();

        assert_eq!(input.options.ip.unwrap().to_string(), "2001:db8::20");
        assert_eq!(input.options.port, 443);
        assert!(input.options.tls12);
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
        };

        let input = cache.take_for_tcp_stall(&event, Some(17), now).unwrap();
        assert_eq!(input.options.name, "example.com");
        assert_eq!(input.options.ip.unwrap().to_string(), "198.51.100.9");
        assert_eq!(input.options.mark, Some(17));
        assert!(input.discovery_target.is_some());
        assert!(cache.take_for_tcp_stall(&event, Some(17), now).is_none());
    }

    #[test]
    fn парная_проверка_fin_retry_разрешена_только_без_плана() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        let hello = hello(SHAPE_MODERN, true, Some(812));
        assert!(cache.capture(&hello, now));

        let planned = R2oTcpFinRetryEvent {
            key: hello.key,
            client_is_low: true,
            planned: true,
        };
        assert!(cache.take_for_fin_retry(&planned, None, now).is_none());

        let unplanned = R2oTcpFinRetryEvent {
            planned: false,
            ..planned
        };
        let input = cache.take_for_fin_retry(&unplanned, None, now).unwrap();
        assert_eq!(input.options.name, "example.com");
        assert_eq!(input.options.wire_len, Some(812));
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
                    },
                    None,
                    now + Duration::from_secs(61),
                )
                .is_none()
        );
    }

    #[test]
    fn кэш_не_принимает_ech_и_события_без_длины_clienthello() {
        let now = Instant::now();
        let mut cache = R2oLateRxCache::default();
        assert!(!cache.capture(
            &hello(r2k_core::control::SHAPE_ECH_TCP, true, Some(812)),
            now
        ));
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
                    },
                    None,
                    now + Duration::from_secs(1),
                )
                .is_none()
        );
        assert_eq!(cache.entries.len(), R2O_LATE_RX_CACHE_CAPACITY);
    }
}
