//! Наблюдение молчания IPv4-потоков Discord voice.

use crate::flow_capacity::R2oFlowCapacity;
use r2k_core::addr::Address;
use r2k_core::control::{KEY_LEN, R2oVoiceSuspectEvent};
use r2k_core::packet::PacketView;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const VOICE_SILENCE: Duration = Duration::from_secs(2);
const VOICE_IDLE: Duration = Duration::from_secs(120);
const VOICE_TRIAL_LIMIT: usize = 1024;
const VOICE_TRIAL_TTL: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Endpoint {
    address: Address,
    port: u16,
}

impl Endpoint {
    fn order_key(self) -> (u8, [u8; 16], u16) {
        (self.address.family(), self.address.bytes(), self.port)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    low: Endpoint,
    high: Endpoint,
}

impl FlowKey {
    fn new(source: Endpoint, destination: Endpoint) -> (Self, bool) {
        if source.order_key() <= destination.order_key() {
            (
                Self {
                    low: source,
                    high: destination,
                },
                true,
            )
        } else {
            (
                Self {
                    low: destination,
                    high: source,
                },
                false,
            )
        }
    }

    fn wire_key(self) -> [u8; KEY_LEN] {
        let mut key = [0; KEY_LEN];
        key[0] = self.low.address.family();
        key[1..17].copy_from_slice(&self.low.address.bytes());
        key[17..33].copy_from_slice(&self.high.address.bytes());
        key[33..35].copy_from_slice(&self.low.port.to_be_bytes());
        key[35..37].copy_from_slice(&self.high.port.to_be_bytes());
        key[37] = 17;
        key
    }
}

struct FlowState {
    client: Endpoint,
    server: Endpoint,
    client_is_low: bool,
    hello: Instant,
    last_forward: Instant,
    last_reverse: Option<Instant>,
    last_seen: Instant,
    forward_after_hello: u32,
    suspected: bool,
}

/// Ограниченное состояние для наблюдения за голосовыми UDP-потоками.
pub struct R2oVoiceSessions {
    flows: HashMap<FlowKey, FlowState>,
    flow_limit: usize,
}

struct PendingVoiceProof {
    client: Endpoint,
    server: Endpoint,
    ssrc: [u8; 4],
    trial_id: [u8; 16],
    expires: Instant,
}

/// Ждёт валидный Discovery-ответ только для успешно исполненного временного плана.
#[derive(Default)]
pub struct R2oVoiceTrialProofs {
    pending: HashMap<FlowKey, PendingVoiceProof>,
}

impl R2oVoiceTrialProofs {
    pub fn note_applied(
        &mut self,
        packet: &[u8],
        event: &r2k_core::control::AppliedEvent,
        now: Instant,
    ) -> bool {
        if event.binding.kind != 2
            || event.binding.family != 4
            || event.binding.shape != r2k_core::control::SHAPE_VOICE
            || !event.binding.temporary
            || event.trial_id.iter().all(|byte| *byte == 0)
        {
            return false;
        }
        let Some(view) =
            PacketView::parse(packet).filter(|view| view.family == 4 && view.protocol == 17)
        else {
            return false;
        };
        let Some(udp) = packet.get(view.l4_offset..view.total_len) else {
            return false;
        };
        if udp.len() < 8 {
            return false;
        }
        let source = Endpoint {
            address: view.src,
            port: u16::from_be_bytes([udp[0], udp[1]]),
        };
        let destination = Endpoint {
            address: view.dst,
            port: u16::from_be_bytes([udp[2], udp[3]]),
        };
        let Some(payload_range) = view.udp_payload_range(packet) else {
            return false;
        };
        let Some(payload) = packet.get(payload_range) else {
            return false;
        };
        if !r2k_core::stun::is_discord_ip_discovery_request(payload) {
            return false;
        }
        let (key, _) = FlowKey::new(source, destination);
        if key.wire_key() != event.key {
            return false;
        }
        self.pending.retain(|_, pending| pending.expires > now);
        if !self.pending.contains_key(&key) && self.pending.len() >= VOICE_TRIAL_LIMIT {
            return false;
        }
        self.pending.insert(
            key,
            PendingVoiceProof {
                client: source,
                server: destination,
                ssrc: payload[4..8]
                    .try_into()
                    .expect("SSRC Discovery имеет 4 байта"),
                trial_id: event.trial_id,
                expires: now + VOICE_TRIAL_TTL,
            },
        );
        true
    }

    pub fn observe_response(
        &mut self,
        packet: &[u8],
        now: Instant,
    ) -> Option<r2k_core::control::R2oVoiceProofEvent> {
        let view =
            PacketView::parse(packet).filter(|view| view.family == 4 && view.protocol == 17)?;
        let udp = packet.get(view.l4_offset..view.total_len)?;
        if udp.len() < 8 {
            return None;
        }
        let source = Endpoint {
            address: view.src,
            port: u16::from_be_bytes([udp[0], udp[1]]),
        };
        let destination = Endpoint {
            address: view.dst,
            port: u16::from_be_bytes([udp[2], udp[3]]),
        };
        let (key, _) = FlowKey::new(source, destination);
        let pending = self.pending.get(&key)?;
        if pending.expires <= now {
            self.pending.remove(&key);
            return None;
        }
        if source != pending.server || destination != pending.client {
            return None;
        }
        let payload = packet.get(view.udp_payload_range(packet)?)?;
        if !r2k_core::stun::is_discord_ip_discovery_response(payload, &pending.ssrc) {
            return None;
        }
        let mapped_end = payload[8..72].iter().position(|byte| *byte == 0)? + 8;
        let mapped_ip = std::str::from_utf8(&payload[8..mapped_end])
            .ok()?
            .parse::<std::net::Ipv4Addr>()
            .ok()?;
        let mapped_port = u16::from_be_bytes([payload[72], payload[73]]);
        let event = r2k_core::control::R2oVoiceProofEvent {
            key: key.wire_key(),
            trial_id: pending.trial_id,
            mapped_ip,
            mapped_port,
        };
        self.pending.remove(&key);
        Some(event)
    }

    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

impl R2oVoiceSessions {
    /// Создать состояние с тем же пределом потоков, что и у UDP-таблицы.
    pub fn try_with_capacity(
        flow_capacity: R2oFlowCapacity,
    ) -> Result<Self, std::collections::TryReserveError> {
        let flow_limit = flow_capacity.limit();
        let mut flows = HashMap::new();
        flows.try_reserve(flow_limit)?;
        Ok(Self { flows, flow_limit })
    }

    /// Запомнить первый Discord IP Discovery или STUN-запрос и движение его потока.
    pub fn observe_packet(&mut self, packet: &[u8], now: Instant) {
        let Some(view) = PacketView::parse(packet).filter(|view| view.protocol == 17) else {
            return;
        };
        if view.family != 4 {
            return;
        }
        let Some(udp) = packet.get(view.l4_offset..view.total_len) else {
            return;
        };
        if udp.len() < 8 {
            return;
        }
        let source = Endpoint {
            address: view.src,
            port: u16::from_be_bytes([udp[0], udp[1]]),
        };
        let destination = Endpoint {
            address: view.dst,
            port: u16::from_be_bytes([udp[2], udp[3]]),
        };
        let Some(payload_range) = view.udp_payload_range(packet) else {
            return;
        };
        let Some(payload) = packet.get(payload_range) else {
            return;
        };
        let (key, client_is_low) = FlowKey::new(source, destination);
        let is_voice_request = r2k_core::stun::is_discord_voice_request(payload, destination.port);

        if is_voice_request {
            let first_request = !self.flows.contains_key(&key);
            if first_request && self.flows.len() >= self.flow_limit {
                return;
            }
            let flow = self.flows.entry(key).or_insert_with(|| FlowState {
                client: source,
                server: destination,
                client_is_low,
                hello: now,
                last_forward: now,
                last_reverse: None,
                last_seen: now,
                forward_after_hello: 0,
                suspected: false,
            });
            if source == flow.client && destination == flow.server {
                if !first_request {
                    flow.forward_after_hello = flow.forward_after_hello.saturating_add(1);
                }
                flow.last_forward = now;
                flow.last_seen = now;
            }
            return;
        }

        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };
        if source == flow.client && destination == flow.server {
            flow.forward_after_hello = flow.forward_after_hello.saturating_add(1);
            flow.last_forward = now;
        } else if source == flow.server && destination == flow.client {
            flow.last_reverse = Some(now);
        } else {
            return;
        }
        flow.last_seen = now;
    }

    /// Выдать одно подозрение после наблюдаемого обратного пути и истёкшего окна молчания.
    pub fn sweep(
        &mut self,
        now: Instant,
        reverse_queue_visible: bool,
    ) -> Vec<R2oVoiceSuspectEvent> {
        self.expire(now);
        if !reverse_queue_visible {
            return Vec::new();
        }
        let mut events = Vec::new();
        for (key, flow) in &mut self.flows {
            if flow.suspected
                || flow.forward_after_hello == 0
                || now.saturating_duration_since(flow.hello) < VOICE_SILENCE
                || flow
                    .last_reverse
                    .is_some_and(|last_reverse| last_reverse >= flow.last_forward)
            {
                continue;
            }
            events.push(R2oVoiceSuspectEvent {
                key: key.wire_key(),
                client_is_low: flow.client_is_low,
            });
        }
        events
    }

    /// Отметить событие отправленным только после успешной передачи контроллеру.
    pub fn mark_suspected(&mut self, key: &[u8; KEY_LEN]) {
        if let Some((_, flow)) = self
            .flows
            .iter_mut()
            .find(|(flow_key, _)| flow_key.wire_key() == *key)
        {
            flow.suspected = true;
        }
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.flows.len();
        self.flows
            .retain(|_, flow| now.saturating_duration_since(flow.last_seen) < VOICE_IDLE);
        before - self.flows.len()
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

impl Default for R2oVoiceSessions {
    fn default() -> Self {
        Self {
            flows: HashMap::new(),
            flow_limit: R2oFlowCapacity::default().limit(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{R2oVoiceSessions, R2oVoiceTrialProofs, VOICE_SILENCE};
    use crate::flow_capacity::R2oFlowCapacity;
    use r2k_core::control::{BindingContext, decode_r2o_voice_suspect};
    use r2k_core::stun::is_discord_ip_discovery_request;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    fn packet(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        body: &[u8],
    ) -> Vec<u8> {
        let total = 20 + 8 + body.len();
        let mut packet = vec![0; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&((8 + body.len()) as u16).to_be_bytes());
        packet[28..].copy_from_slice(body);
        packet
    }

    fn discovery_request(ssrc: [u8; 4]) -> [u8; 74] {
        let mut packet = [0; 74];
        packet[..4].copy_from_slice(&[0, 1, 0, 70]);
        packet[4..8].copy_from_slice(&ssrc);
        packet
    }

    fn trial_applied() -> r2k_core::control::AppliedEvent {
        let mut key = [0; r2k_core::control::KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 20]);
        key[33..35].copy_from_slice(&50_000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&50_004_u16.to_be_bytes());
        key[37] = 17;
        r2k_core::control::AppliedEvent {
            key,
            plan_id: [1; 16],
            trial_id: [0x55; 16],
            execution_id: 42,
            binding: BindingContext {
                generation: 9,
                kind: 2,
                family: 4,
                shape: r2k_core::control::SHAPE_VOICE,
                temporary: true,
                epoch: [0x11; 16],
            },
        }
    }

    fn event_packet(event: &r2k_core::control::R2oVoiceSuspectEvent) -> r2k_core::control::Frame {
        r2k_core::control::Frame {
            kind: r2k_core::control::EVENT_R2O_VOICE_SUSPECT,
            body: event.event_body().unwrap(),
        }
    }

    #[test]
    fn discord_учёт_не_превышает_порог_ёмкости_udp_таблицы() {
        let now = Instant::now();
        let limit = R2oFlowCapacity::default().limit();
        let mut sessions = R2oVoiceSessions::default();
        let request = discovery_request([1, 2, 3, 4]);
        for offset in 0..=limit {
            sessions.observe_packet(
                &packet(
                    [192, 0, 2, 10],
                    [198, 51, 100, 20],
                    40_000 + offset as u16,
                    50_004,
                    &request,
                ),
                now,
            );
        }
        assert_eq!(sessions.len(), limit);
    }

    #[test]
    fn discord_учёт_поддерживает_увеличенную_настройку_ёмкости() {
        let now = Instant::now();
        let capacity = R2oFlowCapacity::from_requested(4096).unwrap();
        let mut sessions = R2oVoiceSessions::try_with_capacity(capacity).unwrap();
        let request = discovery_request([1, 2, 3, 4]);
        for offset in 0..2049 {
            sessions.observe_packet(
                &packet(
                    [192, 0, 2, 10],
                    [198, 51, 100, 20],
                    40_000 + offset as u16,
                    50_004,
                    &request,
                ),
                now,
            );
        }
        assert_eq!(sessions.len(), 2049);
    }

    #[test]
    fn голосовое_подозрение_требует_пакет_клиента_и_видимость_ответов() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut sessions = R2oVoiceSessions::default();
        let request = discovery_request([1, 2, 3, 4]);
        assert!(is_discord_ip_discovery_request(&request));
        sessions.observe_packet(&packet(client, server, 50000, 50004, &request), start);
        assert!(sessions.sweep(start + VOICE_SILENCE, true).is_empty());
        sessions.observe_packet(
            &packet(client, server, 50000, 50004, b"media"),
            start + Duration::from_millis(100),
        );
        assert!(sessions.sweep(start + VOICE_SILENCE, false).is_empty());
        let events = sessions.sweep(start + VOICE_SILENCE, true);
        assert_eq!(events.len(), 1);
        let decoded = decode_r2o_voice_suspect(&event_packet(&events[0])).unwrap();
        assert!(decoded.client_is_low);
        assert_eq!(decoded.key[0], 4);
        assert_eq!(
            Ipv4Addr::new(
                decoded.key[1],
                decoded.key[2],
                decoded.key[3],
                decoded.key[4]
            ),
            Ipv4Addr::from(client)
        );
        sessions.mark_suspected(&decoded.key);
        assert!(
            sessions
                .sweep(start + VOICE_SILENCE + Duration::from_secs(1), true)
                .is_empty()
        );
    }

    #[test]
    fn ответ_после_последнего_пакета_клиента_снимает_подозрение() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut sessions = R2oVoiceSessions::default();
        sessions.observe_packet(
            &packet(
                client,
                server,
                50000,
                50004,
                &discovery_request([1, 2, 3, 4]),
            ),
            start,
        );
        sessions.observe_packet(
            &packet(client, server, 50000, 50004, b"media"),
            start + Duration::from_millis(100),
        );
        sessions.observe_packet(
            &packet(server, client, 50004, 50000, b"reply"),
            start + Duration::from_millis(200),
        );
        assert!(sessions.sweep(start + VOICE_SILENCE, true).is_empty());
    }

    #[test]
    fn временный_план_подтверждается_только_ответом_для_своего_ssrc() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let ssrc = [7, 8, 9, 10];
        let mut proofs = R2oVoiceTrialProofs::default();
        let request = discovery_request(ssrc);
        let sent = packet(client, server, 50_000, 50_004, &request);
        assert!(proofs.note_applied(&sent, &trial_applied(), start));
        assert!(
            proofs
                .observe_response(&sent, start + Duration::from_millis(1))
                .is_none()
        );

        let mut wrong_response = [0; 74];
        wrong_response[..8].copy_from_slice(&[0, 2, 0, 70, 1, 2, 3, 4]);
        wrong_response[8..19].copy_from_slice(b"203.0.113.7");
        wrong_response[72..74].copy_from_slice(&52_000_u16.to_be_bytes());
        assert!(
            proofs
                .observe_response(
                    &packet(server, client, 50_004, 50_000, &wrong_response),
                    start + Duration::from_millis(2),
                )
                .is_none()
        );

        wrong_response[4..8].copy_from_slice(&ssrc);
        let proof = proofs
            .observe_response(
                &packet(server, client, 50_004, 50_000, &wrong_response),
                start + Duration::from_millis(3),
            )
            .unwrap();
        assert_eq!(proof.trial_id, [0x55; 16]);
        assert_eq!(proof.mapped_ip, Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(proof.mapped_port, 52_000);
        assert!(
            proofs
                .observe_response(
                    &packet(server, client, 50_004, 50_000, &wrong_response),
                    start + Duration::from_millis(3),
                )
                .is_none()
        );
    }

    #[test]
    fn обычный_stun_и_постоянный_план_не_создают_trial_proof() {
        let start = Instant::now();
        let mut event = trial_applied();
        let mut proofs = R2oVoiceTrialProofs::default();
        let mut request = vec![0; 20];
        request[..8].copy_from_slice(&[0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
        assert!(!proofs.note_applied(
            &packet(
                [192, 0, 2, 10],
                [198, 51, 100, 20],
                50_000,
                50_004,
                &request
            ),
            &event,
            start,
        ));
        event.binding.temporary = false;
        assert!(!proofs.note_applied(
            &packet(
                [192, 0, 2, 10],
                [198, 51, 100, 20],
                50_000,
                50_004,
                &discovery_request([1, 2, 3, 4]),
            ),
            &event,
            start,
        ));
    }

    #[test]
    fn ipv6_и_обычный_udp_не_создают_голосовой_поток() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut sessions = R2oVoiceSessions::default();
        sessions.observe_packet(&packet(client, server, 50000, 50004, b"ordinary"), start);
        assert_eq!(sessions.len(), 0);
        assert!(
            sessions
                .sweep(start + Duration::from_secs(3), true)
                .is_empty()
        );
    }

    #[test]
    fn повторный_discovery_запрос_считается_пакетом_клиента() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let request = discovery_request([1, 2, 3, 4]);
        let mut sessions = R2oVoiceSessions::default();
        sessions.observe_packet(&packet(client, server, 50000, 50004, &request), start);
        sessions.observe_packet(
            &packet(client, server, 50000, 50004, &request),
            start + Duration::from_millis(100),
        );
        assert_eq!(sessions.sweep(start + VOICE_SILENCE, true).len(), 1);
    }

    #[test]
    fn смена_discord_endpoint_создаёт_отдельное_подозрение() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let mut sessions = R2oVoiceSessions::default();
        let request = discovery_request([1, 2, 3, 4]);

        sessions.observe_packet(
            &packet(client, [198, 51, 100, 20], 50_000, 50_004, &request),
            start,
        );
        sessions.observe_packet(
            &packet(client, [198, 51, 100, 20], 50_000, 50_004, b"media"),
            start + Duration::from_millis(100),
        );
        let first = sessions.sweep(start + VOICE_SILENCE, true);
        assert_eq!(first.len(), 1);
        sessions.mark_suspected(&first[0].key);

        sessions.observe_packet(
            &packet(client, [198, 51, 100, 21], 50_000, 50_005, &request),
            start + Duration::from_secs(3),
        );
        sessions.observe_packet(
            &packet(client, [198, 51, 100, 21], 50_000, 50_005, b"media"),
            start + Duration::from_millis(3_100),
        );

        let changed = sessions.sweep(start + Duration::from_millis(5_100), true);
        assert_eq!(changed.len(), 1);
        assert_ne!(changed[0].key, first[0].key);
        assert_eq!(&changed[0].key[17..21], &[198, 51, 100, 21]);
        assert_eq!(&changed[0].key[35..37], &50_005_u16.to_be_bytes());
    }

    #[test]
    fn повторное_подключение_с_новым_клиентским_портом_создаёт_новый_поток() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut sessions = R2oVoiceSessions::default();
        let request = discovery_request([1, 2, 3, 4]);

        sessions.observe_packet(&packet(client, server, 50_000, 50_004, &request), start);
        sessions.observe_packet(
            &packet(client, server, 50_000, 50_004, b"media"),
            start + Duration::from_millis(100),
        );
        let first = sessions.sweep(start + VOICE_SILENCE, true);
        assert_eq!(first.len(), 1);
        sessions.mark_suspected(&first[0].key);

        sessions.observe_packet(
            &packet(client, server, 50_001, 50_004, &request),
            start + Duration::from_secs(3),
        );
        sessions.observe_packet(
            &packet(client, server, 50_001, 50_004, b"media"),
            start + Duration::from_millis(3_100),
        );

        let reconnected = sessions.sweep(start + Duration::from_millis(5_100), true);
        assert_eq!(reconnected.len(), 1);
        assert_ne!(reconnected[0].key, first[0].key);
        assert_eq!(&reconnected[0].key[33..35], &50_001_u16.to_be_bytes());
    }
}
