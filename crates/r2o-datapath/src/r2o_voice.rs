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
const VOICE_RTP_PROOF_PACKETS: u8 = r2k_core::control::VOICE_RTP_PROOF_MIN_PACKETS;

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
    voice_ssrc: Option<[u8; 4]>,
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
    r2o_idle_timeout: Duration,
}

struct PendingVoiceProof {
    client: Endpoint,
    server: Endpoint,
    proof: PendingVoiceProofKind,
    trial_id: [u8; 16],
    expires: Instant,
    response_confirmed: bool,
    client_ssrc: Option<[u8; 4]>,
    outbound: RtpSequenceProgress,
    inbound: RtpSequenceProgress,
}

#[derive(Clone, Copy)]
enum PendingVoiceProofKind {
    DiscordDiscovery { ssrc: [u8; 4] },
    StunBinding { transaction_id: [u8; 12] },
}

#[derive(Default)]
struct RtpSequenceProgress {
    ssrc: Option<[u8; 4]>,
    last_sequence: Option<u16>,
    packets: u8,
}

impl RtpSequenceProgress {
    fn observe(&mut self, ssrc: [u8; 4], sequence: u16) {
        match (self.ssrc, self.last_sequence) {
            (Some(current_ssrc), Some(last_sequence)) if current_ssrc == ssrc => {
                let advance = sequence.wrapping_sub(last_sequence);
                if advance == 0 || advance >= 0x8000 {
                    return;
                }
                self.last_sequence = Some(sequence);
                self.packets = self.packets.saturating_add(1).min(VOICE_RTP_PROOF_PACKETS);
            }
            _ => {
                self.ssrc = Some(ssrc);
                self.last_sequence = Some(sequence);
                self.packets = 1;
            }
        }
    }
}

struct RtpHeader {
    ssrc: [u8; 4],
    sequence: u16,
}

fn parse_rtp_header(payload: &[u8]) -> Option<RtpHeader> {
    if payload.len() < 12 || payload[0] >> 6 != 2 {
        return None;
    }
    // With RTCP multiplexing, RTP payload types 64–95 overlap RTCP packet types.
    if (64..=95).contains(&(payload[1] & 0x7f)) {
        return None;
    }
    let csrc_count = usize::from(payload[0] & 0x0f);
    let mut header_length = 12_usize.checked_add(csrc_count.checked_mul(4)?)?;
    if header_length > payload.len() {
        return None;
    }
    if payload[0] & 0x10 != 0 {
        let extension = payload.get(header_length..header_length.checked_add(4)?)?;
        let extension_words = usize::from(u16::from_be_bytes([extension[2], extension[3]]));
        header_length = header_length.checked_add(4 + extension_words.checked_mul(4)?)?;
        if header_length > payload.len() {
            return None;
        }
    }
    let padding = if payload[0] & 0x20 != 0 {
        let padding = usize::from(*payload.last()?);
        if padding == 0 {
            return None;
        }
        padding
    } else {
        0
    };
    if padding > payload.len().saturating_sub(header_length)
        || payload.len().saturating_sub(header_length + padding) == 0
    {
        return None;
    }
    Some(RtpHeader {
        ssrc: payload[8..12].try_into().ok()?,
        sequence: u16::from_be_bytes([payload[2], payload[3]]),
    })
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
        let proof = if r2k_core::stun::is_discord_ip_discovery_request(payload) {
            PendingVoiceProofKind::DiscordDiscovery {
                ssrc: payload[4..8]
                    .try_into()
                    .expect("SSRC Discovery имеет 4 байта"),
            }
        } else if r2k_core::stun::is_discord_voice_request(payload, destination.port)
            && r2k_core::stun::is_binding_request(payload)
        {
            let Some(transaction_id) = payload.get(8..20).and_then(|bytes| bytes.try_into().ok())
            else {
                return false;
            };
            PendingVoiceProofKind::StunBinding { transaction_id }
        } else {
            return false;
        };
        let client_ssrc = match proof {
            PendingVoiceProofKind::DiscordDiscovery { ssrc } => Some(ssrc),
            PendingVoiceProofKind::StunBinding { .. } => None,
        };
        let (key, _) = FlowKey::new(source, destination);
        if key.wire_key() != event.key {
            return false;
        }
        self.pending.retain(|_, pending| pending.expires > now);
        if !self.pending.contains_key(&key) && self.pending.len() >= VOICE_TRIAL_LIMIT {
            return false;
        }
        if let Some(pending) = self
            .pending
            .get_mut(&key)
            .filter(|pending| pending.trial_id == event.trial_id && pending.response_confirmed)
        {
            pending.expires = now + VOICE_TRIAL_TTL;
            return true;
        }
        self.pending.insert(
            key,
            PendingVoiceProof {
                client: source,
                server: destination,
                proof,
                trial_id: event.trial_id,
                expires: now + VOICE_TRIAL_TTL,
                response_confirmed: false,
                client_ssrc,
                outbound: RtpSequenceProgress::default(),
                inbound: RtpSequenceProgress::default(),
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
        if self
            .pending
            .get(&key)
            .is_some_and(|pending| pending.expires <= now)
        {
            self.pending.remove(&key);
            return None;
        }
        let pending = self.pending.get_mut(&key)?;
        if pending.response_confirmed {
            return None;
        }
        if source != pending.server || destination != pending.client {
            return None;
        }
        let payload = packet.get(view.udp_payload_range(packet)?)?;
        let proof = match pending.proof {
            PendingVoiceProofKind::DiscordDiscovery { ssrc } => {
                if !r2k_core::stun::is_discord_ip_discovery_response(payload, &ssrc) {
                    return None;
                }
                let mapped_end = payload[8..72].iter().position(|byte| *byte == 0)? + 8;
                let mapped_ip = std::str::from_utf8(&payload[8..mapped_end])
                    .ok()?
                    .parse::<std::net::Ipv4Addr>()
                    .ok()?;
                let mapped_port = u16::from_be_bytes([payload[72], payload[73]]);
                r2k_core::control::R2oVoiceProofKind::DiscordDiscovery {
                    mapped_ip,
                    mapped_port,
                }
            }
            PendingVoiceProofKind::StunBinding { transaction_id } => {
                if !r2k_core::stun::is_binding_response_for(payload, &transaction_id) {
                    return None;
                }
                r2k_core::control::R2oVoiceProofKind::StunBinding
            }
        };
        let event = r2k_core::control::R2oVoiceProofEvent {
            key: key.wire_key(),
            trial_id: pending.trial_id,
            proof,
        };
        pending.response_confirmed = true;
        Some(event)
    }

    /// Учесть принятый NFQUEUE-пакет и подтвердить RTP только при прогрессе в обоих направлениях.
    pub fn observe_forwarded_rtp_packet(
        &mut self,
        packet: &[u8],
        now: Instant,
    ) -> Option<r2k_core::control::R2oVoiceProofEvent> {
        let view = PacketView::parse(packet).filter(|view| {
            view.family == 4 && view.protocol == 17 && view.fragment & 0x3fff == 0
        })?;
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
        if self
            .pending
            .get(&key)
            .is_some_and(|pending| pending.expires <= now)
        {
            self.pending.remove(&key);
            return None;
        }
        let pending = self.pending.get_mut(&key)?;
        if !pending.response_confirmed {
            return None;
        }
        let header = parse_rtp_header(packet.get(view.udp_payload_range(packet)?)?)?;
        if source == pending.client && destination == pending.server {
            if pending
                .client_ssrc
                .is_some_and(|expected| expected != header.ssrc)
            {
                return None;
            }
            pending.client_ssrc.get_or_insert(header.ssrc);
            pending.outbound.observe(header.ssrc, header.sequence);
        } else if source == pending.server && destination == pending.client {
            pending.inbound.observe(header.ssrc, header.sequence);
        } else {
            return None;
        }
        if pending.outbound.packets < VOICE_RTP_PROOF_PACKETS
            || pending.inbound.packets < VOICE_RTP_PROOF_PACKETS
        {
            return None;
        }
        let event = r2k_core::control::R2oVoiceProofEvent {
            key: key.wire_key(),
            trial_id: pending.trial_id,
            proof: r2k_core::control::R2oVoiceProofKind::RtpMedia {
                outbound_packets: pending.outbound.packets,
                inbound_packets: pending.inbound.packets,
            },
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
        Ok(Self {
            flows,
            flow_limit,
            r2o_idle_timeout: VOICE_IDLE,
        })
    }

    /// Настроить срок хранения состояния голосовых UDP-потоков.
    pub fn r2o_set_idle_timeout(&mut self, timeout: Duration) {
        self.r2o_idle_timeout = timeout;
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
        let voice_ssrc = r2k_core::stun::is_discord_ip_discovery_request(payload).then(|| {
            payload[4..8]
                .try_into()
                .expect("Discord Discovery SSRC состоит из четырёх байтов")
        });
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
                voice_ssrc,
                hello: now,
                last_forward: now,
                last_reverse: None,
                last_seen: now,
                forward_after_hello: 0,
                suspected: false,
            });
            if source == flow.client && destination == flow.server {
                if let Some(ssrc) = voice_ssrc {
                    if flow.voice_ssrc.is_some_and(|current| current != ssrc) {
                        flow.voice_ssrc = Some(ssrc);
                        flow.hello = now;
                        flow.last_forward = now;
                        flow.last_reverse = None;
                        flow.last_seen = now;
                        flow.forward_after_hello = 0;
                        flow.suspected = false;
                        return;
                    }
                    flow.voice_ssrc = Some(ssrc);
                }
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
        let mut events = Vec::new();
        if reverse_queue_visible {
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
        }
        self.expire(now);
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
        let idle_timeout = self.r2o_idle_timeout;
        self.flows
            .retain(|_, flow| now.saturating_duration_since(flow.last_seen) < idle_timeout);
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
            r2o_idle_timeout: VOICE_IDLE,
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

    fn rtp_packet(ssrc: [u8; 4], sequence: u16) -> [u8; 16] {
        let mut packet = [0; 16];
        packet[0] = 0x80;
        packet[1] = 0x60;
        packet[2..4].copy_from_slice(&sequence.to_be_bytes());
        packet[4..8].copy_from_slice(&(u32::from(sequence) * 960).to_be_bytes());
        packet[8..12].copy_from_slice(&ssrc);
        packet[12..].copy_from_slice(&[1, 2, 3, 4]);
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
    fn r2o_discord_срок_хранения_состояния_настраивается() {
        let start = Instant::now();
        let mut sessions = R2oVoiceSessions::default();
        sessions.r2o_set_idle_timeout(Duration::from_secs(5));
        let request = discovery_request([1, 2, 3, 4]);
        sessions.observe_packet(
            &packet(
                [192, 0, 2, 10],
                [198, 51, 100, 20],
                50_000,
                50_004,
                &request,
            ),
            start,
        );

        assert_eq!(sessions.expire(start + Duration::from_secs(4)), 0);
        assert_eq!(sessions.expire(start + Duration::from_secs(5)), 1);
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
    fn r2o_discord_проверяет_тишину_до_удаления_по_idle() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut sessions = R2oVoiceSessions::default();
        sessions.r2o_set_idle_timeout(Duration::from_secs(1));
        let request = discovery_request([1, 2, 3, 4]);
        sessions.observe_packet(&packet(client, server, 50_000, 50_004, &request), start);
        sessions.observe_packet(
            &packet(client, server, 50_000, 50_004, b"media"),
            start + Duration::from_millis(100),
        );

        let events = sessions.sweep(start + VOICE_SILENCE, true);
        assert_eq!(events.len(), 1);
        assert!(sessions.is_empty());
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
        assert_eq!(
            proof.proof,
            r2k_core::control::R2oVoiceProofKind::DiscordDiscovery {
                mapped_ip: Ipv4Addr::new(203, 0, 113, 7),
                mapped_port: 52_000,
            }
        );
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
    fn discovery_сам_не_подтверждает_rtp_а_двусторонний_поток_требует_прогресса() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let client_ssrc = [7, 8, 9, 10];
        let mut proofs = R2oVoiceTrialProofs::default();
        assert!(proofs.note_applied(
            &packet(
                client,
                server,
                50_000,
                50_004,
                &discovery_request(client_ssrc),
            ),
            &trial_applied(),
            start,
        ));

        let mut discovery_response = [0; 74];
        discovery_response[..8].copy_from_slice(&[0, 2, 0, 70, 7, 8, 9, 10]);
        discovery_response[8..19].copy_from_slice(b"203.0.113.7");
        discovery_response[72..74].copy_from_slice(&52_000_u16.to_be_bytes());
        let discovery = proofs
            .observe_response(
                &packet(server, client, 50_004, 50_000, &discovery_response),
                start + Duration::from_millis(1),
            )
            .unwrap();
        assert!(matches!(
            discovery.proof,
            r2k_core::control::R2oVoiceProofKind::DiscordDiscovery { .. }
        ));

        let remote_ssrc = [1, 2, 3, 4];
        for (index, sequence) in [u16::MAX - 1, u16::MAX, 0].into_iter().enumerate() {
            assert!(
                proofs
                    .observe_forwarded_rtp_packet(
                        &packet(
                            client,
                            server,
                            50_000,
                            50_004,
                            &rtp_packet(client_ssrc, sequence),
                        ),
                        start + Duration::from_millis(10 + index as u64),
                    )
                    .is_none()
            );
        }
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(
                        server,
                        client,
                        50_004,
                        50_000,
                        &rtp_packet(remote_ssrc, u16::MAX - 1),
                    ),
                    start + Duration::from_millis(20),
                )
                .is_none()
        );
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(
                        server,
                        client,
                        50_004,
                        50_000,
                        &rtp_packet(remote_ssrc, u16::MAX),
                    ),
                    start + Duration::from_millis(21),
                )
                .is_none()
        );
        let rtp = proofs
            .observe_forwarded_rtp_packet(
                &packet(server, client, 50_004, 50_000, &rtp_packet(remote_ssrc, 0)),
                start + Duration::from_millis(22),
            )
            .unwrap();
        assert_eq!(rtp.trial_id, [0x55; 16]);
        assert_eq!(
            rtp.proof,
            r2k_core::control::R2oVoiceProofKind::RtpMedia {
                outbound_packets: 3,
                inbound_packets: 3,
            }
        );
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(client, server, 50_000, 50_004, &rtp_packet(client_ssrc, 4),),
                    start + Duration::from_millis(23),
                )
                .is_none()
        );
    }

    #[test]
    fn rtp_trial_отвергает_чужой_flow_ssrc_malformed_rtcp_и_непродвигающиеся_пакеты() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let client_ssrc = [7, 8, 9, 10];
        let remote_ssrc = [1, 2, 3, 4];
        let mut proofs = R2oVoiceTrialProofs::default();
        assert!(proofs.note_applied(
            &packet(
                client,
                server,
                50_000,
                50_004,
                &discovery_request(client_ssrc),
            ),
            &trial_applied(),
            start,
        ));

        let mut discovery_response = [0; 74];
        discovery_response[..8].copy_from_slice(&[0, 2, 0, 70, 7, 8, 9, 10]);
        discovery_response[8..19].copy_from_slice(b"203.0.113.7");
        discovery_response[72..74].copy_from_slice(&52_000_u16.to_be_bytes());
        assert!(
            proofs
                .observe_response(
                    &packet(server, client, 50_004, 50_000, &discovery_response),
                    start + Duration::from_millis(1),
                )
                .is_some()
        );

        let valid = rtp_packet(client_ssrc, 100);
        let mut malformed = valid;
        malformed[0] = 0x40;
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(client, server, 50_000, 50_004, &malformed),
                    start + Duration::from_millis(2),
                )
                .is_none()
        );
        let mut rtcp_mux_collision = valid;
        rtcp_mux_collision[1] = 72;
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(client, server, 50_000, 50_004, &rtcp_mux_collision),
                    start + Duration::from_millis(3),
                )
                .is_none()
        );
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(client, server, 50_000, 50_004, &valid[..12]),
                    start + Duration::from_millis(4),
                )
                .is_none()
        );
        let mut truncated_csrc = valid[..15].to_vec();
        truncated_csrc[0] |= 1;
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(client, server, 50_000, 50_004, &truncated_csrc),
                    start + Duration::from_millis(4),
                )
                .is_none()
        );
        let mut truncated_extension = valid;
        truncated_extension[0] |= 0x10;
        truncated_extension[14..16].copy_from_slice(&1_u16.to_be_bytes());
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(client, server, 50_000, 50_004, &truncated_extension),
                    start + Duration::from_millis(4),
                )
                .is_none()
        );
        let mut zero_padding = valid;
        zero_padding[0] |= 0x20;
        zero_padding[15] = 0;
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(client, server, 50_000, 50_004, &zero_padding),
                    start + Duration::from_millis(4),
                )
                .is_none()
        );
        let mut excessive_padding = valid;
        excessive_padding[0] |= 0x20;
        excessive_padding[15] = 5;
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(client, server, 50_000, 50_004, &excessive_padding),
                    start + Duration::from_millis(4),
                )
                .is_none()
        );
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(client, server, 50_000, 50_005, &valid),
                    start + Duration::from_millis(5),
                )
                .is_none()
        );
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(
                        client,
                        server,
                        50_000,
                        50_004,
                        &rtp_packet([8, 8, 9, 10], 100),
                    ),
                    start + Duration::from_millis(6),
                )
                .is_none()
        );
        assert_eq!(proofs.pending.values().next().unwrap().outbound.packets, 0);

        for sequence in [100, 100, 99, 101, 101] {
            assert!(
                proofs
                    .observe_forwarded_rtp_packet(
                        &packet(
                            client,
                            server,
                            50_000,
                            50_004,
                            &rtp_packet(client_ssrc, sequence),
                        ),
                        start + Duration::from_millis(u64::from(sequence)),
                    )
                    .is_none()
            );
        }
        assert_eq!(proofs.pending.values().next().unwrap().outbound.packets, 2);
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(
                        client,
                        server,
                        50_000,
                        50_004,
                        &rtp_packet(client_ssrc, 102),
                    ),
                    start + Duration::from_millis(103),
                )
                .is_none()
        );

        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(server, client, 50_004, 50_000, &rtp_packet(remote_ssrc, 1)),
                    start + Duration::from_millis(104),
                )
                .is_none()
        );
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(server, client, 50_004, 50_000, &rtp_packet(remote_ssrc, 1)),
                    start + Duration::from_millis(105),
                )
                .is_none()
        );
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(server, client, 50_004, 50_000, &rtp_packet(remote_ssrc, 0)),
                    start + Duration::from_millis(106),
                )
                .is_none()
        );
        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(server, client, 50_004, 50_000, &rtp_packet(remote_ssrc, 2)),
                    start + Duration::from_millis(107),
                )
                .is_none()
        );
        let proof = proofs
            .observe_forwarded_rtp_packet(
                &packet(server, client, 50_004, 50_000, &rtp_packet(remote_ssrc, 3)),
                start + Duration::from_millis(108),
            )
            .unwrap();
        assert_eq!(
            proof.proof,
            r2k_core::control::R2oVoiceProofKind::RtpMedia {
                outbound_packets: 3,
                inbound_packets: 3,
            }
        );
    }

    #[test]
    fn истёкшая_после_stun_проба_не_подтверждает_rtp() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let transaction_id = [0x75; 12];
        let mut proofs = R2oVoiceTrialProofs::default();
        assert!(proofs.note_applied(
            &packet(
                client,
                server,
                50_000,
                50_004,
                &r2k_core::stun::binding_request(transaction_id),
            ),
            &trial_applied(),
            start,
        ));
        let mut response = [0; 20];
        response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
        response[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
        response[8..].copy_from_slice(&transaction_id);
        assert!(
            proofs
                .observe_response(
                    &packet(server, client, 50_004, 50_000, &response),
                    start + Duration::from_millis(1),
                )
                .is_some()
        );

        assert!(
            proofs
                .observe_forwarded_rtp_packet(
                    &packet(
                        client,
                        server,
                        50_000,
                        50_004,
                        &rtp_packet([7, 8, 9, 10], 1),
                    ),
                    start + super::VOICE_TRIAL_TTL,
                )
                .is_none()
        );
        assert!(proofs.pending.is_empty());
    }

    #[test]
    fn повторное_applied_того_же_trial_продлевает_ожидание_rtp() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let request = r2k_core::stun::binding_request([0x76; 12]);
        let applied_packet = packet(client, server, 50_000, 50_004, &request);
        let mut proofs = R2oVoiceTrialProofs::default();
        assert!(proofs.note_applied(&applied_packet, &trial_applied(), start));
        let mut response = [0; 20];
        response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
        response[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
        response[8..].copy_from_slice(&request[8..20]);
        assert!(
            proofs
                .observe_response(
                    &packet(server, client, 50_004, 50_000, &response),
                    start + Duration::from_millis(1),
                )
                .is_some()
        );

        assert!(proofs.note_applied(
            &applied_packet,
            &trial_applied(),
            start + super::VOICE_TRIAL_TTL - Duration::from_secs(1),
        ));
        let proof_time = start + super::VOICE_TRIAL_TTL + Duration::from_secs(1);
        for sequence in 1..=3 {
            assert!(
                proofs
                    .observe_forwarded_rtp_packet(
                        &packet(
                            client,
                            server,
                            50_000,
                            50_004,
                            &rtp_packet([7, 8, 9, 10], sequence)
                        ),
                        proof_time,
                    )
                    .is_none()
            );
        }
        for sequence in 1..=2 {
            assert!(
                proofs
                    .observe_forwarded_rtp_packet(
                        &packet(
                            server,
                            client,
                            50_004,
                            50_000,
                            &rtp_packet([1, 2, 3, 4], sequence)
                        ),
                        proof_time,
                    )
                    .is_none()
            );
        }
        let proof = proofs
            .observe_forwarded_rtp_packet(
                &packet(server, client, 50_004, 50_000, &rtp_packet([1, 2, 3, 4], 3)),
                proof_time,
            )
            .unwrap();
        assert_eq!(
            proof.proof,
            r2k_core::control::R2oVoiceProofKind::RtpMedia {
                outbound_packets: 3,
                inbound_packets: 3,
            }
        );
    }

    #[test]
    fn stun_создаёт_trial_proof_только_на_медиапорту_и_для_временного_плана() {
        let start = Instant::now();
        let mut event = trial_applied();
        let mut proofs = R2oVoiceTrialProofs::default();
        let request = r2k_core::stun::binding_request([0x61; 12]);
        assert!(!proofs.note_applied(
            &packet([192, 0, 2, 10], [198, 51, 100, 20], 50_000, 3478, &request),
            &event,
            start,
        ));
        assert!(proofs.note_applied(
            &packet(
                [192, 0, 2, 10],
                [198, 51, 100, 20],
                50_000,
                50_004,
                &request,
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
    fn stun_trial_подтверждается_только_ответом_своей_транзакции_и_пятёрки() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let transaction_id = [0x72; 12];
        let request = r2k_core::stun::binding_request(transaction_id);
        let mut proofs = R2oVoiceTrialProofs::default();
        assert!(proofs.note_applied(
            &packet(client, server, 50_000, 50_004, &request),
            &trial_applied(),
            start,
        ));

        let response = |transaction_id: [u8; 12]| {
            let mut response = [0; 20];
            response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
            response[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
            response[8..].copy_from_slice(&transaction_id);
            response
        };
        let wrong_id = response([0x73; 12]);
        assert!(
            proofs
                .observe_response(
                    &packet(server, client, 50_004, 50_000, &wrong_id),
                    start + Duration::from_millis(1),
                )
                .is_none()
        );
        let valid = response(transaction_id);
        assert!(
            proofs
                .observe_response(
                    &packet(server, client, 50_005, 50_000, &valid),
                    start + Duration::from_millis(2),
                )
                .is_none()
        );
        assert!(
            proofs
                .observe_response(
                    &packet(server, client, 50_004, 50_000, &valid[..19]),
                    start + Duration::from_millis(3),
                )
                .is_none()
        );
        let proof = proofs
            .observe_response(
                &packet(server, client, 50_004, 50_000, &valid),
                start + Duration::from_millis(4),
            )
            .unwrap();
        assert_eq!(proof.trial_id, [0x55; 16]);
        assert_eq!(
            proof.proof,
            r2k_core::control::R2oVoiceProofKind::StunBinding
        );
        assert!(
            proofs
                .observe_response(
                    &packet(server, client, 50_004, 50_000, &valid),
                    start + Duration::from_millis(5),
                )
                .is_none()
        );
    }

    #[test]
    fn истёкший_stun_trial_не_подтверждается() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let transaction_id = [0x74; 12];
        let request = r2k_core::stun::binding_request(transaction_id);
        let mut proofs = R2oVoiceTrialProofs::default();
        assert!(proofs.note_applied(
            &packet(client, server, 50_000, 50_004, &request),
            &trial_applied(),
            start,
        ));
        let mut response = [0; 20];
        response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
        response[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
        response[8..].copy_from_slice(&transaction_id);
        assert!(
            proofs
                .observe_response(
                    &packet(server, client, 50_004, 50_000, &response),
                    start + Duration::from_secs(120),
                )
                .is_none()
        );
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

    #[test]
    fn повторное_подключение_с_новым_ssrc_обновляет_то_же_5_tuple() {
        let start = Instant::now();
        let client = [192, 0, 2, 10];
        let server = [198, 51, 100, 20];
        let mut sessions = R2oVoiceSessions::default();

        sessions.observe_packet(
            &packet(
                client,
                server,
                50_000,
                50_004,
                &discovery_request([1, 2, 3, 4]),
            ),
            start,
        );
        sessions.observe_packet(
            &packet(client, server, 50_000, 50_004, b"media"),
            start + Duration::from_millis(100),
        );
        let first = sessions.sweep(start + VOICE_SILENCE, true);
        assert_eq!(first.len(), 1);
        sessions.mark_suspected(&first[0].key);

        sessions.observe_packet(
            &packet(
                client,
                server,
                50_000,
                50_004,
                &discovery_request([1, 2, 3, 4]),
            ),
            start + Duration::from_secs(3),
        );
        sessions.observe_packet(
            &packet(client, server, 50_000, 50_004, b"media"),
            start + Duration::from_millis(3_100),
        );
        assert!(
            sessions
                .sweep(start + Duration::from_millis(5_100), true)
                .is_empty(),
            "повтор Discovery с тем же SSRC остаётся той же подозреваемой сессией"
        );

        sessions.observe_packet(
            &packet(
                client,
                server,
                50_000,
                50_004,
                &discovery_request([5, 6, 7, 8]),
            ),
            start + Duration::from_secs(6),
        );
        sessions.observe_packet(
            &packet(client, server, 50_000, 50_004, b"media"),
            start + Duration::from_millis(6_100),
        );

        let reconnected = sessions.sweep(start + Duration::from_millis(8_100), true);
        assert_eq!(reconnected.len(), 1);
        assert_eq!(reconnected[0].key, first[0].key);
    }
}
