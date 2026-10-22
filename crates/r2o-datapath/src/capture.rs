//! Ограниченная сборка TCP ClientHello по таблице потоков датапата r2o.

use r2k_core::addr::Address;
use r2k_core::control::MAX_DNS_NAME_LEN;
use r2k_core::packet::PacketView;
use std::time::{Duration, Instant};

pub const CAPTURE_BYTES: usize = 4096;
pub const CAPTURE_SLOTS: usize = 64;
pub const CAPTURE_WINDOW: usize = 64;
pub const CAPTURE_TTL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcpFlowKey {
    pub low_address: Address,
    pub high_address: Address,
    pub low_port: u16,
    pub high_port: u16,
}

impl TcpFlowKey {
    /// Создаёт канонический ключ конечных точек, используемый таблицей потоков r2o.
    pub fn from_packet(packet: &[u8]) -> Option<Self> {
        let view = PacketView::parse(packet)?;
        if view.protocol != 6 {
            return None;
        }
        let tcp = view.tcp_segment(packet)?;
        let source = (view.src, tcp.source_port);
        let destination = (view.dst, tcp.destination_port);
        let address_bytes = |address: Address| address.bytes();
        let address_len = if view.family == 4 { 4 } else { 16 };
        let source_bytes = address_bytes(source.0);
        let destination_bytes = address_bytes(destination.0);
        let order = source_bytes[..address_len]
            .cmp(&destination_bytes[..address_len])
            .then_with(|| source.1.cmp(&destination.1));
        let (low, high) = if order.is_le() {
            (source, destination)
        } else {
            (destination, source)
        };
        Some(Self {
            low_address: low.0,
            high_address: high.0,
            low_port: low.1,
            high_port: high.1,
        })
    }

    pub fn wire_key(self) -> [u8; r2k_core::control::KEY_LEN] {
        let mut key = [0; r2k_core::control::KEY_LEN];
        key[0] = self.low_address.family();
        key[1..17].copy_from_slice(&self.low_address.bytes());
        key[17..33].copy_from_slice(&self.high_address.bytes());
        key[33..35].copy_from_slice(&self.low_port.to_be_bytes());
        key[35..37].copy_from_slice(&self.high_port.to_be_bytes());
        key[37] = 6;
        key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpHello {
    pub key: TcpFlowKey,
    pub host: Option<Vec<u8>>,
    pub shape: u8,
    pub r2o_wire_len: Option<usize>,
    pub client_hello: Option<Vec<u8>>,
}

impl TcpHello {
    /// Кодирует наблюдение TCP с формой и длиной TLS-записи.
    pub fn event_body(&self) -> Vec<u8> {
        let mut body = self.key.wire_key().to_vec();
        let host = self.host.as_deref().unwrap_or_default();
        body.push(host.len() as u8);
        body.extend_from_slice(host);
        body.push(self.shape);
        if matches!(
            self.shape,
            r2k_core::control::SHAPE_MODERN
                | r2k_core::control::SHAPE_LEGACY
                | r2k_core::control::SHAPE_ECH_TCP
        ) && let Some(r2o_wire_len) = self
            .r2o_wire_len
            .filter(|length| (5..=4096).contains(length))
        {
            body.extend_from_slice(&(r2o_wire_len as u16).to_be_bytes());
        }
        body
    }

    /// Закодировать точный снимок TCP для повторного измерения слабой привязки.
    pub fn shape_event_body(&self) -> Option<Vec<u8>> {
        let event = r2k_core::control::ClientShapeEvent {
            key: self.key.wire_key(),
            host: self.host.clone()?,
            shape: self.shape,
            client_hello: self.client_hello.clone()?,
        };
        event.event_body()
    }
}

pub fn tcp_http_hello_from_bytes(key: TcpFlowKey, bytes: &[u8]) -> Option<TcpHello> {
    let (host, _) = r2k_core::httpup::request_target(bytes)?;
    Some(TcpHello {
        key,
        host: Some(host),
        shape: r2k_core::control::SHAPE_HTTP,
        r2o_wire_len: None,
        client_hello: None,
    })
}

pub fn tcp_http_hello_from_packet(packet: &[u8]) -> Option<TcpHello> {
    let view = PacketView::parse(packet)?;
    if view.protocol != 6 || view.fragment & 0x3fff != 0 {
        return None;
    }
    let tcp = view.tcp_segment(packet)?;
    if tcp.destination_port != 80 {
        return None;
    }
    let key = TcpFlowKey::from_packet(packet)?;
    tcp_http_hello_from_bytes(key, packet.get(tcp.payload)?)
}

pub fn tcp_hello_from_bytes(key: TcpFlowKey, bytes: &[u8]) -> Option<TcpHello> {
    let tls = r2k_core::tls::parse(bytes);
    if !tls.is_client_hello {
        return None;
    }
    let host = tls
        .sni_range
        .and_then(|range| bytes.get(range))
        .filter(|name| name.len() <= MAX_DNS_NAME_LEN)
        .map(<[u8]>::to_vec);
    let shape = if tls.ech_offer {
        r2k_core::control::SHAPE_ECH_TCP
    } else if tls.is_tls13 {
        r2k_core::control::SHAPE_MODERN
    } else {
        r2k_core::control::SHAPE_LEGACY
    };
    Some(TcpHello {
        key,
        host,
        shape,
        r2o_wire_len: tls.record_end,
        client_hello: tls
            .record_end
            .filter(|length| *length == bytes.len())
            .and_then(|length| bytes.get(..length))
            .map(<[u8]>::to_vec),
    })
}

pub fn tcp_hello_from_packet(packet: &[u8]) -> Option<TcpHello> {
    let view = PacketView::parse(packet)?;
    if view.protocol != 6 || view.fragment & 0x3fff != 0 {
        return None;
    }
    let tcp = view.tcp_segment(packet)?;
    let key = TcpFlowKey::from_packet(packet)?;
    tcp_hello_from_bytes(key, packet.get(tcp.payload)?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicHello {
    pub key: [u8; r2k_core::control::KEY_LEN],
    pub host: Vec<u8>,
    pub snapshot: Option<Vec<u8>>,
}

impl QuicHello {
    /// Кодирует событие наблюдения QUIC Initial версии 22.
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if self.host.len() > MAX_DNS_NAME_LEN {
            return None;
        }
        let mut body = self.key.to_vec();
        body.push(self.host.len() as u8);
        body.extend_from_slice(&self.host);
        body.push(r2k_core::control::SHAPE_QUIC);
        if let Some(snapshot) = &self.snapshot {
            if snapshot.len() > r2k_core::quic_snapshot::R2K_QUIC_SNAPSHOT_MAX_BYTES {
                return None;
            }
            let parsed = r2k_core::quic_snapshot::r2k_quic_snapshot_parse(snapshot)?;
            let snapshot_host =
                r2k_core::quic::r2k_quic_initial_sni_result_from_datagrams(parsed.datagrams())
                    .ok()?;
            if snapshot_host.as_deref() != (!self.host.is_empty()).then_some(self.host.as_slice()) {
                return None;
            }
            body.extend_from_slice(&(snapshot.len() as u16).to_be_bytes());
            body.extend_from_slice(snapshot);
        }
        Some(body)
    }
}

/// Извлекает подтверждённое имя SNI ClientHello из полного UDP/443 Initial.
pub fn quic_hello_from_packet(packet: &[u8]) -> Option<QuicHello> {
    let view = PacketView::parse(packet)?;
    if view.protocol != 17 || view.fragment & 0x3fff != 0 {
        return None;
    }
    let payload = packet.get(view.udp_payload_range(packet)?)?;
    let source_port = read_packet_port(packet, view.l4_offset)?;
    let destination_port = read_packet_port(packet, view.l4_offset.checked_add(2)?)?;
    if destination_port != 443 {
        return None;
    }
    let host = r2k_core::quic::r2k_quic_initial_sni_result_from_datagrams(&[payload])
        .ok()?
        .unwrap_or_default();
    if host.len() > 253 {
        return None;
    }

    let source = (view.src, source_port);
    let destination = (view.dst, destination_port);
    let address_len = if view.family == 4 { 4 } else { 16 };
    let order = source.0.bytes()[..address_len]
        .cmp(&destination.0.bytes()[..address_len])
        .then_with(|| source.1.cmp(&destination.1));
    let (low, high) = if order.is_le() {
        (source, destination)
    } else {
        (destination, source)
    };
    let mut key = [0; r2k_core::control::KEY_LEN];
    key[0] = view.family;
    key[1..17].copy_from_slice(&low.0.bytes());
    key[17..33].copy_from_slice(&high.0.bytes());
    key[33..35].copy_from_slice(&low.1.to_be_bytes());
    key[35..37].copy_from_slice(&high.1.to_be_bytes());
    key[37] = 17;
    let snapshot = r2k_core::quic_snapshot::r2k_quic_snapshot_pack(&[payload])?;
    Some(QuicHello {
        key,
        host,
        snapshot: Some(snapshot),
    })
}

fn read_packet_port(packet: &[u8], offset: usize) -> Option<u16> {
    let bytes = packet.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes(bytes.try_into().ok()?))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureStats {
    pub completed: u64,
    pub rejected: u64,
    pub expired: u64,
    pub full: u64,
    pub tls_completed: u64,
    pub tls_rejected: u64,
    pub tls_expired: u64,
    pub tls_full: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureResult {
    Ignored,
    Incomplete,
    Complete { sequence: u32, bytes: Vec<u8> },
    Rejected,
    Full,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SlotState {
    #[default]
    Free,
    Collecting,
    Rejected,
    Delivered,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum CaptureMode {
    #[default]
    Tls,
    Http,
}

struct CaptureInput<'a> {
    key: TcpFlowKey,
    generation: u64,
    now: Instant,
    sequence: u32,
    anchor: Option<u32>,
    bytes: &'a [u8],
    mode: CaptureMode,
}

struct CaptureSlot {
    key: Option<TcpFlowKey>,
    generation: u64,
    started: Option<Instant>,
    sequence: u32,
    contiguous: usize,
    high: usize,
    state: SlotState,
    mode: CaptureMode,
    bytes: [u8; CAPTURE_BYTES],
    present: [u8; CAPTURE_BYTES / 8],
}

impl Default for CaptureSlot {
    fn default() -> Self {
        Self {
            key: None,
            generation: 0,
            started: None,
            sequence: 0,
            contiguous: 0,
            high: 0,
            state: SlotState::Free,
            mode: CaptureMode::Tls,
            bytes: [0; CAPTURE_BYTES],
            present: [0; CAPTURE_BYTES / 8],
        }
    }
}

impl CaptureSlot {
    fn start(
        &mut self,
        key: TcpFlowKey,
        generation: u64,
        now: Instant,
        sequence: u32,
        mode: CaptureMode,
    ) {
        self.bytes.fill(0);
        self.present.fill(0);
        self.key = Some(key);
        self.generation = generation;
        self.started = Some(now);
        self.sequence = sequence;
        self.contiguous = 0;
        self.high = 0;
        self.state = SlotState::Collecting;
        self.mode = mode;
    }

    fn free(&mut self) {
        self.key = None;
        self.started = None;
        self.state = SlotState::Free;
    }

    fn has_byte(&self, index: usize) -> bool {
        self.present[index / 8] & (1 << (index % 8)) != 0
    }
}

pub struct CaptureTable {
    slots: Vec<CaptureSlot>,
    stats: CaptureStats,
}

impl Default for CaptureTable {
    fn default() -> Self {
        Self {
            slots: (0..CAPTURE_SLOTS).map(|_| CaptureSlot::default()).collect(),
            stats: CaptureStats::default(),
        }
    }
}

impl CaptureTable {
    /// Возвращает длину непрерывной части ожидающего запроса и длину TLS-записи.
    pub(crate) fn r2o_incomplete_summary(
        &self,
        key: TcpFlowKey,
        generation: u64,
    ) -> Option<(usize, Option<usize>)> {
        let slot = self.slots.iter().find(|slot| {
            slot.key == Some(key)
                && slot.generation == generation
                && slot.state == SlotState::Collecting
        })?;
        let declared_record_bytes = (slot.mode == CaptureMode::Tls && slot.contiguous >= 5)
            .then(|| 5 + usize::from(u16::from_be_bytes([slot.bytes[3], slot.bytes[4]])));
        Some((slot.contiguous, declared_record_bytes))
    }

    pub fn feed(
        &mut self,
        key: TcpFlowKey,
        generation: u64,
        now: Instant,
        sequence: u32,
        anchor: Option<u32>,
        bytes: &[u8],
    ) -> CaptureResult {
        self.feed_mode(CaptureInput {
            key,
            generation,
            now,
            sequence,
            anchor,
            bytes,
            mode: CaptureMode::Tls,
        })
    }

    pub fn feed_http(
        &mut self,
        key: TcpFlowKey,
        generation: u64,
        now: Instant,
        sequence: u32,
        anchor: Option<u32>,
        bytes: &[u8],
    ) -> CaptureResult {
        self.feed_mode(CaptureInput {
            key,
            generation,
            now,
            sequence,
            anchor,
            bytes,
            mode: CaptureMode::Http,
        })
    }

    fn feed_mode(&mut self, input: CaptureInput<'_>) -> CaptureResult {
        let CaptureInput {
            key,
            generation,
            now,
            sequence,
            anchor,
            bytes,
            mode,
        } = input;
        if bytes.is_empty() {
            return CaptureResult::Ignored;
        }

        let mut found = None;
        let mut vacant = None;
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.state != SlotState::Free {
                let expired = slot
                    .started
                    .and_then(|started| now.checked_duration_since(started))
                    .is_none_or(|age| age >= CAPTURE_TTL);
                if expired {
                    if slot.state == SlotState::Collecting {
                        self.stats.expired = self.stats.expired.saturating_add(1);
                        if slot.mode == CaptureMode::Tls {
                            self.stats.tls_expired = self.stats.tls_expired.saturating_add(1);
                        }
                    }
                    slot.free();
                }
            }
            if slot.state != SlotState::Free && slot.key == Some(key) {
                if slot.generation == generation && slot.mode == mode {
                    found = Some(index);
                } else {
                    slot.free();
                }
            }
            if slot.state == SlotState::Free && vacant.is_none() {
                vacant = Some(index);
            }
        }

        let anchor = anchor.filter(|anchor| {
            let offset = sequence.wrapping_sub(*anchor);
            (offset as i32) >= 0
                && (offset as usize) < CAPTURE_BYTES
                && bytes.len() <= CAPTURE_BYTES - offset as usize
        });

        let index = if let Some(index) = found {
            index
        } else {
            if anchor.is_none() && mode == CaptureMode::Tls && bytes[0] != 22 {
                return CaptureResult::Ignored;
            }
            let Some(index) = vacant else {
                self.stats.full = self.stats.full.saturating_add(1);
                if mode == CaptureMode::Tls {
                    self.stats.tls_full = self.stats.tls_full.saturating_add(1);
                }
                return CaptureResult::Full;
            };
            let start_sequence = anchor.unwrap_or(sequence);
            self.slots[index].start(key, generation, now, start_sequence, mode);
            index
        };

        let result = {
            let slot = &mut self.slots[index];
            if slot.state != SlotState::Collecting {
                return CaptureResult::Ignored;
            }

            let offset = sequence.wrapping_sub(slot.sequence) as usize;
            if offset >= CAPTURE_BYTES || bytes.len() > CAPTURE_BYTES - offset {
                slot.state = SlotState::Rejected;
                Err(())
            } else {
                for (relative, byte) in bytes.iter().copied().enumerate() {
                    let position = offset + relative;
                    let mask = 1_u8 << (position % 8);
                    let present = &mut slot.present[position / 8];
                    if *present & mask != 0 && slot.bytes[position] != byte {
                        slot.state = SlotState::Rejected;
                        return self.reject_result(mode);
                    }
                    slot.bytes[position] = byte;
                    *present |= mask;
                }
                slot.high = slot.high.max(offset + bytes.len());
                while slot.contiguous < CAPTURE_BYTES && slot.has_byte(slot.contiguous) {
                    slot.contiguous += 1;
                }
                let readiness = match mode {
                    CaptureMode::Tls => tls_ready(&slot.bytes, slot.contiguous, slot.high),
                    CaptureMode::Http => http_ready(&slot.bytes, slot.contiguous, slot.high),
                };
                match readiness {
                    Err(()) => {
                        slot.state = SlotState::Rejected;
                        Err(())
                    }
                    Ok(false) => Ok(None),
                    Ok(true) => {
                        slot.state = SlotState::Delivered;
                        Ok(Some((
                            slot.sequence,
                            slot.bytes[..slot.contiguous].to_vec(),
                        )))
                    }
                }
            }
        };

        match result {
            Err(()) => self.reject_result(mode),
            Ok(None) => CaptureResult::Incomplete,
            Ok(Some((sequence, bytes))) => {
                self.stats.completed = self.stats.completed.saturating_add(1);
                if mode == CaptureMode::Tls {
                    self.stats.tls_completed = self.stats.tls_completed.saturating_add(1);
                }
                CaptureResult::Complete { sequence, bytes }
            }
        }
    }

    pub fn forget(&mut self, key: &TcpFlowKey) {
        for slot in &mut self.slots {
            if slot.state != SlotState::Free && slot.key == Some(*key) {
                slot.free();
            }
        }
    }

    pub const fn stats(&self) -> CaptureStats {
        self.stats
    }

    fn reject_result(&mut self, mode: CaptureMode) -> CaptureResult {
        self.stats.rejected = self.stats.rejected.saturating_add(1);
        if mode == CaptureMode::Tls {
            self.stats.tls_rejected = self.stats.tls_rejected.saturating_add(1);
        }
        CaptureResult::Rejected
    }
}

fn tls_ready(bytes: &[u8; CAPTURE_BYTES], contiguous: usize, high: usize) -> Result<bool, ()> {
    if (contiguous >= 2 && bytes[1] != 3) || (contiguous >= 6 && bytes[5] != 1) {
        return Err(());
    }
    if contiguous < 5 {
        return Ok(false);
    }
    let total = 5 + (usize::from(bytes[3]) << 8) + usize::from(bytes[4]);
    if !(9..=CAPTURE_BYTES).contains(&total) || high > total {
        return Err(());
    }
    if contiguous < 9 {
        return Ok(false);
    }
    let handshake_len =
        (usize::from(bytes[6]) << 16) | (usize::from(bytes[7]) << 8) | usize::from(bytes[8]);
    if handshake_len + 9 != total {
        return Err(());
    }
    Ok(contiguous == total)
}

fn http_ready(bytes: &[u8; CAPTURE_BYTES], contiguous: usize, high: usize) -> Result<bool, ()> {
    if contiguous != high {
        return Ok(false);
    }
    let input = &bytes[..contiguous];
    if r2k_core::httpup::request_host_range(input).is_some() {
        return Ok(true);
    }
    if input.windows(4).any(|window| window == b"\r\n\r\n") || contiguous == CAPTURE_BYTES {
        return Err(());
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::{
        CAPTURE_BYTES, CAPTURE_SLOTS, CAPTURE_TTL, CaptureResult, CaptureTable, TcpFlowKey,
        tcp_hello_from_bytes,
    };
    use r2k_core::addr::Address;
    use r2k_core::control::SHAPE_ECH_TCP;
    use std::time::{Duration, Instant};

    fn key(port: u16) -> TcpFlowKey {
        TcpFlowKey {
            low_address: Address::parse("192.0.2.1").unwrap(),
            high_address: Address::parse("198.51.100.2").unwrap(),
            low_port: port,
            high_port: 443,
        }
    }

    fn hello(length: usize) -> Vec<u8> {
        let mut bytes: Vec<_> = (0..length).map(|index| index as u8).collect();
        bytes[0] = 22;
        bytes[1] = 3;
        bytes[2] = 1;
        bytes[3..5].copy_from_slice(&((length - 5) as u16).to_be_bytes());
        bytes[5] = 1;
        bytes[6] = 0;
        bytes[7] = ((length - 9) >> 8) as u8;
        bytes[8] = (length - 9) as u8;
        bytes
    }

    fn push_extension(extensions: &mut Vec<u8>, kind: u16, bytes: &[u8]) {
        extensions.extend_from_slice(&kind.to_be_bytes());
        extensions.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        extensions.extend_from_slice(bytes);
    }

    fn hello_with_late_ech() -> Vec<u8> {
        let host = b"late-ech.example";
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        server_name.push(0);
        server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
        server_name.extend_from_slice(host);

        let mut extensions = Vec::new();
        push_extension(&mut extensions, 0, &server_name);
        push_extension(&mut extensions, 43, &[2, 3, 4]);
        push_extension(&mut extensions, 21, &vec![0; 1400]);
        push_extension(
            &mut extensions,
            0xfe0d,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0xaa, 0xbb],
        );

        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 1, 1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![1];
        handshake.extend_from_slice(&((body.len() as u32).to_be_bytes()[1..]));
        handshake.extend_from_slice(&body);

        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn ipv4_tcp(source: [u8; 4], destination: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut packet = vec![0; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&sport.to_be_bytes());
        packet[22..24].copy_from_slice(&dport.to_be_bytes());
        packet[32] = 5 << 4;
        packet
    }

    fn ipv6_tcp(source: [u8; 16], destination: [u8; 16], sport: u16, dport: u16) -> Vec<u8> {
        let mut packet = vec![0; 60];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&20_u16.to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
        packet[40..42].copy_from_slice(&sport.to_be_bytes());
        packet[42..44].copy_from_slice(&dport.to_be_bytes());
        packet[52] = 5 << 4;
        packet
    }

    fn complete(result: CaptureResult, sequence: u32, expected: &[u8]) {
        assert_eq!(
            result,
            CaptureResult::Complete {
                sequence,
                bytes: expected.to_vec()
            }
        );
    }

    #[test]
    fn packet_keys_are_canonical_for_both_address_families() {
        let left4 = ipv4_tcp([192, 0, 2, 1], [198, 51, 100, 2], 50000, 443);
        let right4 = ipv4_tcp([198, 51, 100, 2], [192, 0, 2, 1], 443, 50000);
        assert_eq!(
            TcpFlowKey::from_packet(&left4),
            TcpFlowKey::from_packet(&right4)
        );

        let mut source6 = [0; 16];
        source6[0] = 0x20;
        source6[15] = 1;
        let mut destination6 = [0; 16];
        destination6[0] = 0x20;
        destination6[15] = 2;
        let left6 = ipv6_tcp(source6, destination6, 50000, 443);
        let right6 = ipv6_tcp(destination6, source6, 443, 50000);
        assert_eq!(
            TcpFlowKey::from_packet(&left6),
            TcpFlowKey::from_packet(&right6)
        );
        assert_ne!(
            TcpFlowKey::from_packet(&left4),
            TcpFlowKey::from_packet(&left6)
        );
    }

    #[test]
    fn assembles_every_segment_boundary_across_sequence_wrap() {
        let hello = hello(1544);
        let start = Instant::now();
        for cut in 1..hello.len() {
            let mut capture = CaptureTable::default();
            let sequence = u32::MAX - 10;
            assert_eq!(
                capture.feed(key(1234), 1, start, sequence, None, &hello[..cut]),
                CaptureResult::Incomplete
            );
            complete(
                capture.feed(
                    key(1234),
                    1,
                    start + Duration::from_millis(1),
                    sequence.wrapping_add(cut as u32),
                    None,
                    &hello[cut..],
                ),
                sequence,
                &hello,
            );
            assert_eq!(
                capture.feed(
                    key(1234),
                    1,
                    start + Duration::from_millis(2),
                    sequence,
                    None,
                    &hello
                ),
                CaptureResult::Ignored
            );
        }
    }

    #[test]
    fn распознаёт_ech_когда_расширение_приходит_во_втором_tcp_сегменте() {
        let complete_hello = hello_with_late_ech();
        let cut = 1388;
        assert!(complete_hello.len() <= CAPTURE_BYTES);
        assert!(cut < complete_hello.len());

        let start = Instant::now();
        let mut capture = CaptureTable::default();
        assert_eq!(
            capture.feed(key(1234), 1, start, 1000, None, &complete_hello[..cut]),
            CaptureResult::Incomplete
        );
        let CaptureResult::Complete { bytes, .. } = capture.feed(
            key(1234),
            1,
            start + Duration::from_millis(1),
            1000 + cut as u32,
            None,
            &complete_hello[cut..],
        ) else {
            panic!("сегментированный ClientHello не собрался целиком");
        };

        let observed = tcp_hello_from_bytes(key(1234), &bytes).unwrap();
        assert_eq!(observed.host.as_deref(), Some(&b"late-ech.example"[..]));
        assert_eq!(observed.shape, SHAPE_ECH_TCP);
    }

    #[test]
    fn joins_out_of_order_segments_and_identical_overlaps_with_a_syn_anchor() {
        let hello = hello(32);
        let start = Instant::now();
        let mut capture = CaptureTable::default();
        assert_eq!(
            capture.feed(key(1234), 1, start, 116, Some(100), &hello[16..]),
            CaptureResult::Incomplete
        );
        assert_eq!(
            capture.feed(
                key(1234),
                1,
                start + Duration::from_millis(1),
                116,
                Some(100),
                &hello[16..24]
            ),
            CaptureResult::Incomplete
        );
        complete(
            capture.feed(
                key(1234),
                1,
                start + Duration::from_millis(2),
                100,
                Some(100),
                &hello[..16],
            ),
            100,
            &hello,
        );
        assert_eq!(capture.stats().completed, 1);
    }

    #[test]
    fn conflicting_overlap_poisoning_requires_a_new_generation_or_forget() {
        let hello = hello(32);
        let start = Instant::now();
        let mut capture = CaptureTable::default();
        assert_eq!(
            capture.feed(key(1234), 1, start, 100, None, &hello[..20]),
            CaptureResult::Incomplete
        );
        let mut changed = hello[12..24].to_vec();
        changed[3] ^= 1;
        assert_eq!(
            capture.feed(
                key(1234),
                1,
                start + Duration::from_millis(1),
                112,
                None,
                &changed
            ),
            CaptureResult::Rejected
        );
        assert_eq!(capture.stats().rejected, 1);
        assert_eq!(
            capture.feed(key(1234), 1, start, 100, None, &hello),
            CaptureResult::Ignored
        );
        complete(
            capture.feed(key(1234), 2, start, 100, None, &hello),
            100,
            &hello,
        );
        capture.forget(&key(1234));
        complete(
            capture.feed(key(1234), 2, start, 100, None, &hello),
            100,
            &hello,
        );
    }

    #[test]
    fn absolute_ttl_expires_a_capture_despite_retransmissions() {
        let hello = hello(32);
        let start = Instant::now();
        let mut capture = CaptureTable::default();
        assert_eq!(
            capture.feed(key(1234), 1, start, 100, None, &hello[..1]),
            CaptureResult::Incomplete
        );
        assert_eq!(
            capture.feed(
                key(1234),
                1,
                start + CAPTURE_TTL - Duration::from_millis(1),
                100,
                None,
                &hello[..1]
            ),
            CaptureResult::Incomplete
        );
        assert_eq!(
            capture.feed(key(1234), 1, start + CAPTURE_TTL, 101, None, &hello[1..]),
            CaptureResult::Ignored
        );
        assert_eq!(capture.stats().expired, 1);
    }

    #[test]
    fn a_full_table_does_not_evict_an_active_capture() {
        let hello = hello(32);
        let start = Instant::now();
        let mut capture = CaptureTable::default();
        for port in 0..CAPTURE_SLOTS {
            assert_eq!(
                capture.feed(key(1000 + port as u16), 1, start, 100, None, &hello[..1]),
                CaptureResult::Incomplete
            );
        }
        assert_eq!(
            capture.feed(key(2000), 1, start, 100, None, &hello[..1]),
            CaptureResult::Full
        );
        assert_eq!(capture.stats().full, 1);
        complete(
            capture.feed(
                key(1000),
                1,
                start + Duration::from_millis(1),
                101,
                None,
                &hello[1..],
            ),
            100,
            &hello,
        );
        complete(
            capture.feed(key(2000), 1, start + CAPTURE_TTL, 100, None, &hello),
            100,
            &hello,
        );
        assert_eq!(capture.stats().expired, CAPTURE_SLOTS as u64 - 1);
    }

    #[test]
    fn rejects_invalid_single_record_client_hellos_and_ignores_other_data() {
        let start = Instant::now();
        let mut capture = CaptureTable::default();
        let mut malformed = hello(32);
        malformed[1] = 2;
        assert_eq!(
            capture.feed(key(1234), 1, start, 100, None, &malformed),
            CaptureResult::Rejected
        );
        capture.forget(&key(1234));

        malformed = hello(32);
        malformed[5] = 2;
        assert_eq!(
            capture.feed(key(1234), 1, start, 100, None, &malformed),
            CaptureResult::Rejected
        );
        capture.forget(&key(1234));

        malformed = hello(32);
        malformed[8] ^= 1;
        assert_eq!(
            capture.feed(key(1234), 1, start, 100, None, &malformed),
            CaptureResult::Rejected
        );
        capture.forget(&key(1234));

        malformed = hello(CAPTURE_BYTES + 1);
        assert_eq!(
            capture.feed(key(1234), 1, start, 100, None, &malformed),
            CaptureResult::Rejected
        );
        capture.forget(&key(1234));

        let mut trailing = hello(32);
        trailing.push(0);
        assert_eq!(
            capture.feed(key(1234), 1, start, 100, None, &trailing),
            CaptureResult::Rejected
        );
        capture.forget(&key(1234));

        let mut other = hello(32);
        other[0] = 23;
        assert_eq!(
            capture.feed(key(1234), 1, start, 100, None, &other),
            CaptureResult::Ignored
        );
        assert_eq!(
            capture.feed(key(1234), 1, start, 100, None, &[]),
            CaptureResult::Ignored
        );
    }
}
