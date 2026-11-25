//! Ограниченная сборка TCP ClientHello по таблице потоков датапата r2o.

use r2k_core::addr::Address;
use r2k_core::control::MAX_DNS_NAME_LEN;
use r2k_core::packet::PacketView;
use std::time::{Duration, Instant};

pub const CAPTURE_BYTES: usize = 4096;
pub const CAPTURE_SLOTS: usize = 64;
pub const CAPTURE_WINDOW: usize = 64;
pub const CAPTURE_TTL: Duration = Duration::from_secs(5);
const CAPTURE_BUCKETS: usize = 8;
const _: () = assert!(CAPTURE_SLOTS == u64::BITS as usize && CAPTURE_BYTES <= u16::MAX as usize);

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
    /// Есть ли TCP timestamp option на сегменте ClientHello; runtime заменяет значение на опции SYN.
    pub tcp_has_timestamp: Option<bool>,
    pub tcp_client_is_low: Option<bool>,
    /// Полный набор TCP-опций клиента (C `shape_opts[k]`, не более 40 байт).
    pub tcp_options: Option<Vec<u8>>,
}

impl TcpHello {
    pub(crate) fn note_client_side(&mut self, address: Address, port: u16) {
        if self.host.is_none() && self.client_hello.is_some() {
            self.tcp_client_is_low =
                Some((address, port) == (self.key.low_address, self.key.low_port));
        }
    }

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
            r2k_core::control::append_tcp_hello_metadata(
                &mut body,
                self.tcp_has_timestamp,
                self.tcp_client_is_low,
            );
        }
        body
    }

    /// Закодировать точный снимок TCP для повторного измерения слабой привязки.
    pub fn shape_event_body(&self) -> Option<Vec<u8>> {
        let event = r2k_core::control::ClientShapeEvent {
            key: self.key.wire_key(),
            host: self.host.clone().unwrap_or_default(),
            shape: self.shape,
            client_hello: self.client_hello.clone()?,
            tcp_has_timestamp: self.tcp_has_timestamp,
            tcp_client_is_low: self.tcp_client_is_low,
        };
        event.event_body()
    }
}

pub fn tcp_http_hello_from_bytes(key: TcpFlowKey, bytes: &[u8]) -> Option<TcpHello> {
    let request = r2k_core::httpup::r2o_http_plan_request(bytes)?;
    let host = bytes.get(request.host_range)?.to_vec();
    Some(TcpHello {
        key,
        host: Some(host),
        shape: r2k_core::control::SHAPE_HTTP,
        r2o_wire_len: None,
        client_hello: None,
        tcp_has_timestamp: None,
        tcp_client_is_low: None,
        tcp_options: None,
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
        .filter(|name| !name.is_empty() && name.len() <= MAX_DNS_NAME_LEN)
        .map(<[u8]>::to_vec);
    let record = tls.record_end.and_then(|end| bytes.get(..end));
    // Полный, но повреждённый/слишком длинный SNI не превращает доменную
    // цель в адресную. Неполные сегменты остаются доступны сборщику.
    if host.is_none()
        && record.is_some_and(|record| !r2k_core::control::valid_no_sni_client_hello(record))
    {
        return None;
    }
    let shape = if tls.ech_offer {
        r2k_core::control::SHAPE_ECH_TCP
    } else if tls.is_tls13 {
        r2k_core::control::SHAPE_MODERN
    } else {
        r2k_core::control::SHAPE_LEGACY
    };
    let client_hello = record
        .filter(|record| host.is_none() || record.len() == bytes.len())
        .map(<[u8]>::to_vec);
    Some(TcpHello {
        key,
        host,
        shape,
        r2o_wire_len: tls.record_end,
        client_hello,
        tcp_has_timestamp: None,
        tcp_client_is_low: None,
        tcp_options: None,
    })
}

pub fn tcp_hello_from_packet(packet: &[u8]) -> Option<TcpHello> {
    let view = PacketView::parse(packet)?;
    if view.protocol != 6 || view.fragment & 0x3fff != 0 {
        return None;
    }
    let tcp = view.tcp_segment(packet)?;
    let key = TcpFlowKey::from_packet(packet)?;
    let mut hello = tcp_hello_from_bytes(key, packet.get(tcp.payload)?)?;
    hello.note_client_side(view.src, tcp.source_port);
    let options = packet.get(tcp.options)?;
    hello.tcp_has_timestamp = r2k_core::packet::tcp_timestamp_metadata(options);
    // C `shape_opts[4][40]`: набор опций ограничен 40 байтами.
    hello.tcp_options = Some(options[..options.len().min(40)].to_vec());
    Some(hello)
}

/// Найти TCP timestamp option. Некорректный список опций считается отсутствующим.
pub fn tcp_timestamp_option_present(options: &[u8]) -> bool {
    let mut offset = 0;
    while offset < options.len() {
        match options[offset] {
            0 => return false,
            1 => offset += 1,
            kind => {
                let Some(length) = options.get(offset + 1).copied().map(usize::from) else {
                    return false;
                };
                if length < 2 || offset.saturating_add(length) > options.len() {
                    return false;
                }
                if kind == 8 && length == 10 {
                    return true;
                }
                offset += length;
            }
        }
    }
    false
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicHello {
    pub key: [u8; r2k_core::control::KEY_LEN],
    pub host: Vec<u8>,
    pub snapshot: Option<Vec<u8>>,
    /// C `first_hello`: имя этого потока отдаётся событием впервые. Снимок
    /// может появиться позже (SNI-first неполный ClientHello), и повторять
    /// HELLO тогда нельзя.
    pub r2o_first_hello: bool,
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
    let r2o_first_hello = !host.is_empty();
    Some(QuicHello {
        key,
        host,
        snapshot: Some(snapshot),
        r2o_first_hello,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
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
    visible: bool,
}

struct CaptureSlot {
    key: TcpFlowKey,
    generation: u64,
    started: Instant,
    sequence: u32,
    contiguous: u16,
    high: u16,
    bitmap_dirty: bool,
    state: SlotState,
    mode: CaptureMode,
    visible: bool,
    bytes: [u8; CAPTURE_BYTES],
    present: [u8; CAPTURE_BYTES / 8],
}

impl CaptureSlot {
    fn new(now: Instant) -> Self {
        let unspecified = Address::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        Self {
            key: TcpFlowKey {
                low_address: unspecified,
                high_address: unspecified,
                low_port: 0,
                high_port: 0,
            },
            generation: 0,
            started: now,
            sequence: 0,
            contiguous: 0,
            high: 0,
            bitmap_dirty: false,
            state: SlotState::Rejected,
            mode: CaptureMode::Tls,
            visible: false,
            bytes: [0; CAPTURE_BYTES],
            present: [0; CAPTURE_BYTES / 8],
        }
    }

    fn start(
        &mut self,
        key: TcpFlowKey,
        generation: u64,
        now: Instant,
        sequence: u32,
        mode: CaptureMode,
        visible: bool,
    ) {
        // Readers only use the written prefix. Sparse bytes are read only
        // when their bits are set for the current generation.
        if self.bitmap_dirty {
            self.present[..usize::from(self.high).div_ceil(8)].fill(0);
            self.bitmap_dirty = false;
        }
        self.key = key;
        self.generation = generation;
        self.started = now;
        self.sequence = sequence;
        self.contiguous = 0;
        self.high = 0;
        self.state = SlotState::Collecting;
        self.mode = mode;
        self.visible = visible;
    }

    fn store(&mut self, offset: usize, input: &[u8]) -> bool {
        let contiguous = usize::from(self.contiguous);
        let high = usize::from(self.high);
        let end = offset + input.len();
        if offset == contiguous && contiguous == high {
            self.bytes[offset..end].copy_from_slice(input);
            self.contiguous = end as u16;
            self.high = self.contiguous;
            return true;
        }
        let overlap = contiguous.saturating_sub(offset).min(input.len());
        if self.bytes[offset..offset + overlap] != input[..overlap] {
            return false;
        }
        let start = offset + overlap;
        if start == end {
            return true;
        }
        self.high = self.high.max(end as u16);
        if !self.record_sparse_bits(start, &input[overlap..]) {
            return false;
        }
        self.bytes[start..end].copy_from_slice(&input[overlap..]);
        if start == contiguous {
            let mut prefix = end;
            while prefix < high {
                let bit = prefix % 8;
                let written = (self.present[prefix / 8] >> bit).trailing_ones() as usize;
                prefix += written;
                if written < 8 - bit {
                    break;
                }
            }
            self.contiguous = prefix.min(usize::from(self.high)) as u16;
        }
        true
    }

    #[cold]
    fn record_sparse_bits(&mut self, start: usize, input: &[u8]) -> bool {
        self.bitmap_dirty = true;
        let end = start + input.len();
        let mut cursor = start;
        while cursor < end {
            let bit = cursor % 8;
            let len = (8 - bit).min(end - cursor);
            let mask = (u8::MAX >> (8 - len)) << bit;
            let block = &mut self.present[cursor / 8];
            let mut overlap = (*block & mask) >> bit;
            let relative = cursor - start;
            if *block & mask == mask {
                if self.bytes[cursor..cursor + len] != input[relative..relative + len] {
                    return false;
                }
            } else {
                while overlap != 0 {
                    let index = overlap.trailing_zeros() as usize;
                    if self.bytes[cursor + index] != input[relative + index] {
                        return false;
                    }
                    overlap &= overlap - 1;
                }
            }
            *block |= mask;
            cursor += len;
        }
        true
    }
}

pub struct CaptureTable {
    slots: Vec<CaptureSlot>,
    occupied: u64,
    buckets: [u64; CAPTURE_BUCKETS],
    oldest_start: Instant,
    newest_start: Instant,
    stats: CaptureStats,
}

impl Default for CaptureTable {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            slots: (0..CAPTURE_SLOTS).map(|_| CaptureSlot::new(now)).collect(),
            occupied: 0,
            buckets: [0; CAPTURE_BUCKETS],
            oldest_start: now,
            newest_start: now,
            stats: CaptureStats::default(),
        }
    }
}

impl CaptureTable {
    fn bucket(key: &TcpFlowKey) -> usize {
        let mixed = key.low_port ^ key.high_port.rotate_left(5);
        usize::from(mixed ^ (mixed >> 3) ^ (mixed >> 9)) & (CAPTURE_BUCKETS - 1)
    }

    #[inline(never)]
    fn find(&self, key: &TcpFlowKey) -> Option<usize> {
        let mut candidates = self.buckets[Self::bucket(key)];
        while candidates != 0 {
            let index = candidates.trailing_zeros() as usize;
            if &self.slots[index].key == key {
                return Some(index);
            }
            candidates &= candidates - 1;
        }
        None
    }

    fn free(&mut self, index: usize) {
        let bit = !(1_u64 << index);
        self.buckets[Self::bucket(&self.slots[index].key)] &= bit;
        self.occupied &= bit;
    }

    fn expire(&mut self, now: Instant) {
        if self.occupied == 0
            || (now >= self.newest_start && now.duration_since(self.oldest_start) < CAPTURE_TTL)
        {
            return;
        }
        self.sweep_expired(now);
    }

    #[cold]
    fn sweep_expired(&mut self, now: Instant) {
        self.oldest_start = now;
        self.newest_start = now;
        let mut live = self.occupied;
        while live != 0 {
            let index = live.trailing_zeros() as usize;
            live &= live - 1;
            let slot = &self.slots[index];
            let started = slot.started;
            if now
                .checked_duration_since(started)
                .is_some_and(|age| age < CAPTURE_TTL)
            {
                self.oldest_start = self.oldest_start.min(started);
                continue;
            }
            if slot.state == SlotState::Collecting && slot.visible {
                self.stats.expired = self.stats.expired.saturating_add(1);
                if slot.mode == CaptureMode::Tls {
                    self.stats.tls_expired = self.stats.tls_expired.saturating_add(1);
                }
            }
            self.free(index);
        }
    }

    pub(crate) fn r2o_http_capture_active(&self, key: TcpFlowKey, generation: u64) -> bool {
        self.find(&key).is_some_and(|index| {
            let slot = &self.slots[index];
            slot.generation == generation
                && slot.mode == CaptureMode::Http
                && slot.state == SlotState::Collecting
        })
    }

    /// Возвращает длину непрерывной части ожидающего запроса и длину TLS-записи.
    pub(crate) fn r2o_incomplete_summary(
        &self,
        key: TcpFlowKey,
        generation: u64,
    ) -> Option<(usize, Option<usize>)> {
        let slot = &self.slots[self.find(&key)?];
        if slot.generation != generation || slot.state != SlotState::Collecting {
            return None;
        }
        let declared_record_bytes = (slot.mode == CaptureMode::Tls && slot.contiguous >= 5)
            .then(|| 5 + usize::from(u16::from_be_bytes([slot.bytes[3], slot.bytes[4]])));
        Some((usize::from(slot.contiguous), declared_record_bytes))
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
        self.feed_with_visibility(key, generation, now, sequence, anchor, bytes, true)
    }

    pub(crate) fn feed_with_visibility(
        &mut self,
        key: TcpFlowKey,
        generation: u64,
        now: Instant,
        sequence: u32,
        anchor: Option<u32>,
        bytes: &[u8],
        visible: bool,
    ) -> CaptureResult {
        self.feed_mode(CaptureInput {
            key,
            generation,
            now,
            sequence,
            anchor,
            bytes,
            mode: CaptureMode::Tls,
            visible,
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
        self.feed_http_with_visibility(key, generation, now, sequence, anchor, bytes, true)
    }

    pub(crate) fn feed_http_with_visibility(
        &mut self,
        key: TcpFlowKey,
        generation: u64,
        now: Instant,
        sequence: u32,
        anchor: Option<u32>,
        bytes: &[u8],
        visible: bool,
    ) -> CaptureResult {
        self.feed_mode(CaptureInput {
            key,
            generation,
            now,
            sequence,
            anchor,
            bytes,
            mode: CaptureMode::Http,
            visible,
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
            visible,
        } = input;
        if bytes.is_empty() {
            return CaptureResult::Ignored;
        }

        self.expire(now);
        let found = self.find(&key).filter(|&index| {
            let slot = &self.slots[index];
            if slot.generation == generation && slot.mode == mode {
                true
            } else {
                self.free(index);
                false
            }
        });

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
            let index = (!self.occupied).trailing_zeros() as usize;
            if index == CAPTURE_SLOTS {
                if visible {
                    self.stats.full = self.stats.full.saturating_add(1);
                    if mode == CaptureMode::Tls {
                        self.stats.tls_full = self.stats.tls_full.saturating_add(1);
                    }
                }
                return CaptureResult::Full;
            }
            let start_sequence = anchor.unwrap_or(sequence);
            self.slots[index].start(key, generation, now, start_sequence, mode, visible);
            if self.occupied == 0 {
                self.oldest_start = now;
            }
            self.occupied |= 1_u64 << index;
            self.buckets[Self::bucket(&key)] |= 1_u64 << index;
            self.newest_start = now;
            index
        };
        self.slots[index].visible &= visible;
        let capture_visible = self.slots[index].visible;

        let result = {
            let slot = &mut self.slots[index];
            if slot.state != SlotState::Collecting {
                return CaptureResult::Ignored;
            }

            let offset = sequence.wrapping_sub(slot.sequence) as usize;
            if offset >= CAPTURE_BYTES
                || bytes.len() > CAPTURE_BYTES - offset
                || !slot.store(offset, bytes)
            {
                slot.state = SlotState::Rejected;
                Err(())
            } else {
                let contiguous = usize::from(slot.contiguous);
                let high = usize::from(slot.high);
                let readiness = match mode {
                    CaptureMode::Tls => tls_ready(&slot.bytes, contiguous, high),
                    CaptureMode::Http => http_ready(&slot.bytes, contiguous, high),
                };
                match readiness {
                    Err(()) => {
                        slot.state = SlotState::Rejected;
                        Err(())
                    }
                    Ok(false) => Ok(None),
                    Ok(true) => {
                        slot.state = SlotState::Delivered;
                        Ok(Some((slot.sequence, slot.bytes[..contiguous].to_vec())))
                    }
                }
            }
        };

        match result {
            Err(()) => self.reject_result(mode, capture_visible),
            Ok(None) => CaptureResult::Incomplete,
            Ok(Some((sequence, bytes))) => {
                if capture_visible {
                    self.stats.completed = self.stats.completed.saturating_add(1);
                    if mode == CaptureMode::Tls {
                        self.stats.tls_completed = self.stats.tls_completed.saturating_add(1);
                    }
                }
                CaptureResult::Complete { sequence, bytes }
            }
        }
    }

    pub fn forget(&mut self, key: &TcpFlowKey) {
        if let Some(index) = self.find(key) {
            self.free(index);
        }
    }

    pub const fn stats(&self) -> CaptureStats {
        self.stats
    }

    fn reject_result(&mut self, mode: CaptureMode, visible: bool) -> CaptureResult {
        if visible {
            self.stats.rejected = self.stats.rejected.saturating_add(1);
            if mode == CaptureMode::Tls {
                self.stats.tls_rejected = self.stats.tls_rejected.saturating_add(1);
            }
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
    // C `http_ready` (`hold.c:93-100`): готовность только при полном
    // непрерывном префиксе; полный заголовок без имени — отказ.
    if contiguous != high {
        return Ok(false);
    }
    let input = &bytes[..contiguous];
    if r2k_core::httpup::request_host_range(input).is_some() {
        return Ok(true);
    }
    if input.windows(4).any(|window| window == b"\r\n\r\n") {
        return Err(());
    }
    Ok(false)
}

/// C `http_ready` для C/Rust differential: тот же tri-state без побочных
/// эффектов. Возвращает 1 — готово, 0 — ждать, -1 — отказ.
pub fn r2o_http_ready_trace(bytes: &[u8], high: usize) -> i32 {
    let mut buffer = [0_u8; CAPTURE_BYTES];
    let Some(target) = buffer.get_mut(..bytes.len()) else {
        return -1;
    };
    target.copy_from_slice(bytes);
    match http_ready(&buffer, bytes.len(), high) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(()) => -1,
    }
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

    fn client_hello_with_extensions(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        record.push(1);
        record.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn no_sni_packet_capture_preserves_complete_hello_and_alpn() {
        let mut extensions = Vec::new();
        push_extension(&mut extensions, 43, &[2, 3, 4]);
        push_extension(&mut extensions, 16, &[0, 3, 2, b'h', b'2']);
        let record = client_hello_with_extensions(&extensions);

        for mut packet in [
            ipv4_tcp([192, 0, 2, 1], [198, 51, 100, 2], 40_000, 8443),
            ipv6_tcp(
                "2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
                "2001:db8::2"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
                40_000,
                8443,
            ),
        ] {
            packet.extend_from_slice(&record);
            let (offset, length) = if packet[0] >> 4 == 4 {
                (2, packet.len())
            } else {
                (4, packet.len() - 40)
            };
            packet[offset..offset + 2].copy_from_slice(&(length as u16).to_be_bytes());
            let captured = super::tcp_hello_from_packet(&packet).unwrap();
            assert!(captured.host.is_none());
            let hello = r2k_core::control::decode_hello(&r2k_core::control::Frame {
                kind: r2k_core::control::EVENT_HELLO,
                body: captured.event_body(),
            })
            .unwrap();
            assert_eq!(hello.tcp_client_is_low, Some(true));
            let frame = r2k_core::control::Frame {
                kind: r2k_core::control::EVENT_CLIENT_SHAPE,
                body: captured.shape_event_body().unwrap(),
            };
            let decoded = r2k_core::control::decode_client_shape(&frame).unwrap();
            assert!(decoded.host.is_empty());
            assert_eq!(decoded.client_hello, record);
            assert_eq!(decoded.key, captured.key.wire_key());
            assert_eq!(decoded.tcp_has_timestamp, captured.tcp_has_timestamp);
            assert_eq!(decoded.tcp_client_is_low, hello.tcp_client_is_low);
            let partial =
                super::tcp_hello_from_bytes(captured.key, &record[..record.len() - 2]).unwrap();
            assert!(partial.shape_event_body().is_none());
            let mut coalesced = record.clone();
            coalesced.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
            let observed = super::tcp_hello_from_bytes(captured.key, &coalesced).unwrap();
            assert_eq!(observed.client_hello.as_deref(), Some(record.as_slice()));
        }
    }

    #[test]
    fn malformed_or_oversized_sni_is_not_captured_as_an_address_target() {
        let length = r2k_core::control::MAX_DNS_NAME_LEN + 1;
        let mut oversized = Vec::new();
        oversized.extend_from_slice(&((length + 3) as u16).to_be_bytes());
        oversized.push(0);
        oversized.extend_from_slice(&(length as u16).to_be_bytes());
        oversized.extend(std::iter::repeat_n(b'a', length));
        for names in [Vec::new(), vec![0], oversized] {
            let mut extensions = Vec::new();
            push_extension(&mut extensions, 0, &names);
            push_extension(&mut extensions, 43, &[2, 3, 4]);
            let record = client_hello_with_extensions(&extensions);
            assert!(super::tcp_hello_from_bytes(key(40_000), &record).is_none());
            assert!(
                super::tcp_hello_from_bytes(key(40_000), &record[..record.len() - 2]).is_some()
            );
        }
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
    #[ignore]
    fn d2o_capture_ready_trace() {
        fn print(name: &str, result: &CaptureResult, capture: &CaptureTable) {
            let stats = capture.stats();
            let (rc, len, seq) = match result {
                CaptureResult::Complete { sequence, bytes } => (1, bytes.len(), *sequence),
                CaptureResult::Rejected => (-1, 0, 0),
                CaptureResult::Full => (-2, 0, 0),
                _ => (0, 0, 0),
            };
            println!(
                "{name} rc={rc} len={len} seq={seq} rejected={} completed={} expired={} full={}",
                stats.rejected, stats.completed, stats.expired, stats.full
            );
        }
        let key = key(50000);
        let hello = hello(20);
        let start = Instant::now();

        let mut capture = CaptureTable::default();
        let result = capture.feed(key, 1, start, 1000, Some(1000), &hello);
        print("A complete", &result, &capture);

        let mut capture = CaptureTable::default();
        let _ = capture.feed(key, 1, start, 1000, Some(1000), &hello[..10]);
        let result = capture.feed(key, 1, start, 1010, Some(1000), &hello[10..]);
        print("B split", &result, &capture);

        let mut capture = CaptureTable::default();
        let _ = capture.feed(key, 1, start, 1000, Some(1000), &hello[..10]);
        let _ = capture.feed(key, 1, start, 1010, Some(1000), &hello[10..]);
        let result = capture.feed(key, 1, start, 1000, Some(1000), &hello);
        print("C retransmit", &result, &capture);

        let mut capture = CaptureTable::default();
        let _ = capture.feed(key, 1, start, 1000, Some(1000), &hello[..10]);
        let mut conflict = hello[10..].to_vec();
        conflict[0] ^= 0xFF;
        let result = capture.feed(key, 1, start, 1010, Some(1000), &conflict);
        print("D conflict", &result, &capture);

        let mut capture = CaptureTable::default();
        let result = capture.feed(key, 1, start, 1000, None, &hello);
        print("E no-anchor head", &result, &capture);

        let mut capture = CaptureTable::default();
        let mut not_tls = hello.clone();
        not_tls[0] = b'G';
        let result = capture.feed(key, 1, start, 1000, None, &not_tls);
        print("F no-anchor tail", &result, &capture);

        let mut capture = CaptureTable::default();
        let result = capture.feed(key, 1, start, 6000, Some(1000), &hello);
        print("G far anchor", &result, &capture);

        let mut capture = CaptureTable::default();
        let _ = capture.feed(key, 1, start, 1000, Some(1000), &hello[..10]);
        let result = capture.feed(
            key,
            1,
            start + Duration::from_secs(5),
            1010,
            Some(1000),
            &hello[10..],
        );
        print("H ttl", &result, &capture);

        let mut capture = CaptureTable::default();
        let _ = capture.feed(key, 1, start, 1000, Some(1000), &hello[..10]);
        let result = capture.feed(key, 2, start, 1000, Some(1000), &hello);
        print("I generation", &result, &capture);

        let mut capture = CaptureTable::default();
        let _ = capture.feed(key, 1, start, 0xFFFF_FFF0, Some(0xFFFF_FFF0), &hello[..16]);
        let result = capture.feed(key, 1, start, 0, Some(0xFFFF_FFF0), &hello[16..]);
        print("J wrap", &result, &capture);

        let mut capture = CaptureTable::default();
        let _ = capture.feed(key, 1, start, 1000, Some(1000), &hello[..10]);
        let _ = capture.feed(key, 1, start, 1010, Some(1000), &conflict);
        let result = capture.feed(key, 1, start, 1000, Some(1000), &hello);
        print("K rejected-retry", &result, &capture);
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
    fn sparse_bitmap_masks_holes_and_is_reset_on_slot_reuse() {
        let now = Instant::now();
        let key = key(32000);
        let hello = hello(48);
        let mut table = CaptureTable::default();
        let feed = |table: &mut CaptureTable, generation, offset: usize, bytes: &[u8]| {
            table.feed(key, generation, now, 100 + offset as u32, Some(100), bytes)
        };

        assert_eq!(
            feed(&mut table, 1, 9, &hello[9..11]),
            CaptureResult::Incomplete
        );
        assert_eq!(
            feed(&mut table, 1, 13, &hello[13..21]),
            CaptureResult::Incomplete
        );
        assert_eq!(
            feed(&mut table, 1, 8, &hello[8..21]),
            CaptureResult::Incomplete
        );
        let mut conflicting = hello[11..14].to_vec();
        conflicting[2] ^= 0xff;
        assert_eq!(
            feed(&mut table, 1, 11, &conflicting),
            CaptureResult::Rejected
        );

        let mut next = hello.clone();
        next[9] ^= 0xff;
        assert_eq!(
            feed(&mut table, 2, 13, &next[13..]),
            CaptureResult::Incomplete
        );
        assert_eq!(
            feed(&mut table, 2, 0, &next[..10]),
            CaptureResult::Incomplete
        );
        complete(feed(&mut table, 2, 8, &next[8..13]), 100, &next);
    }

    #[test]
    fn reused_capture_slot_matches_a_fresh_byte_map() {
        use super::{CaptureMode, CaptureSlot};

        let now = Instant::now();
        let mut slot = CaptureSlot::new(now);
        let mut seed = 41_u32;
        let mut next = |limit| {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (seed >> 8) as usize % limit
        };
        let mut rejected = 0;
        for generation in 0..128 {
            slot.start(key(32000), generation, now, 0, CaptureMode::Tls, true);
            let mut expected = [None; CAPTURE_BYTES];
            let payload = [generation as u8; CAPTURE_BYTES];
            assert!(slot.store(0, &payload[..2]));
            expected[..2].fill(Some(generation as u8));

            // Leave a hole at the start and exercise the last bitmap octet.
            assert!(slot.store(CAPTURE_BYTES - 7, &payload[CAPTURE_BYTES - 7..]));
            expected[CAPTURE_BYTES - 7..].fill(Some(generation as u8));
            for round in 0..64 {
                let offset = next(CAPTURE_BYTES);
                let end = offset + (next(137) + 1).min(CAPTURE_BYTES - offset);
                let mut input = payload[offset..end].to_vec();
                if round == 31 {
                    input[0] ^= 0xff;
                }
                let consistent = expected[offset..end]
                    .iter()
                    .zip(&input)
                    .all(|(saved, &incoming)| saved.is_none_or(|saved| saved == incoming));
                assert_eq!(
                    slot.store(offset, &input),
                    consistent,
                    "generation {generation}, round {round}"
                );
                if !consistent {
                    rejected += 1;
                    break;
                }
                for (saved, incoming) in expected[offset..end].iter_mut().zip(input) {
                    *saved = Some(incoming);
                }
                let prefix = expected.iter().take_while(|byte| byte.is_some()).count();
                assert_eq!(usize::from(slot.contiguous), prefix);
                assert!(
                    slot.bytes[..prefix]
                        .iter()
                        .zip(&expected)
                        .all(|(&byte, saved)| Some(byte) == *saved)
                );
            }
        }
        assert!(rejected > 0, "the workload must also reuse rejected slots");
    }

    #[test]
    fn capture_lifecycle_traces_match_d2o() {
        let hello = hello(32);
        let hash = hello
            .iter()
            .fold(14_695_981_039_346_656_037_u64, |hash, byte| {
                (hash ^ u64::from(*byte)).wrapping_mul(1_099_511_628_211)
            });
        let status = |result: &CaptureResult| match result {
            CaptureResult::Ignored | CaptureResult::Incomplete => 0,
            CaptureResult::Complete { .. } => 1,
            CaptureResult::Rejected => -1,
            CaptureResult::Full => -2,
        };
        let start = Instant::now();
        let mut capture = CaptureTable::default();
        let first = capture.feed(key(1234), 1, start, 116, Some(100), &hello[16..]);
        let overlap = capture.feed(
            key(1234),
            1,
            start + Duration::from_millis(1),
            116,
            Some(100),
            &hello[16..24],
        );
        let final_segment = capture.feed(
            key(1234),
            1,
            start + Duration::from_millis(2),
            100,
            Some(100),
            &hello[..16],
        );
        complete(final_segment, 100, &hello);
        let stats = capture.stats();
        assert_eq!(
            (stats.completed, stats.rejected, stats.expired, stats.full),
            (1, 0, 0, 0)
        );
        println!(
            "TRACE reorder hash={hash:016x} first={} overlap={} final=1 seq=100 len=32 completed={} rejected={} expired={} full={}",
            status(&first),
            status(&overlap),
            stats.completed,
            stats.rejected,
            stats.expired,
            stats.full
        );

        let mut capture = CaptureTable::default();
        let first = capture.feed(key(1234), 1, start, 100, None, &hello[..1]);
        let retry = capture.feed(
            key(1234),
            1,
            start + CAPTURE_TTL - Duration::from_nanos(1),
            100,
            None,
            &hello[..1],
        );
        let tail = capture.feed(key(1234), 1, start + CAPTURE_TTL, 101, None, &hello[1..]);
        let stats = capture.stats();
        assert_eq!(
            (stats.completed, stats.rejected, stats.expired, stats.full),
            (0, 0, 1, 0)
        );
        println!(
            "TRACE ttl hash={hash:016x} first={} retry={} tail={} completed={} rejected={} expired={} full={}",
            status(&first),
            status(&retry),
            status(&tail),
            stats.completed,
            stats.rejected,
            stats.expired,
            stats.full
        );

        let mut capture = CaptureTable::default();
        for port in 0..CAPTURE_SLOTS {
            assert_eq!(
                capture.feed(key(1000 + port as u16), 1, start, 100, None, &hello[..1]),
                CaptureResult::Incomplete
            );
        }
        let refused = capture.feed(key(2000), 1, start, 100, None, &hello);
        assert_eq!(refused, CaptureResult::Full);
        let active = capture.feed(
            key(1000),
            1,
            start + Duration::from_nanos(2),
            101,
            None,
            &hello[1..],
        );
        complete(active, 100, &hello);
        let reused = capture.feed(key(2000), 1, start + CAPTURE_TTL, 100, None, &hello);
        complete(reused, 100, &hello);
        let stats = capture.stats();
        assert_eq!(
            (stats.completed, stats.rejected, stats.expired, stats.full),
            (2, 0, 63, 1)
        );
        println!(
            "TRACE full hash={hash:016x} refused={} active=1 reused=1 completed={} rejected={} expired={} full={}",
            status(&refused),
            stats.completed,
            stats.rejected,
            stats.expired,
            stats.full
        );
    }
    #[test]
    fn capture_size_limit_traces_match_d2o() {
        let hash = |bytes: &[u8]| {
            bytes
                .iter()
                .fold(14_695_981_039_346_656_037_u64, |hash, byte| {
                    (hash ^ u64::from(*byte)).wrapping_mul(1_099_511_628_211)
                })
        };
        let start = Instant::now();
        let max_hello = hello(CAPTURE_BYTES);
        let mut capture = CaptureTable::default();
        let max_result = capture.feed(key(1234), 1, start, 100, None, &max_hello);
        let status = |result: &CaptureResult| match result {
            CaptureResult::Ignored | CaptureResult::Incomplete => 0,
            CaptureResult::Complete { .. } => 1,
            CaptureResult::Rejected => -1,
            CaptureResult::Full => -2,
        };
        let max_status = status(&max_result);
        complete(max_result, 100, &max_hello);
        let stats = capture.stats();
        assert_eq!((stats.completed, stats.rejected), (1, 0));
        println!(
            "TRACE limit max hash={:016x} result={} len={} completed={} rejected={}",
            hash(&max_hello),
            max_status,
            max_hello.len(),
            stats.completed,
            stats.rejected
        );

        let over_hello = hello(CAPTURE_BYTES + 1);
        let mut capture = CaptureTable::default();
        let over_result = capture.feed(key(1234), 1, start, 100, None, &over_hello);
        assert_eq!(over_result, CaptureResult::Rejected);
        let stats = capture.stats();
        assert_eq!((stats.completed, stats.rejected), (0, 1));
        println!(
            "TRACE limit over hash={:016x} result={} len={} completed={} rejected={}",
            hash(&over_hello),
            status(&over_result),
            over_hello.len(),
            stats.completed,
            stats.rejected
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
