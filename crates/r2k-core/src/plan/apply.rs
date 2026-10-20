use super::{
    Fake, ORDER_REVERSE, PLACE_BEFORE, PLACE_BETWEEN, POISON_MD5, PROTO_HTTP, Plan, Poison,
    SeqOverlay, WIRE_BATCH_MAX, WIRE_TCP_TEMPLATE,
};
use std::error::Error;
use std::fmt;

const MAX_TLS_TRIGGER: usize = 16_384;
const MAX_EMISSIONS: usize = WIRE_BATCH_MAX;
const EMIT_IP_HEADER: usize = 20;
const EMIT_TCP_HEADER: usize = 20;
const EMIT_UDP_HEADER: usize = 8;
const EMIT_TIMESTAMP_OPTION: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalFate {
    Pass,
    Drop,
    Hold,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmitKind {
    Fake,
    Payload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketInput<'a> {
    pub payload: &'a [u8],
    pub seq: u32,
    pub have_sni: bool,
    pub is_tls13: bool,
    pub sni_off: usize,
    pub sni_len: usize,
    pub segment_cap: usize,
    pub own_after_fakes: bool,
    pub is_http: bool,
}

impl<'a> PacketInput<'a> {
    pub const fn new(payload: &'a [u8], seq: u32) -> Self {
        Self {
            payload,
            seq,
            have_sni: false,
            is_tls13: false,
            sni_off: 0,
            sni_len: 0,
            segment_cap: 0,
            own_after_fakes: false,
            is_http: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Emission {
    pub kind: EmitKind,
    pub delay_us: u32,
    pub seq: u32,
    pub ttl: u8,
    pub poison: u8,
    pub seq_shift: i32,
    pub wire_profile: u8,
    pub ipfrag: u8,
    pub urgent: bool,
    pub urgent_ptr: u16,
    /// Байты, размещённые перед `bytes` в пространстве последовательности TCP.
    pub prefix: Vec<u8>,
    pub bytes: Vec<u8>,
}

impl Emission {
    fn payload(seq: u32, bytes: &[u8]) -> Result<Self, ApplyError> {
        Ok(Self {
            kind: EmitKind::Payload,
            delay_us: 0,
            seq,
            ttl: 0,
            poison: 0,
            seq_shift: 0,
            wire_profile: 0,
            ipfrag: 0,
            urgent: false,
            urgent_ptr: 0,
            prefix: Vec::new(),
            bytes: copy_bytes(bytes)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Actions {
    pub fate: OriginalFate,
    pub emits: Vec<Emission>,
}

impl Actions {
    /// Применить правило отмены datapath к числу завершённых отправок.
    pub fn cancel(&self, emitted: usize) -> Cancellation {
        let sent = emitted.min(self.emits.len());
        let payload_out = self.emits[..sent]
            .iter()
            .any(|action| action.kind == EmitKind::Payload);
        let partial = sent < self.emits.len();
        Cancellation {
            fate: if payload_out {
                OriginalFate::Drop
            } else {
                OriginalFate::Pass
            },
            partial,
            stream_damaged: payload_out && partial,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cancellation {
    pub fate: OriginalFate,
    pub partial: bool,
    pub stream_damaged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyError {
    kind: &'static str,
    message: &'static str,
}

impl ApplyError {
    fn new(kind: &'static str, message: &'static str) -> Self {
        Self { kind, message }
    }

    pub const fn kind(&self) -> &'static str {
        self.kind
    }
}

impl fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for ApplyError {}

impl Plan {
    /// Скомпилировать проверенный план и пакет в точные отправки полезной нагрузки дейтаграмм.
    pub fn apply(&self, input: &PacketInput<'_>) -> Result<Actions, ApplyError> {
        self.check_references().map_err(|_| {
            ApplyError::new("invalid-plan", "план изменён после проверки и несовместим")
        })?;
        if input.payload.is_empty() {
            return Err(ApplyError::new(
                "empty-input",
                "в пакете нет полезной нагрузки",
            ));
        }
        if (self.proto == PROTO_HTTP) != input.is_http {
            return Err(if self.proto == PROTO_HTTP {
                ApplyError::new(
                    "http-mismatch",
                    "план открытого HTTP, а пакет — не запрос HTTP",
                )
            } else {
                ApplyError::new(
                    "http-mismatch",
                    "пакет — запрос HTTP, а план объявлен не для него",
                )
            });
        }
        if self.qdeny != 0 {
            return Ok(Actions {
                fate: OriginalFate::Drop,
                emits: Vec::new(),
            });
        }
        if input.is_http
            && (self.input_tls
                || self.input_len != 0
                || self.oob_enabled
                || self.ipfrag != 0
                || self.udplen != 0
                || self.qsplit != 0)
        {
            return Err(ApplyError::new(
                "http-operation",
                "приёмы этого плана к запросу HTTP не применяются",
            ));
        }
        if self.input_tls {
            validate_tls_input(input)?;
        }
        if self.input_len != 0 {
            validate_measured_input(self, input)?;
        }
        if self.qsplit != 0 {
            let bytes =
                crate::quic::initial_split_crypto(input.payload).map_err(|error| match error {
                    crate::quic::QuicSplitError::NoNameInDatagram => ApplyError::new(
                        "quic-name-missing",
                        "разрез CRYPTO: имени нет в этой датаграмме; такой разрез не мерили",
                    ),
                    crate::quic::QuicSplitError::Invalid => ApplyError::new(
                        "quic-split-invalid",
                        "разрез CRYPTO неприменим: не Initial, чужой кадр или нет добивки",
                    ),
                })?;
            if self
                .fakes
                .iter()
                .any(|fake| fake.placement == PLACE_BETWEEN)
            {
                return Err(ApplyError::new(
                    "quic-split-fake-order",
                    "фальшивка между частями неприменима к одному QUIC Initial",
                ));
            }
            let emission_count = self.fakes.iter().try_fold(1usize, |count, fake| {
                count.checked_add(usize::from(fake.repeats.max(1)))
            });
            let Some(emission_count) = emission_count.filter(|count| *count <= MAX_EMISSIONS)
            else {
                return Err(ApplyError::new(
                    "too-many-emissions",
                    "слишком много посылок плана",
                ));
            };
            let mut emits = Vec::new();
            emits
                .try_reserve_exact(emission_count)
                .map_err(|_| ApplyError::new("out-of-memory", "нет памяти на посылки плана"))?;
            for fake in self
                .fakes
                .iter()
                .filter(|fake| fake.placement == PLACE_BEFORE)
            {
                self.append_fake_repeats(&mut emits, fake, input, input.seq)?;
            }
            emits.push(Emission::payload(input.seq, &bytes)?);
            return Ok(Actions {
                fate: OriginalFate::Drop,
                emits,
            });
        }
        if self.udplen != 0
            && input
                .payload
                .len()
                .checked_add(usize::from(self.udplen))
                .is_none_or(|len| len > 65_535 - EMIT_UDP_HEADER)
        {
            return Err(ApplyError::new(
                "udp-length",
                "удлинённая нагрузка не помещается в одну UDP-датаграмму",
            ));
        }

        if self.oob_enabled {
            let middle = anchor_offset(input, self.oob_anchor)?;
            if middle == 0 || middle >= input.payload.len() {
                return Err(ApplyError::new(
                    "urgent-position",
                    "место срочного байта вне нагрузки этого пакета",
                ));
            }
            let mut first = Emission::payload(input.seq, &input.payload[..middle])?;
            let mut urgent = Emission::payload(
                input.seq.wrapping_add(middle as u32),
                std::slice::from_ref(&self.oob_byte),
            )?;
            urgent.urgent = true;
            urgent.urgent_ptr = 1;
            let suffix = Emission::payload(
                input.seq.wrapping_add(middle as u32).wrapping_add(1),
                &input.payload[middle..],
            )?;
            first.wire_profile = self.wire_profile;
            urgent.wire_profile = self.wire_profile;
            let mut actions = Actions {
                fate: OriginalFate::Drop,
                emits: vec![first, urgent, suffix],
            };
            self.segment(&mut actions.emits, input)?;
            return Ok(actions);
        }

        let points = split_points(self, input)?;
        let mut owns_payload = !points.is_empty()
            || !self.seq_overlays.is_empty()
            || self.pace_us != 0
            || self.settle_us != 0
            || self.delay_us != 0
            || self.ipfrag != 0
            || self.udplen != 0
            || self.qsplit != 0;
        if input.own_after_fakes && !self.fakes.is_empty() {
            owns_payload = true;
        }

        let mut emission_capacity = 0usize;
        let mut between_per_gap = 0usize;
        for fake in &self.fakes {
            let repeats = usize::from(fake.repeats.max(1));
            if fake.placement == PLACE_BETWEEN {
                between_per_gap = between_per_gap.checked_add(repeats).ok_or_else(|| {
                    ApplyError::new("too-many-emissions", "слишком много посылок плана")
                })?;
            } else {
                emission_capacity = emission_capacity.checked_add(repeats).ok_or_else(|| {
                    ApplyError::new("too-many-emissions", "слишком много посылок плана")
                })?;
            }
        }
        if owns_payload {
            emission_capacity = emission_capacity
                .checked_add(points.len() + 1)
                .and_then(|count| count.checked_add(points.len().checked_mul(between_per_gap)?))
                .ok_or_else(|| {
                    ApplyError::new("too-many-emissions", "слишком много посылок плана")
                })?;
        }
        if emission_capacity == 0 {
            return Ok(Actions {
                fate: OriginalFate::Pass,
                emits: Vec::new(),
            });
        }
        if emission_capacity > MAX_EMISSIONS {
            return Err(ApplyError::new(
                "too-many-emissions",
                "нарезка на сегменты даёт слишком много посылок",
            ));
        }
        let mut emits = Vec::new();
        emits
            .try_reserve_exact(emission_capacity)
            .map_err(|_| ApplyError::new("out-of-memory", "нет памяти на посылки плана"))?;

        for fake in self
            .fakes
            .iter()
            .filter(|fake| fake.placement == PLACE_BEFORE)
        {
            self.append_fake_repeats(&mut emits, fake, input, input.seq)?;
        }

        if owns_payload {
            let overlay = self.seq_overlays.first();
            let mut start = 0;
            for index in 0..=points.len() {
                let end = points.get(index).copied().unwrap_or(input.payload.len());
                let mut emission = Emission::payload(
                    input.seq.wrapping_add(start as u32),
                    &input.payload[start..end],
                )?;
                emission.ipfrag = self.ipfrag;
                if self.udplen != 0 {
                    emission
                        .bytes
                        .try_reserve_exact(usize::from(self.udplen))
                        .map_err(|_| {
                            ApplyError::new("out-of-memory", "нет памяти на удлинение датаграммы")
                        })?;
                    let grown_len = emission.bytes.len() + usize::from(self.udplen);
                    emission.bytes.resize(grown_len, 0);
                }
                if index == 0
                    && let Some(overlay) = overlay
                {
                    self.apply_overlay(&mut emission, overlay)?;
                }
                emits.push(emission);
                start = end;
                if index < points.len() {
                    for fake in self
                        .fakes
                        .iter()
                        .filter(|fake| fake.placement == PLACE_BETWEEN)
                    {
                        self.append_fake_repeats(
                            &mut emits,
                            fake,
                            input,
                            input.seq.wrapping_add(start as u32),
                        )?;
                    }
                }
            }

            if self.order == ORDER_REVERSE {
                reverse_payload_emissions(&mut emits);
            }
        }

        self.apply_timing(&mut emits);
        for emission in &mut emits {
            emission.wire_profile = self.wire_profile;
        }
        self.segment(&mut emits, input)?;
        Ok(Actions {
            fate: if owns_payload {
                OriginalFate::Drop
            } else {
                OriginalFate::Pass
            },
            emits,
        })
    }

    /// Консервативный максимум размера в сети для любого действия из этого плана.
    pub fn max_emit(&self) -> usize {
        let mut maximum = 0;
        for fake in &self.fakes {
            let Some(payload) = self
                .payloads
                .iter()
                .find(|payload| payload.id == fake.payload_id)
            else {
                continue;
            };
            let poison = (fake.poison_id != 0)
                .then(|| {
                    self.poisons
                        .iter()
                        .find(|poison| poison.id == fake.poison_id)
                })
                .flatten();
            let body = payload.bytes.len() + usize::from(fake.tls_mod & 2 != 0) * 32;
            maximum = maximum.max(self.emit_overhead(poison) + self.segment_body(body));
        }
        for overlay in &self.seq_overlays {
            let Some(payload) = self
                .payloads
                .iter()
                .find(|payload| payload.id == overlay.payload_id)
            else {
                continue;
            };
            let poison = (overlay.poison_id != 0)
                .then(|| {
                    self.poisons
                        .iter()
                        .find(|poison| poison.id == overlay.poison_id)
                })
                .flatten();
            maximum =
                maximum.max(self.emit_overhead(poison) + self.segment_body(payload.bytes.len()));
        }
        if self.udplen != 0 {
            let body = (if self.proto == 2 { 1200 } else { 1 }) + usize::from(self.udplen);
            maximum = maximum.max(self.emit_overhead(None) + body);
        }
        maximum
    }

    fn append_fake_repeats(
        &self,
        emits: &mut Vec<Emission>,
        fake: &Fake,
        input: &PacketInput<'_>,
        sequence: u32,
    ) -> Result<(), ApplyError> {
        let repeats = fake.repeats.max(1);
        for repeat in 0..repeats {
            let mut emission = self.emit_fake(fake, input)?;
            emission.seq = sequence;
            emission.delay_us = if repeat == 0 { 0 } else { fake.gap_us };
            if repeat != 0
                && self.wire_profile == WIRE_TCP_TEMPLATE
                && let Some(previous) = emits.last()
            {
                emission.bytes = copy_bytes(&previous.bytes)?;
            }
            emits.push(emission);
        }
        Ok(())
    }

    fn emit_fake(&self, fake: &Fake, input: &PacketInput<'_>) -> Result<Emission, ApplyError> {
        let payload = self
            .payloads
            .iter()
            .find(|payload| payload.id == fake.payload_id)
            .ok_or_else(|| {
                ApplyError::new(
                    "invalid-plan",
                    "фальшивка плана ссылается на нагрузку, которой нет",
                )
            })?;
        let poison = (fake.poison_id != 0)
            .then(|| {
                self.poisons
                    .iter()
                    .find(|poison| poison.id == fake.poison_id)
            })
            .flatten();
        let bytes = if fake.tls_mod == 0 {
            copy_bytes(&payload.bytes)?
        } else {
            self.fake_tls_bytes(fake, payload, input)?
        };
        let mut emission = Emission {
            kind: EmitKind::Fake,
            delay_us: 0,
            seq: input.seq,
            ttl: 0,
            poison: 0,
            seq_shift: 0,
            wire_profile: self.wire_profile,
            ipfrag: 0,
            urgent: false,
            urgent_ptr: 0,
            prefix: Vec::new(),
            bytes,
        };
        if let Some(poison) = poison {
            emission.ttl = poison.ttl;
            emission.poison = poison.flags;
            emission.seq_shift = poison.seq_shift;
        }
        Ok(emission)
    }

    fn fake_tls_bytes(
        &self,
        fake: &Fake,
        payload: &super::Payload,
        input: &PacketInput<'_>,
    ) -> Result<Vec<u8>, ApplyError> {
        if !input.is_tls13 && self.wire_profile != WIRE_TCP_TEMPLATE {
            return Err(ApplyError::new(
                "tls-shape",
                "правка приветствия просит TLS 1.3, а у этого пакета форма другая",
            ));
        }
        let real = tls_client_hello_layout(input.payload, self.wire_profile == WIRE_TCP_TEMPLATE)?;
        let fake_layout = tls_client_hello_layout(&payload.bytes, false)?;
        if self.wire_profile == WIRE_TCP_TEMPLATE {
            let mut output = copy_bytes(&payload.bytes)?;
            if fake.tls_mod & 1 != 0 {
                secure_random(&mut output[11..43])?;
                secure_random(
                    &mut output
                        [fake_layout.sid_offset..fake_layout.sid_offset + fake_layout.sid_len],
                )?;
            }
            if fake.tls_mod & 2 != 0 && fake_layout.sid_len == real.sid_len {
                output[fake_layout.sid_offset..fake_layout.sid_offset + fake_layout.sid_len]
                    .copy_from_slice(
                        &input.payload[real.sid_offset..real.sid_offset + real.sid_len],
                    );
            }
            return Ok(output);
        }

        let output_len = if fake.tls_mod & 2 != 0 {
            payload
                .bytes
                .len()
                .checked_sub(fake_layout.sid_len)
                .and_then(|len| len.checked_add(real.sid_len))
                .filter(|len| {
                    *len <= 65_540 && *len >= 9 && *len - 5 <= 65_535 && *len - 9 <= 0x00ff_ffff
                })
                .ok_or_else(|| {
                    ApplyError::new(
                        "tls-length",
                        "правка приветствия: копия session id не влезает в запись TLS",
                    )
                })?
        } else {
            payload.bytes.len()
        };
        let mut output = Vec::new();
        output
            .try_reserve_exact(output_len)
            .map_err(|_| ApplyError::new("out-of-memory", "нет памяти на правку приветствия"))?;
        output.resize(output_len, 0);
        if fake.tls_mod & 2 != 0 {
            let start = fake_layout.sid_offset;
            let end = start + fake_layout.sid_len;
            output[..start].copy_from_slice(&payload.bytes[..start]);
            output[start..start + real.sid_len]
                .copy_from_slice(&input.payload[real.sid_offset..real.sid_offset + real.sid_len]);
            output[start + real.sid_len..].copy_from_slice(&payload.bytes[end..]);
            output[start - 1] = real.sid_len as u8;
            write_u16(&mut output, 3, output_len - 5);
            write_u24(&mut output, 6, output_len - 9);
        } else {
            output.copy_from_slice(&payload.bytes);
        }
        if fake.tls_mod & 1 != 0 {
            secure_random(&mut output[11..43])?;
        }
        Ok(output)
    }

    fn apply_overlay(
        &self,
        emission: &mut Emission,
        overlay: &SeqOverlay,
    ) -> Result<(), ApplyError> {
        let payload = self
            .payloads
            .iter()
            .find(|payload| payload.id == overlay.payload_id)
            .ok_or_else(|| {
                ApplyError::new(
                    "invalid-plan",
                    "перекрытие ссылается на отсутствующую приманку",
                )
            })?;
        emission.prefix = copy_bytes(&payload.bytes)?;
        emission.seq = emission.seq.wrapping_sub(payload.bytes.len() as u32);
        if overlay.poison_id != 0
            && let Some(poison) = self
                .poisons
                .iter()
                .find(|poison| poison.id == overlay.poison_id)
        {
            emission.ttl = poison.ttl;
            emission.poison = poison.flags;
            emission.seq_shift = poison.seq_shift;
        }
        Ok(())
    }

    fn apply_timing(&self, emits: &mut [Emission]) {
        if self.pace_us != 0 {
            for (index, emit) in emits.iter_mut().enumerate() {
                if emit.kind == EmitKind::Payload {
                    emit.delay_us = if index == 0 { 0 } else { self.pace_us };
                }
            }
        }
        if self.settle_us != 0
            && let Some((index, emit)) = emits
                .iter_mut()
                .enumerate()
                .find(|(_, emit)| emit.kind == EmitKind::Payload)
            && index > 0
        {
            emit.delay_us = self.settle_us;
        }
        if self.delay_us != 0
            && let Some(emit) = emits.iter_mut().find(|emit| emit.kind == EmitKind::Payload)
        {
            emit.delay_us = self.delay_us;
        }
    }

    fn segment(
        &self,
        emits: &mut Vec<Emission>,
        input: &PacketInput<'_>,
    ) -> Result<(), ApplyError> {
        if self.segment_size == 0 && input.segment_cap == 0 {
            return Ok(());
        }
        let mut chunk_count = 0usize;
        let mut limits = Vec::new();
        limits
            .try_reserve_exact(emits.len())
            .map_err(|_| ApplyError::new("out-of-memory", "нет памяти на нарезку посылок"))?;
        for emit in emits.iter() {
            let mut limit = self.segment_size as usize;
            if input.segment_cap != 0
                && (self.transport == 0 || self.transport == 6)
                && self.ipfrag == 0
                && emit.kind == EmitKind::Payload
                && (limit == 0 || input.segment_cap < limit)
            {
                limit = input.segment_cap;
            }
            let total = emit
                .prefix
                .len()
                .checked_add(emit.bytes.len())
                .ok_or_else(|| {
                    ApplyError::new(
                        "too-many-emissions",
                        "нарезка на сегменты даёт слишком много посылок",
                    )
                })?;
            let chunks = if limit != 0 && total != 0 {
                (total - 1) / limit + 1
            } else {
                1
            };
            chunk_count = chunk_count.checked_add(chunks).ok_or_else(|| {
                ApplyError::new(
                    "too-many-emissions",
                    "нарезка на сегменты даёт слишком много посылок",
                )
            })?;
            if chunks > MAX_EMISSIONS || chunk_count > MAX_EMISSIONS {
                return Err(ApplyError::new(
                    "too-many-emissions",
                    "нарезка на сегменты даёт слишком много посылок",
                ));
            }
            limits.push(limit);
        }

        let mut segmented = Vec::new();
        segmented
            .try_reserve_exact(chunk_count)
            .map_err(|_| ApplyError::new("out-of-memory", "нет памяти на нарезку посылок"))?;
        for (emit, limit) in emits.iter().zip(limits) {
            let total = emit.prefix.len() + emit.bytes.len();
            let mut offset = 0usize;
            loop {
                let take = if limit != 0 {
                    (total - offset).min(limit)
                } else {
                    total - offset
                };
                segmented.push(slice_emission(emit, offset, take)?);
                offset += take;
                if offset >= total {
                    break;
                }
            }
        }
        *emits = segmented;
        Ok(())
    }

    fn emit_overhead(&self, poison: Option<&Poison>) -> usize {
        let mut header_len = EMIT_IP_HEADER
            + if self.transport == 17 {
                EMIT_UDP_HEADER
            } else {
                EMIT_TCP_HEADER
            };
        if poison.is_some() && self.transport != 17 {
            let flags = poison.map_or(0, |poison| poison.flags);
            if flags & POISON_MD5 != 0 {
                header_len += 20;
            } else if flags & super::POISON_TCPTS_BACK != 0 {
                header_len += EMIT_TIMESTAMP_OPTION;
            }
        }
        header_len
    }

    fn segment_body(&self, body: usize) -> usize {
        if self.segment_size == 0 {
            body
        } else {
            body.min(self.segment_size as usize)
        }
    }
}

fn validate_tls_input(input: &PacketInput<'_>) -> Result<(), ApplyError> {
    let bytes = input.payload;
    let n = bytes.len();
    if !(9..=MAX_TLS_TRIGGER).contains(&n)
        || bytes[0] != 0x16
        || bytes[1] != 3
        || bytes[5] != 1
        || !input.have_sni
        || input.sni_len <= 1
        || input.sni_off == 0
        || input.sni_off > n
        || input.sni_len > n - input.sni_off
    {
        return Err(if !input.have_sni {
            ApplyError::new(
                "tls-input",
                "план считает от имени, а имени в этом пакете нет",
            )
        } else {
            ApplyError::new(
                "tls-input",
                "план считает от имени, а разметка имени негодна",
            )
        });
    }
    let record_total = 5 + usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    let handshake_len =
        (usize::from(bytes[6]) << 16) | (usize::from(bytes[7]) << 8) | usize::from(bytes[8]);
    let handshake_total = 9 + handshake_len;
    if record_total != handshake_total || n > record_total {
        return Err(ApplyError::new(
            "tls-length",
            "приветствие негодно: длины записи и рукопожатия не сходятся или пришло больше объявленного",
        ));
    }
    Ok(())
}

fn validate_measured_input(plan: &Plan, input: &PacketInput<'_>) -> Result<(), ApplyError> {
    let mut declared_len = 0usize;
    let bytes = input.payload;
    if bytes.len() >= 9 && bytes[0] == 0x16 && bytes[1] == 3 && bytes[5] == 1 {
        let record_total = 5 + usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
        let handshake_len =
            (usize::from(bytes[6]) << 16) | (usize::from(bytes[7]) << 8) | usize::from(bytes[8]);
        let handshake_total = 9 + handshake_len;
        if record_total == handshake_total {
            declared_len = record_total;
        }
    }
    let expected_len = plan.input_len as usize;
    let have = if bytes.len() == expected_len {
        expected_len
    } else {
        declared_len
    };
    if have != expected_len
        || bytes.len() > expected_len
        || (if input.have_sni { input.sni_len } else { 0 }) != plan.input_sni_len as usize
        || (plan.input_sni_len != 0 && input.sni_off != plan.input_sni_off as usize)
    {
        return Err(ApplyError::new(
            "measured-input",
            "байты плана собраны под другой вход: объявленная длина приветствия, длина или место имени не те, что мерили",
        ));
    }
    for split in &plan.splits {
        if split.anchor == 0 && split.offset > 0 && split.offset as usize >= bytes.len() {
            return Err(ApplyError::new(
                "measured-split",
                "измеренный разрез лежит за пришедшими байтами: исполнилась бы другая программа, чем мерили",
            ));
        }
    }
    Ok(())
}

fn anchor_offset(input: &PacketInput<'_>, anchor: u16) -> Result<usize, ApplyError> {
    match anchor {
        0 => Ok(0),
        1 if input.have_sni => Ok(input.sni_off),
        1 => Err(ApplyError::new(
            "missing-sni",
            "якорь «начало имени»: имени в этом пакете нет",
        )),
        2 if input.have_sni => input.sni_off.checked_add(input.sni_len).ok_or_else(|| {
            ApplyError::new("invalid-sni", "разметка имени выходит за размер пакета")
        }),
        2 => Err(ApplyError::new(
            "missing-sni",
            "якорь «конец имени»: имени в этом пакете нет",
        )),
        3 => Ok(input.payload.len() / 2),
        4 => Err(ApplyError::new(
            "unsupported-anchor",
            "якорь «конец записи TLS» не поддержан исполнителем",
        )),
        5 if input.have_sni => {
            let mut midpoint = input
                .sni_off
                .checked_add(input.sni_len / 2)
                .ok_or_else(|| {
                    ApplyError::new("invalid-sni", "разметка имени выходит за размер пакета")
                })?;
            if midpoint < 2 {
                midpoint = 2;
            }
            if midpoint >= input.payload.len() {
                midpoint = input.payload.len().saturating_sub(1);
            }
            Ok(midpoint)
        }
        5 => Err(ApplyError::new(
            "missing-sni",
            "якорь «середина имени»: имени в этом пакете нет",
        )),
        _ => Err(ApplyError::new(
            "unknown-anchor",
            "якорь плана не известен исполнителю",
        )),
    }
}

fn split_points(plan: &Plan, input: &PacketInput<'_>) -> Result<Vec<usize>, ApplyError> {
    let mut points = Vec::new();
    points
        .try_reserve_exact(plan.splits.len())
        .map_err(|_| ApplyError::new("out-of-memory", "нет памяти на разрезы плана"))?;
    for split in &plan.splits {
        let base = anchor_offset(input, split.anchor)?;
        let point = i128::try_from(base).unwrap_or(i128::MAX) + i128::from(split.offset);
        if point > 0 && point < input.payload.len() as i128 {
            points.push(point as usize);
        }
    }
    points.sort_unstable();
    points.dedup();
    Ok(points)
}

fn reverse_payload_emissions(emits: &mut [Emission]) {
    let mut payload_indexes: Vec<usize> = emits
        .iter()
        .enumerate()
        .filter_map(|(index, emit)| (emit.kind == EmitKind::Payload).then_some(index))
        .collect();
    let count = payload_indexes.len();
    for index in 0..count / 2 {
        let other = count - index - 1;
        emits.swap(payload_indexes[index], payload_indexes[other]);
    }
    payload_indexes.clear();
}

fn slice_emission(emit: &Emission, offset: usize, length: usize) -> Result<Emission, ApplyError> {
    let prefix_start = offset.min(emit.prefix.len());
    let prefix_end = (offset + length).min(emit.prefix.len());
    let prefix = if prefix_start < prefix_end {
        copy_bytes(&emit.prefix[prefix_start..prefix_end])?
    } else {
        Vec::new()
    };
    let body_start = offset.saturating_sub(emit.prefix.len());
    let body_end = (offset + length)
        .saturating_sub(emit.prefix.len())
        .min(emit.bytes.len());
    let bytes = if body_start < body_end {
        copy_bytes(&emit.bytes[body_start..body_end])?
    } else {
        Vec::new()
    };
    let mut output = emit.clone();
    output.seq = output.seq.wrapping_add(offset as u32);
    if offset != 0 {
        output.delay_us = 0;
    }
    output.prefix = prefix;
    output.bytes = bytes;
    if length == 0 {
        output.prefix.clear();
        output.bytes.clear();
    }
    Ok(output)
}

fn tls_client_hello_layout(
    bytes: &[u8],
    allow_prefix: bool,
) -> Result<TlsClientHelloLayout, ApplyError> {
    if bytes.len() < 44 || bytes[0] != 0x16 || bytes[1] != 3 || bytes[5] != 1 {
        return Err(ApplyError::new(
            "tls-shape",
            "правка приветствия: это не ClientHello или он короче 44 байт",
        ));
    }
    let record_len = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
    let handshake_len =
        (usize::from(bytes[6]) << 16) | (usize::from(bytes[7]) << 8) | usize::from(bytes[8]);
    if record_len + 5 != handshake_len + 9 {
        return Err(ApplyError::new(
            "tls-shape",
            "правка приветствия: объявленные длины записи и рукопожатия не сходятся",
        ));
    }
    if bytes.len() > record_len + 5 {
        return Err(ApplyError::new(
            "tls-shape",
            "правка приветствия: пришло больше, чем объявлено записью",
        ));
    }
    if !allow_prefix && (handshake_len > bytes.len() - 9 || record_len > bytes.len() - 5) {
        return Err(ApplyError::new(
            "tls-shape",
            "правка приветствия просит приветствие ЦЕЛИКОМ, а пришло только его начало",
        ));
    }
    let session_id_len = usize::from(bytes[43]);
    if session_id_len > 32 || session_id_len > bytes.len() - 44 {
        return Err(ApplyError::new(
            "tls-shape",
            "правка приветствия: длина session id выходит за пришедшие байты",
        ));
    }
    Ok(TlsClientHelloLayout {
        sid_offset: 44,
        sid_len: session_id_len,
    })
}

struct TlsClientHelloLayout {
    sid_offset: usize,
    sid_len: usize,
}

fn secure_random(output: &mut [u8]) -> Result<(), ApplyError> {
    getrandom::getrandom(output).map_err(|_| {
        ApplyError::new(
            "random-source",
            "криптографический источник случайных байтов недоступен",
        )
    })
}

fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, ApplyError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| ApplyError::new("out-of-memory", "нет памяти на посылки плана"))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

fn write_u16(bytes: &mut [u8], offset: usize, value: usize) {
    bytes[offset] = (value >> 8) as u8;
    bytes[offset + 1] = value as u8;
}

fn write_u24(bytes: &mut [u8], offset: usize, value: usize) {
    bytes[offset] = (value >> 16) as u8;
    bytes[offset + 1] = (value >> 8) as u8;
    bytes[offset + 2] = value as u8;
}
