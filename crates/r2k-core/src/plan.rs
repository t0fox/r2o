use std::error::Error;
use std::fmt;

mod apply;
pub use apply::{Actions, ApplyError, Cancellation, Emission, EmitKind, OriginalFate, PacketInput};

pub const EXEC_VERSION: u16 = 12;
pub const SCHEMA_MAX: u16 = 1;
/// Максимальное число пакетов в результате обработки потока.
pub const WIRE_BATCH_MAX: usize = 26;
pub const PLAN_MAGIC: [u8; 4] = *b"R2OP";
pub const PROTO_QUIC: u8 = 2;
pub const PROTO_HTTP: u8 = 4;
pub const PROTO_VOICE: u8 = 3;
/// Точная полезная нагрузка QUIC-пробы с ограничением срока жизни пакета.
pub const R2K_QUIC_TTL_PROBE_PAYLOAD: &[u8] = include_bytes!("quic/quic_ttl_probe.bin");
pub const WIRE_DETECT_TCP: u8 = 1;
pub const WIRE_TCP_TEMPLATE: u8 = 2;
pub const POISON_BADSUM: u8 = 1 << 0;
pub const POISON_TCPTS_BACK: u8 = 1 << 1;
pub const POISON_IPID_ZERO: u8 = 1 << 2;
pub const POISON_MD5: u8 = 1 << 3;
pub const GUARD_RST_ALIEN: u8 = 1 << 0;

const HEADER_LEN: usize = 12;
const PLAN_ID_LEN: usize = 16;

const REC_ID: u16 = 0x0001;
const REC_PROTO: u16 = 0x0002;
const REC_PAYLOAD: u16 = 0x0010;
const REC_POISON: u16 = 0x0011;
const REC_SPLIT: u16 = 0x0100;
const REC_FAKE: u16 = 0x0101;
const REC_SEQOVL: u16 = 0x0102;
const REC_ORDER: u16 = 0x0103;
const REC_GUARD: u16 = 0x0104;
const REC_PACE: u16 = 0x0105;
const REC_INPUT: u16 = 0x0106;
const REC_SETTLE: u16 = 0x0107;
const REC_SEGMENT: u16 = 0x0108;
const REC_WIRE: u16 = 0x0109;
const REC_INPUT_TLS: u16 = 0x010a;
const REC_DELAY: u16 = 0x010b;
const REC_IPFRAG: u16 = 0x010c;
const REC_OOB: u16 = 0x010d;
const REC_UDPLEN: u16 = 0x010e;
const REC_QSPLIT: u16 = 0x010f;
const REC_QDENY: u16 = 0x0110;

const ANCHOR_SNI_MIDDLE: u16 = 5;
const PLACE_BEFORE: u8 = 0;
const PLACE_BETWEEN: u8 = 1;
const ORDER_FORWARD: u8 = 0;
const ORDER_REVERSE: u8 = 1;
const TLS_MOD_RND: u8 = 1 << 0;
const TLS_MOD_DUPSID: u8 = 1 << 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanError(String);

impl PlanError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for PlanError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payload {
    pub id: u16,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Poison {
    pub id: u16,
    pub ttl: u8,
    pub flags: u8,
    pub seq_shift: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Split {
    pub anchor: u16,
    pub offset: i16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fake {
    pub payload_id: u16,
    pub poison_id: u16,
    pub repeats: u8,
    pub placement: u8,
    pub gap_us: u32,
    pub tls_mod: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeqOverlay {
    pub payload_id: u16,
    pub poison_id: u16,
}

/// Полностью проверенное неизменяемое представление плана R2O.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Plan {
    pub schema: u16,
    pub minexec: u16,
    pub id: [u8; PLAN_ID_LEN],
    pub transport: u8,
    pub proto: u8,
    pub order: u8,
    pub guards: u8,
    pub input_len: u32,
    pub input_sni_off: u32,
    pub input_sni_len: u32,
    pub settle_us: u32,
    pub segment_size: u32,
    pub wire_profile: u8,
    pub input_tls: bool,
    pub ipfrag: u8,
    pub oob_enabled: bool,
    pub oob_anchor: u16,
    pub oob_byte: u8,
    pub udplen: u16,
    pub qsplit: u8,
    pub qdeny: u8,
    pub pace_us: u32,
    pub delay_us: u32,
    pub payloads: Vec<Payload>,
    pub poisons: Vec<Poison>,
    pub splits: Vec<Split>,
    pub fakes: Vec<Fake>,
    pub seq_overlays: Vec<SeqOverlay>,
}

impl Plan {
    /// Проверяет все записи до возврата плана; неизвестные и неполные данные отклоняются.
    pub fn parse(bytes: &[u8]) -> Result<Self, PlanError> {
        if bytes.len() < HEADER_LEN {
            return Err(PlanError::new("короче заголовка"));
        }
        if bytes.get(..PLAN_MAGIC.len()) != Some(PLAN_MAGIC.as_slice()) {
            return Err(PlanError::new("не план r2o"));
        }
        let schema = read_u16(bytes, 4)?;
        let minexec = read_u16(bytes, 6)?;
        if schema > SCHEMA_MAX {
            return Err(PlanError::new("схема новее, чем понимает эта сборка"));
        }
        if minexec > EXEC_VERSION {
            return Err(PlanError::new("плану нужен более новый исполнитель"));
        }
        if read_u16(bytes, 8)? != 0 {
            return Err(PlanError::new("ненулевые флаги заголовка"));
        }
        let declared_records = usize::from(read_u16(bytes, 10)?);
        let (counts, records_seen) = scan(bytes, minexec)?;
        if records_seen != declared_records {
            return Err(PlanError::new("число записей не совпадает с заявленным"));
        }

        let mut plan = Self {
            schema,
            minexec,
            payloads: Vec::with_capacity(counts.payloads),
            poisons: Vec::with_capacity(counts.poisons),
            splits: Vec::with_capacity(counts.splits),
            fakes: Vec::with_capacity(counts.fakes),
            seq_overlays: Vec::with_capacity(counts.seq_overlays),
            ..Self::default()
        };

        let mut offset = HEADER_LEN;
        while let Some((kind, value)) = next_record(bytes, &mut offset)? {
            match kind {
                REC_IPFRAG => set_once_u8(&mut plan.ipfrag, value[0], "повторная запись ipfrag")?,
                REC_UDPLEN => set_once_u16(
                    &mut plan.udplen,
                    read_u16(value, 0)?,
                    "повторная запись udplen",
                )?,
                REC_QSPLIT => {
                    set_once_u8(&mut plan.qsplit, value[0], "повторная запись quicsplit")?
                }
                REC_QDENY => set_once_u8(&mut plan.qdeny, value[0], "повторная запись quicdeny")?,
                REC_OOB => {
                    plan.oob_enabled = true;
                    plan.oob_anchor = read_u16(value, 0)?;
                    plan.oob_byte = value[2];
                }
                REC_ID => plan.id.copy_from_slice(value),
                REC_PROTO => {
                    plan.transport = value[0];
                    plan.proto = value[1];
                }
                REC_PAYLOAD => plan.payloads.push(Payload {
                    id: read_u16(value, 0)?,
                    bytes: value[2..].to_vec(),
                }),
                REC_POISON => plan.poisons.push(Poison {
                    id: read_u16(value, 0)?,
                    ttl: value[2],
                    flags: value[3],
                    seq_shift: read_u32(value, 4)? as i32,
                }),
                REC_SPLIT => plan.splits.push(Split {
                    anchor: read_u16(value, 0)?,
                    offset: read_u16(value, 2)? as i16,
                }),
                REC_FAKE => plan.fakes.push(Fake {
                    payload_id: read_u16(value, 0)?,
                    poison_id: read_u16(value, 2)?,
                    repeats: value[4],
                    placement: value[5],
                    gap_us: read_u32(value, 6)?,
                    tls_mod: value.get(10).copied().unwrap_or(0),
                }),
                REC_SEQOVL => plan.seq_overlays.push(SeqOverlay {
                    payload_id: read_u16(value, 0)?,
                    poison_id: read_u16(value, 2)?,
                }),
                REC_ORDER => plan.order = value[0],
                REC_PACE => plan.pace_us = read_u32(value, 0)?,
                REC_DELAY => plan.delay_us = read_u32(value, 0)?,
                REC_INPUT => {
                    plan.input_len = read_u32(value, 0)?;
                    plan.input_sni_off = read_u32(value, 4)?;
                    plan.input_sni_len = read_u32(value, 8)?;
                }
                REC_INPUT_TLS => plan.input_tls = true,
                REC_WIRE => plan.wire_profile = value[0],
                REC_SETTLE => plan.settle_us = read_u32(value, 0)?,
                REC_SEGMENT => plan.segment_size = read_u32(value, 0)?,
                REC_GUARD => plan.guards = value[0],
                _ => return Err(PlanError::new("неизвестный тип записи")),
            }
        }

        plan.check_references()?;
        if plan.transport != 6
            && (plan.input_len != 0
                || plan.input_tls
                || plan.settle_us != 0
                || plan.segment_size != 0
                || plan.wire_profile != 0)
        {
            return Err(PlanError::new(
                "измеренные TCP-операции требуют явного транспорта TCP",
            ));
        }
        Ok(plan)
    }

    pub fn poison_used(&self) -> u8 {
        self.poisons
            .iter()
            .fold(0, |used, poison| used | poison.flags)
    }

    pub const fn quic_deny(&self) -> bool {
        self.qdeny != 0
    }

    pub const fn stream_input(&self) -> bool {
        self.transport == 6
            && matches!(self.wire_profile, WIRE_DETECT_TCP | WIRE_TCP_TEMPLATE)
            && (self.input_tls || self.input_len != 0)
    }

    pub fn r2k_is_quic_udp_length_probe(&self) -> bool {
        self.udplen != 0
            && self.transport == 17
            && self.proto == PROTO_QUIC
            && self.qsplit == 0
            && self.qdeny == 0
            && self.ipfrag == 0
            && self.payloads.is_empty()
            && self.poisons.is_empty()
            && self.splits.is_empty()
            && self.fakes.is_empty()
            && self.seq_overlays.is_empty()
            && self.order == 0
            && self.guards == 0
            && self.input_len == 0
            && self.input_sni_off == 0
            && self.input_sni_len == 0
            && !self.input_tls
            && self.settle_us == 0
            && self.segment_size == 0
            && self.wire_profile == 0
            && !self.oob_enabled
            && self.oob_anchor == 0
            && self.oob_byte == 0
            && self.pace_us == 0
            && self.delay_us == 0
    }

    pub fn r2k_is_quic_clearance_probe(&self) -> bool {
        if self.transport != 17
            || self.proto != PROTO_QUIC
            || self.minexec < 10
            || self.ipfrag != 0
            || self.udplen != 0
            || self.qsplit != 0
            || self.qdeny != 0
            || self.order != 0
            || self.guards != 0
            || self.input_len != 0
            || self.input_sni_off != 0
            || self.input_sni_len != 0
            || self.input_tls
            || self.settle_us != 0
            || self.segment_size != 0
            || self.wire_profile != 0
            || self.oob_enabled
            || self.oob_anchor != 0
            || self.oob_byte != 0
            || self.pace_us != 0
            || self.delay_us != 0
            || !self.splits.is_empty()
            || !self.seq_overlays.is_empty()
            || !self.poisons.is_empty()
            || self.payloads.len() != 1
            || self.fakes.len() != 1
        {
            return false;
        }
        let payload = &self.payloads[0];
        let fake = &self.fakes[0];
        payload.bytes.as_slice() == [0; 16]
            && fake.payload_id == payload.id
            && fake.poison_id == 0
            && fake.repeats == 1
            && fake.placement == PLACE_BEFORE
            && fake.gap_us == 0
            && fake.tls_mod == 0
    }

    /// Проверить единственную поддерживаемую форму QUIC-пробы TTL 3.
    pub fn r2k_is_quic_ttl_probe(&self) -> bool {
        self.r2k_is_quic_ttl_probe_for(&[3])
    }

    /// Проверить разрешённые TTL исходной резервной QUIC-лестницы.
    pub fn r2k_is_quic_fallback_ttl_probe(&self) -> bool {
        self.r2k_is_quic_ttl_probe_for(&[3, 5, 8, 12])
    }

    fn r2k_is_quic_ttl_probe_for(&self, allowed_ttl: &[u8]) -> bool {
        if self.transport != 17
            || self.proto != PROTO_QUIC
            || self.minexec < 10
            || self.ipfrag != 0
            || self.udplen != 0
            || self.qsplit != 0
            || self.qdeny != 0
            || self.order != 0
            || self.guards != 0
            || self.input_len != 0
            || self.input_sni_off != 0
            || self.input_sni_len != 0
            || self.input_tls
            || self.settle_us != 0
            || self.segment_size != 0
            || self.wire_profile != 0
            || self.oob_enabled
            || self.oob_anchor != 0
            || self.oob_byte != 0
            || self.pace_us != 0
            || self.delay_us != 0
            || !self.splits.is_empty()
            || !self.seq_overlays.is_empty()
            || self.payloads.len() != 1
            || self.poisons.len() != 1
            || self.fakes.len() != 1
        {
            return false;
        }

        let payload = &self.payloads[0];
        let poison = &self.poisons[0];
        let fake = &self.fakes[0];
        payload.bytes.as_slice() == R2K_QUIC_TTL_PROBE_PAYLOAD
            && allowed_ttl.contains(&poison.ttl)
            && poison.flags == 0
            && poison.seq_shift == 0
            && fake.payload_id == payload.id
            && fake.poison_id == poison.id
            && fake.repeats == 2
            && fake.placement == PLACE_BEFORE
            && fake.gap_us == 0
            && fake.tls_mod == 0
    }

    pub fn r2k_is_quic_address_plan(&self) -> bool {
        self.transport == 17
            && self.proto == PROTO_QUIC
            && ((self.qsplit == 1) != (self.qdeny == 1)
                || self.r2k_is_quic_ipfrag_plan()
                || self.r2k_is_quic_udp_length_probe()
                || self.r2k_is_quic_clearance_probe()
                || self.r2k_is_quic_ttl_probe()
                || self.r2k_is_quic_fallback_ttl_probe()
                || self.r2k_is_quic_fake_probe())
    }

    pub fn r2k_is_quic_fake_probe(&self) -> bool {
        self.transport == 17
            && self.proto == PROTO_QUIC
            && self.qdeny == 0
            && self.ipfrag == 0
            && self.udplen == 0
            && self.poisons.is_empty()
            && !self.fakes.is_empty()
    }

    pub fn r2k_is_quic_ipfrag_plan(&self) -> bool {
        self.transport == 17 && self.proto == PROTO_QUIC && (1..=4).contains(&self.ipfrag)
    }

    fn check_references(&self) -> Result<(), PlanError> {
        for poison in &self.poisons {
            if poison.flags & POISON_MD5 != 0
                && (self.minexec < 12
                    || self.transport != 6
                    || self.wire_profile != WIRE_DETECT_TCP)
            {
                return Err(PlanError::new(
                    "md5 требует minexec=12 и wire detect-tcp-v1 TCP",
                ));
            }
        }

        if self.ipfrag != 0
            && (self.transport != 17
                || !self.splits.is_empty()
                || !self.seq_overlays.is_empty()
                || self.order != 0
                || self.input_len != 0
                || self.input_tls
                || self.settle_us != 0
                || self.segment_size != 0
                || self.wire_profile != 0
                || self.guards != 0)
        {
            return Err(PlanError::new(
                "ipfrag требует UDP без TCP-операций/перестановки",
            ));
        }
        if self.udplen != 0
            && (self.transport != 17
                || self.ipfrag != 0
                || !self.splits.is_empty()
                || !self.seq_overlays.is_empty()
                || self.order != 0
                || self.input_len != 0
                || self.input_tls
                || self.settle_us != 0
                || self.segment_size != 0
                || self.wire_profile != 0
                || self.guards != 0
                || self.oob_enabled)
        {
            return Err(PlanError::new(
                "udplen требует UDP без фрагментации, разрезов и TCP-операций",
            ));
        }
        if self.qsplit != 0
            && (self.transport != 17
                || self.ipfrag != 0
                || self.udplen != 0
                || !self.splits.is_empty()
                || !self.seq_overlays.is_empty()
                || self.order != 0
                || self.input_len != 0
                || self.input_tls
                || self.settle_us != 0
                || self.segment_size != 0
                || self.wire_profile != 0
                || self.guards != 0
                || self.oob_enabled)
        {
            return Err(PlanError::new(
                "quicsplit требует UDP без фрагментации, удлинения и TCP-операций",
            ));
        }
        if self.qdeny != 0
            && (self.transport != 17
                || self.ipfrag != 0
                || self.udplen != 0
                || self.qsplit != 0
                || !self.splits.is_empty()
                || !self.seq_overlays.is_empty()
                || !self.fakes.is_empty()
                || !self.payloads.is_empty()
                || !self.poisons.is_empty()
                || self.order != 0
                || self.input_len != 0
                || self.input_tls
                || self.settle_us != 0
                || self.segment_size != 0
                || self.wire_profile != 0
                || self.guards != 0
                || self.oob_enabled
                || self.pace_us != 0
                || self.delay_us != 0)
        {
            return Err(PlanError::new(
                "quicdeny требует UDP и план без воздействий",
            ));
        }
        if self.oob_enabled
            && (self.minexec < 8
                || self.transport != 6
                || self.proto != 1
                || !self.input_tls
                || self.wire_profile == 0
                || !self.splits.is_empty()
                || !self.seq_overlays.is_empty()
                || !self.fakes.is_empty()
                || self.ipfrag != 0
                || self.pace_us != 0
                || self.settle_us != 0
                || self.delay_us != 0)
        {
            return Err(PlanError::new(
                "oob требует измеренный TCP/TLS-вход и отдельный план",
            ));
        }

        for fake in &self.fakes {
            if fake.payload_id == 0
                || !self
                    .payloads
                    .iter()
                    .any(|payload| payload.id == fake.payload_id)
            {
                return Err(PlanError::new(
                    "фальшивка ссылается на несуществующую приманку",
                ));
            }
            if fake.poison_id != 0
                && !self
                    .poisons
                    .iter()
                    .any(|poison| poison.id == fake.poison_id)
            {
                return Err(PlanError::new(
                    "фальшивка ссылается на несуществующую порчу",
                ));
            }
            if fake.placement == PLACE_BETWEEN && self.splits.is_empty() {
                return Err(PlanError::new("фальшивка между кусками, а разрезов нет"));
            }
            if !matches!(fake.placement, PLACE_BEFORE | PLACE_BETWEEN) {
                return Err(PlanError::new("неизвестное размещение фальшивки"));
            }
        }
        for overlay in &self.seq_overlays {
            if overlay.payload_id == 0
                || !self
                    .payloads
                    .iter()
                    .any(|payload| payload.id == overlay.payload_id)
            {
                return Err(PlanError::new(
                    "перекрытие ссылается на несуществующую приманку",
                ));
            }
            if overlay.poison_id != 0
                && !self
                    .poisons
                    .iter()
                    .any(|poison| poison.id == overlay.poison_id)
            {
                return Err(PlanError::new(
                    "перекрытие ссылается на несуществующую порчу",
                ));
            }
        }
        if !matches!(self.order, ORDER_FORWARD | ORDER_REVERSE) {
            return Err(PlanError::new("неизвестный порядок посылки"));
        }
        if self.seq_overlays.len() > 1 {
            return Err(PlanError::new("перекрытие может быть только одно"));
        }
        Ok(())
    }
}

#[derive(Default)]
struct Counts {
    payloads: usize,
    poisons: usize,
    splits: usize,
    fakes: usize,
    seq_overlays: usize,
    oob: usize,
}

fn scan(bytes: &[u8], minexec: u16) -> Result<(Counts, usize), PlanError> {
    let mut counts = Counts::default();
    let mut records_seen = 0;
    let mut offset = HEADER_LEN;
    while let Some((kind, value)) = next_record(bytes, &mut offset)? {
        if matches!(kind, REC_INPUT | REC_SETTLE | REC_SEGMENT) && minexec < 3 {
            return Err(PlanError::new("измеренный план требует minexec=3"));
        }
        match kind {
            REC_IPFRAG if minexec < 7 || value.len() != 1 || !(1..=4).contains(&value[0]) => {
                return Err(PlanError::new("ipfrag требует minexec=7 и форму 1..4"));
            }
            REC_UDPLEN if minexec < 9 || value.len() != 2 || read_u16(value, 0)? == 0 => {
                return Err(PlanError::new(
                    "udplen требует minexec=9 и ненулевого прироста",
                ));
            }
            REC_QSPLIT if minexec < 10 || value.len() != 1 || value[0] != 1 => {
                return Err(PlanError::new("quicsplit требует minexec=10 и форму 1"));
            }
            REC_QDENY if minexec < 11 || value.len() != 1 || value[0] != 1 => {
                return Err(PlanError::new("quicdeny требует minexec=11 и форму 1"));
            }
            REC_OOB => {
                if minexec < 8 || value.len() != 3 || read_u16(value, 0)? > ANCHOR_SNI_MIDDLE {
                    return Err(PlanError::new("oob требует minexec=8, якорь и один байт"));
                }
                counts.oob += 1;
                if counts.oob > 1 {
                    return Err(PlanError::new("повторная запись oob"));
                }
            }
            REC_ID if value.len() != PLAN_ID_LEN => {
                return Err(PlanError::new("id не 16 байт"));
            }
            REC_PROTO => {
                if value.len() != 2 {
                    return Err(PlanError::new("proto не 2 байта"));
                }
                if value[1] == PROTO_HTTP && (minexec < 11 || value[0] != 6) {
                    return Err(PlanError::new("протокол http требует TCP и minexec=11"));
                }
            }
            REC_PAYLOAD => {
                if value.len() < 2 {
                    return Err(PlanError::new("приманка без номера"));
                }
                counts.payloads += 1;
            }
            REC_POISON => {
                if value.len() != 8 {
                    return Err(PlanError::new("порча не 8 байт"));
                }
                if value[3] & POISON_MD5 != 0 && minexec < 12 {
                    return Err(PlanError::new("md5 требует minexec=12"));
                }
                counts.poisons += 1;
            }
            REC_SPLIT => {
                require_len(value, 4, "разрез не 4 байта")?;
                counts.splits += 1;
            }
            REC_FAKE => {
                if !matches!(value.len(), 10 | 11) {
                    return Err(PlanError::new("фальшивка не 10/11 байт"));
                }
                if value.len() == 11 && minexec < 8 {
                    return Err(PlanError::new("tlsmod требует minexec=8"));
                }
                if value.len() == 11 && value[10] & !(TLS_MOD_RND | TLS_MOD_DUPSID) != 0 {
                    return Err(PlanError::new("неизвестный tlsmod"));
                }
                counts.fakes += 1;
            }
            REC_SEQOVL => {
                require_len(value, 4, "перекрытие не 4 байта")?;
                counts.seq_overlays += 1;
            }
            REC_ORDER => require_len(value, 1, "порядок не 1 байт")?,
            REC_PACE => require_len(value, 4, "разнос во времени не 4 байта")?,
            REC_DELAY => {
                if minexec < 6 || value.len() != 4 || read_u32(value, 0)? == 0 {
                    return Err(PlanError::new(
                        "выдержка требует minexec=6 и ненулевого числа",
                    ));
                }
            }
            REC_INPUT => {
                if value.len() != 12 {
                    return Err(PlanError::new("недопустимый контекст измеренного входа"));
                }
                let input_len = read_u32(value, 0)?;
                let sni_off = read_u32(value, 4)?;
                let sni_len = read_u32(value, 8)?;
                if input_len == 0 || sni_off > input_len || sni_len > input_len - sni_off {
                    return Err(PlanError::new("недопустимый контекст измеренного входа"));
                }
            }
            REC_WIRE => {
                if minexec < 4
                    || value.len() != 1
                    || !matches!(value[0], WIRE_DETECT_TCP | WIRE_TCP_TEMPLATE)
                    || (value[0] == WIRE_TCP_TEMPLATE && minexec < 8)
                {
                    return Err(PlanError::new(
                        "неподдержанный TCP wire profile или minexec < 4",
                    ));
                }
            }
            REC_INPUT_TLS => {
                if minexec < 5 || !value.is_empty() {
                    return Err(PlanError::new(
                        "input tls-sni требует minexec=5 и пустую запись",
                    ));
                }
            }
            REC_SETTLE => {
                if value.len() != 4 || read_u32(value, 0)? == 0 {
                    return Err(PlanError::new("недопустимая пауза перед правдой"));
                }
            }
            REC_SEGMENT => {
                let length = if value.len() == 4 {
                    read_u32(value, 0)?
                } else {
                    0
                };
                if length == 0 || length > 65_535 {
                    return Err(PlanError::new("недопустимый размер сегмента"));
                }
            }
            REC_GUARD => {
                if value.len() != 1 {
                    return Err(PlanError::new("защита не 1 байт"));
                }
                if value[0] == 0 || value[0] & !GUARD_RST_ALIEN != 0 {
                    return Err(PlanError::new("неизвестные биты защиты"));
                }
            }
            REC_ID | REC_IPFRAG | REC_UDPLEN | REC_QSPLIT | REC_QDENY => {}
            _ => return Err(PlanError::new("неизвестный тип записи")),
        }
        records_seen += 1;
        if records_seen > usize::from(u16::MAX) {
            return Err(PlanError::new("слишком много записей"));
        }
    }
    Ok((counts, records_seen))
}

fn next_record<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
) -> Result<Option<(u16, &'a [u8])>, PlanError> {
    if *offset == bytes.len() {
        return Ok(None);
    }
    let header_end = offset
        .checked_add(4)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| PlanError::new("обрезанный заголовок записи"))?;
    let kind = read_u16(bytes, *offset)?;
    let value_len = usize::from(read_u16(bytes, *offset + 2)?);
    let value_end = header_end
        .checked_add(value_len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| PlanError::new("запись выходит за буфер"))?;
    let value = &bytes[header_end..value_end];
    *offset = value_end;
    Ok(Some((kind, value)))
}

fn require_len(value: &[u8], expected: usize, message: &'static str) -> Result<(), PlanError> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(PlanError::new(message))
    }
}

fn set_once_u8(slot: &mut u8, value: u8, message: &'static str) -> Result<(), PlanError> {
    if *slot != 0 {
        return Err(PlanError::new(message));
    }
    *slot = value;
    Ok(())
}

fn set_once_u16(slot: &mut u16, value: u16, message: &'static str) -> Result<(), PlanError> {
    if *slot != 0 {
        return Err(PlanError::new(message));
    }
    *slot = value;
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, PlanError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| PlanError::new("обрезанное поле"))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| PlanError::new("обрезанное поле"))?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PlanError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| PlanError::new("обрезанное поле"))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| PlanError::new("обрезанное поле"))?;
    Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
}
