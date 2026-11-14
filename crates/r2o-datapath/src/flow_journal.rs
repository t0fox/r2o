use crate::engine::{R2oTcpExchangeEvent, R2oTcpRstCutEvent, R2oTcpRstEvent};
use crate::r2o_quic::R2oUdpExchangeEvent;
use r2k_core::control::{
    AppliedEvent, BindingContext, EVENT_APPLIED, EVENT_HELLO, EVENT_LEGACY_EXCHANGE,
    EVENT_LEGACY_SUSPECT, EVENT_R2O_JOURNAL_END, EVENT_R2O_JOURNAL_ENTRY, EVENT_R2O_QUIC_STALL,
    EVENT_R2O_QUIC_SUSPECT, EVENT_R2O_TCP_CLEAN_HANDSHAKE, EVENT_R2O_TCP_EARLY_RST,
    EVENT_R2O_TCP_FIN_RETRY, EVENT_R2O_TCP_REPEAT, EVENT_R2O_TCP_RST_AFTER_APP,
    EVENT_R2O_TCP_RST_CUT, EVENT_R2O_TCP_SILENT, EVENT_R2O_TCP_STALL, EVENT_R2O_VOICE_PROOF,
    EVENT_R2O_VOICE_RTP_PROOF, EVENT_R2O_VOICE_STUN_PROOF, EVENT_R2O_VOICE_SUSPECT, EVENT_REFUSED,
    Frame, KEY_LEN, decode_applied, decode_r2o_quic_stall, decode_r2o_quic_suspect,
    decode_r2o_tcp_clean_handshake, decode_r2o_tcp_early_rst, decode_r2o_tcp_fin_retry,
    decode_r2o_tcp_repeat, decode_r2o_tcp_rst_after_app, decode_r2o_tcp_rst_cut_signal,
    decode_r2o_tcp_silence, decode_r2o_tcp_stall, decode_r2o_voice_proof, decode_r2o_voice_suspect,
};

pub const R2O_JOURNAL_NAME_MAX: usize = 63;
pub const R2O_JOURNAL_REFUSE_NONE: u8 = 0;
pub const R2O_JOURNAL_REFUSE_SEND: u8 = 1;
pub const R2O_JOURNAL_REFUSE_QUEUE: u8 = 2;
pub const R2O_JOURNAL_REFUSE_TOO_LONG: u8 = 3;
pub const R2O_JOURNAL_REFUSE_DAMAGED: u8 = 4;
pub const R2O_JOURNAL_REFUSE_NOT_APPLIED: u8 = 5;
pub const R2O_JOURNAL_REFUSE_FLOW_UNFIT: u8 = 6;
const R2O_JOURNAL_WIRE_VERSION: u8 = 1;
const R2O_JOURNAL_ENTRY_BODY_LEN: usize = 205;

/// Тексты D2O `d2k_suspect_text`, байт-в-байт.
pub fn r2o_suspect_text(code: u8) -> &'static str {
    match code {
        1 => "сброс в ответ на приветствие",
        2 => "приветствие повторено",
        3 => "ответа на приветствие не было",
        4 => "снят чужой сброс в ответ на приветствие",
        5 => "сброс клиента или сервера после TLS app-data; проверить объём ответа",
        7 => {
            "QUIC: сервер замолчал после рукопожатия, клиент повторяет; проверить ответ своим запросом"
        }
        8 => "TCP: сервер замолчал на бюджете коробки, соединение открыто; проверить объём ответа",
        6 => "FIN клиента повторён без ответа после ответа сервера; проверить объём ответа",
        _ => "подозрение без кода",
    }
}

/// Тексты D2O `d2k_refuse_text`, байт-в-байт.
pub fn r2o_refuse_text(code: u8) -> &'static str {
    match code {
        0 => "причина не названа",
        1 => "ядро отвергло посылку",
        2 => "очередь отложенной отправки не приняла посылку",
        3 => "посылка длиннее того, что унесёт способ отправки",
        4 => "поток испорчен недоисполнением плана",
        5 => "исполнитель отверг план на этом пакете (причина — в записи)",
        6 => "поток клиента не несёт того, что план требует (причина — в записи)",
        _ => "отказ без кода",
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum R2oFlowJournalKind {
    #[default]
    Observation,
    Hello,
    PlanApplied,
    PlanRefused,
    Exchange,
    Shape,
    Suspect,
    PlanDone,
    PlanUnsent,
    PlanDamaged,
    R2oVoiceSuspect,
    R2oQuicSuspect,
    R2oQuicStall,
    R2oTcpSilent,
    R2oTcpStall,
    R2oTcpFinRetry,
    R2oTcpRstAfterApp,
    R2oVoiceProof,
    R2oTcpRstCut,
    R2oTcpRst,
}

impl R2oFlowJournalKind {
    /// Имена D2O `jrn_kind`; R2O-only виды сохраняют свои названия.
    pub fn c_name(self) -> &'static str {
        match self {
            Self::Hello => "приветствие",
            Self::PlanApplied => "план применён",
            Self::PlanRefused => "план не применён",
            Self::Exchange => "обмен пошёл",
            Self::Shape => "снята форма приветствия",
            Self::Suspect => "подозрение",
            Self::PlanDone => "",
            Self::PlanUnsent => "посылка не ушла",
            Self::PlanDamaged => "поток испорчен",
            _ => self.russian_name(),
        }
    }

    /// C `jrn_kind`: HELLO_NONAME отличается от HELLO_SNI по наличию имени.
    pub fn c_name_with_name(self, has_name: bool) -> &'static str {
        if self == Self::Hello && !has_name {
            return "приветствие без имени";
        }
        self.c_name()
    }

    pub fn russian_name(self) -> &'static str {
        match self {
            Self::Observation => "наблюдение",
            Self::Hello => "ClientHello",
            Self::PlanApplied => "план подготовлен",
            Self::PlanRefused => "план отклонён",
            Self::Exchange => "обмен данными",
            Self::Shape => "форма приветствия",
            Self::Suspect => "подозрение",
            Self::PlanDone => "план выполнен",
            Self::PlanUnsent => "план отправлен не полностью",
            Self::PlanDamaged => "поток повреждён",
            Self::R2oVoiceSuspect => "подозрение голосового UDP-потока",
            Self::R2oQuicSuspect => "подозрение молчания QUIC",
            Self::R2oQuicStall => "зависание QUIC после ответа",
            Self::R2oTcpSilent => "молчание TCP",
            Self::R2oTcpStall => "зависание TCP на бюджете",
            Self::R2oTcpFinRetry => "повтор FIN TCP",
            Self::R2oTcpRstAfterApp => "RST TCP после TLS-данных",
            Self::R2oVoiceProof => "подтверждение голосового UDP-обмена",
            Self::R2oTcpRstCut => "чужой RST TCP снят защитой",
            Self::R2oTcpRst => "RST TCP в ответ на ClientHello",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oFlowJournalEntry {
    pub at_ns: u64,
    pub execution_id: u64,
    pub binding: Option<BindingContext>,
    pub key: [u8; KEY_LEN],
    pub kind: R2oFlowJournalKind,
    pub code: u8,
    pub name_len: u8,
    pub num: u32,
    pub ttl: u8,
    pub reference_ttl: u8,
    pub tos: u8,
    pub server_hello: bool,
    pub planned: u8,
    pub client_shape: u8,
    pub client_is_low: Option<bool>,
    pub elapsed_ms: u32,
    pub ip_id: u16,
    pub mapped_ip: [u8; 4],
    pub mapped_port: u16,
    pub plan_id: [u8; 16],
    pub trial_id: [u8; 16],
    pub name: [u8; R2O_JOURNAL_NAME_MAX + 1],
    pub note: Option<&'static str>,
}

impl R2oFlowJournalEntry {
    /// C `d2k_ctlsrv_pump` (`ctlsrv.c:511-694`) для v22: journal entry →
    /// один или несколько D2O-совместимых кадров. SHAPE/CLIENT_TCP требуют
    /// session-shape, которого в записи журнала нет, и здесь не выдаются.
    pub fn to_v22_frames(&self) -> Vec<(u16, Vec<u8>)> {
        let mut body = Vec::with_capacity(KEY_LEN + 64);
        body.extend_from_slice(&self.key);
        let kind = match self.kind {
            R2oFlowJournalKind::Hello => {
                body.push(self.name_len);
                let length = usize::from(self.name_len).min(R2O_JOURNAL_NAME_MAX);
                body.extend_from_slice(&self.name[..length]);
                EVENT_HELLO
            }
            R2oFlowJournalKind::Suspect => {
                body.push(self.code);
                body.push(self.ttl);
                body.push(self.reference_ttl);
                body.push(self.tos);
                body.extend_from_slice(&self.ip_id.to_be_bytes());
                body.push(self.planned);
                body.push(self.client_shape);
                let num = self.num.min(u32::from(u16::MAX)) as u16;
                body.extend_from_slice(&num.to_be_bytes());
                EVENT_LEGACY_SUSPECT
            }
            R2oFlowJournalKind::PlanApplied => return Vec::new(),
            R2oFlowJournalKind::PlanDone => {
                body.extend_from_slice(&self.plan_id);
                body.extend_from_slice(&self.trial_id);
                body.extend_from_slice(&self.execution_id.to_be_bytes());
                append_binding(&mut body, self.binding.as_ref());
                EVENT_APPLIED
            }
            R2oFlowJournalKind::PlanRefused
            | R2oFlowJournalKind::PlanUnsent
            | R2oFlowJournalKind::PlanDamaged => {
                body.push(self.code);
                body.extend_from_slice(&self.plan_id);
                body.extend_from_slice(&self.trial_id);
                body.push(self.client_shape);
                body.extend_from_slice(&self.execution_id.to_be_bytes());
                append_binding(&mut body, self.binding.as_ref());
                EVENT_REFUSED
            }
            R2oFlowJournalKind::Exchange => {
                body.push(self.code);
                body.push(self.tos);
                body.extend_from_slice(&self.num.to_be_bytes());
                body.push(u8::from(self.server_hello));
                body.push(self.planned);
                EVENT_LEGACY_EXCHANGE
            }
            _ => return Vec::new(),
        };
        vec![(kind, body)]
    }
}

fn append_binding(body: &mut Vec<u8>, binding: Option<&BindingContext>) {
    let binding = binding.copied().unwrap_or_default();
    body.extend_from_slice(&binding.generation.to_be_bytes());
    body.push(binding.kind);
    body.push(binding.family);
    body.push(binding.shape);
    body.push(u8::from(binding.temporary));
    body.extend_from_slice(&binding.epoch);
}

impl Default for R2oFlowJournalEntry {
    fn default() -> Self {
        Self {
            at_ns: 0,
            execution_id: 0,
            binding: None,
            key: [0; KEY_LEN],
            kind: R2oFlowJournalKind::Observation,
            code: 0,
            name_len: 0,
            num: 0,
            ttl: 0,
            reference_ttl: 0,
            tos: 0,
            server_hello: false,
            planned: 0,
            client_shape: 0,
            client_is_low: None,
            elapsed_ms: 0,
            ip_id: 0,
            mapped_ip: [0; 4],
            mapped_port: 0,
            plan_id: [0; 16],
            trial_id: [0; 16],
            name: [0; R2O_JOURNAL_NAME_MAX + 1],
            note: None,
        }
    }
}

impl R2oFlowJournalEntry {
    pub fn set_name(&mut self, name: &[u8]) {
        self.name = [0; R2O_JOURNAL_NAME_MAX + 1];
        let length = name.len().min(R2O_JOURNAL_NAME_MAX);
        for (destination, source) in self.name.iter_mut().zip(&name[..length]) {
            *destination = if (0x20..0x7f).contains(source) {
                *source
            } else {
                b'.'
            };
        }
        self.name_len = length as u8;
    }

    /// Закодировать полную запись кольца в управляющее событие.
    ///
    /// Контрольный формат v1 не несёт `note`: тексты suspect/refuse остаются
    /// локальной диагностикой, как и в C printf-журнале. Поле не мешает
    /// снимку и не подменяет остальные поля.
    pub fn to_event_frame(&self) -> Result<Frame, &'static str> {
        let name_length = usize::from(self.name_len);
        if name_length > R2O_JOURNAL_NAME_MAX
            || self.name[name_length..].iter().any(|byte| *byte != 0)
            || self.name[..name_length]
                .iter()
                .any(|byte| !(0x20..0x7f).contains(byte))
        {
            return Err("запись журнала содержит неверное имя");
        }

        let mut body = Vec::with_capacity(R2O_JOURNAL_ENTRY_BODY_LEN);
        body.push(R2O_JOURNAL_WIRE_VERSION);
        body.push(journal_kind_id(self.kind));
        body.extend_from_slice(&self.at_ns.to_be_bytes());
        body.extend_from_slice(&self.execution_id.to_be_bytes());
        body.extend_from_slice(&self.key);
        body.push(self.code);
        body.push(self.name_len);
        body.extend_from_slice(&self.name[..R2O_JOURNAL_NAME_MAX]);
        body.extend_from_slice(&self.num.to_be_bytes());
        body.push(self.ttl);
        body.push(self.reference_ttl);
        body.push(self.tos);
        body.push(u8::from(self.server_hello));
        body.push(self.planned);
        body.push(self.client_shape);
        body.push(match self.client_is_low {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        });
        body.extend_from_slice(&self.elapsed_ms.to_be_bytes());
        body.extend_from_slice(&self.ip_id.to_be_bytes());
        body.extend_from_slice(&self.mapped_ip);
        body.extend_from_slice(&self.mapped_port.to_be_bytes());
        body.extend_from_slice(&self.plan_id);
        body.extend_from_slice(&self.trial_id);
        if let Some(binding) = self.binding {
            if !binding.is_known() || !matches!(binding.family, 4 | 6) {
                return Err("запись журнала содержит неверную привязку");
            }
            body.push(1);
            body.extend_from_slice(&binding.generation.to_be_bytes());
            body.push(binding.kind);
            body.push(binding.family);
            body.push(binding.shape);
            body.push(u8::from(binding.temporary));
            body.extend_from_slice(&binding.epoch);
        } else {
            body.push(0);
            body.extend_from_slice(&[0; 28]);
        }
        if body.len() != R2O_JOURNAL_ENTRY_BODY_LEN {
            return Err("неверная внутренняя длина записи журнала");
        }
        Ok(Frame {
            kind: EVENT_R2O_JOURNAL_ENTRY,
            body,
        })
    }

    /// Проверить и декодировать запись управляющего события.
    pub fn from_event_frame(frame: &Frame) -> Result<Self, &'static str> {
        if frame.kind != EVENT_R2O_JOURNAL_ENTRY || frame.body.len() != R2O_JOURNAL_ENTRY_BODY_LEN {
            return Err("неверный размер события журнала");
        }
        let mut cursor = 0;
        let body = frame.body.as_slice();
        if take_journal(body, &mut cursor, 1)?[0] != R2O_JOURNAL_WIRE_VERSION {
            return Err("неподдерживаемая версия записи журнала");
        }
        let kind = journal_kind_from_id(take_journal(body, &mut cursor, 1)?[0])?;
        let at_ns = take_journal_u64(body, &mut cursor)?;
        let execution_id = take_journal_u64(body, &mut cursor)?;
        let key = take_journal(body, &mut cursor, KEY_LEN)?
            .try_into()
            .map_err(|_| "неверный ключ записи журнала")?;
        if !valid_journal_key(&key) {
            return Err("запись журнала содержит неверный ключ потока");
        }
        let code = take_journal(body, &mut cursor, 1)?[0];
        let name_len = take_journal(body, &mut cursor, 1)?[0];
        let name_bytes = take_journal(body, &mut cursor, R2O_JOURNAL_NAME_MAX)?;
        let name_length = usize::from(name_len);
        if name_length > R2O_JOURNAL_NAME_MAX
            || name_bytes[name_length..].iter().any(|byte| *byte != 0)
            || name_bytes[..name_length]
                .iter()
                .any(|byte| !(0x20..0x7f).contains(byte))
        {
            return Err("событие журнала содержит неверное имя");
        }
        let num = take_journal_u32(body, &mut cursor)?;
        let ttl = take_journal(body, &mut cursor, 1)?[0];
        let reference_ttl = take_journal(body, &mut cursor, 1)?[0];
        let tos = take_journal(body, &mut cursor, 1)?[0];
        let server_hello = decode_journal_bool(take_journal(body, &mut cursor, 1)?[0])?;
        let planned = take_journal(body, &mut cursor, 1)?[0];
        let client_shape = take_journal(body, &mut cursor, 1)?[0];
        let client_is_low = match take_journal(body, &mut cursor, 1)?[0] {
            0 => None,
            1 => Some(false),
            2 => Some(true),
            _ => return Err("неверное направление в событии журнала"),
        };
        let elapsed_ms = take_journal_u32(body, &mut cursor)?;
        let ip_id = take_journal_u16(body, &mut cursor)?;
        let mapped_ip = take_journal(body, &mut cursor, 4)?
            .try_into()
            .map_err(|_| "неверный адрес в событии журнала")?;
        let mapped_port = take_journal_u16(body, &mut cursor)?;
        let plan_id = take_journal(body, &mut cursor, 16)?
            .try_into()
            .map_err(|_| "неверный идентификатор плана в событии журнала")?;
        let trial_id = take_journal(body, &mut cursor, 16)?
            .try_into()
            .map_err(|_| "неверный идентификатор испытания в событии журнала")?;
        let binding_present = decode_journal_bool(take_journal(body, &mut cursor, 1)?[0])?;
        let binding_bytes = take_journal(body, &mut cursor, 28)?;
        let binding = if binding_present {
            let binding = BindingContext {
                generation: u64::from_be_bytes(
                    binding_bytes[..8]
                        .try_into()
                        .map_err(|_| "неверное поколение привязки журнала")?,
                ),
                kind: binding_bytes[8],
                family: binding_bytes[9],
                shape: binding_bytes[10],
                temporary: decode_journal_bool(binding_bytes[11])?,
                epoch: binding_bytes[12..28]
                    .try_into()
                    .map_err(|_| "неверная эпоха привязки журнала")?,
            };
            if !binding.is_known() || !matches!(binding.family, 4 | 6) {
                return Err("событие журнала содержит неверную привязку");
            }
            Some(binding)
        } else {
            if binding_bytes.iter().any(|byte| *byte != 0) {
                return Err("событие журнала содержит данные отсутствующей привязки");
            }
            None
        };
        if cursor != body.len() {
            return Err("лишние данные после события журнала");
        }
        let mut name = [0; R2O_JOURNAL_NAME_MAX + 1];
        name[..R2O_JOURNAL_NAME_MAX].copy_from_slice(name_bytes);
        Ok(Self {
            at_ns,
            execution_id,
            binding,
            key,
            kind,
            code,
            name_len: name_len.min(R2O_JOURNAL_NAME_MAX as u8),
            num,
            ttl,
            reference_ttl,
            tos,
            server_hello,
            planned,
            client_shape,
            client_is_low,
            elapsed_ms,
            ip_id,
            mapped_ip,
            mapped_port,
            plan_id,
            trial_id,
            name,
            note: None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oFlowJournalSummary {
    pub added: u64,
    pub dropped: u64,
    pub count: u32,
}

impl R2oFlowJournalSummary {
    /// Сформировать завершающий кадр снимка журнала.
    pub fn to_event_frame(self) -> Frame {
        let mut body = Vec::with_capacity(20);
        body.extend_from_slice(&self.added.to_be_bytes());
        body.extend_from_slice(&self.dropped.to_be_bytes());
        body.extend_from_slice(&self.count.to_be_bytes());
        Frame {
            kind: EVENT_R2O_JOURNAL_END,
            body,
        }
    }

    /// Проверить и декодировать границу снимка журнала.
    pub fn from_event_frame(frame: &Frame) -> Result<Self, &'static str> {
        if frame.kind != EVENT_R2O_JOURNAL_END || frame.body.len() != 20 {
            return Err("неверное событие завершения снимка журнала");
        }
        Ok(Self {
            added: u64::from_be_bytes(
                frame.body[..8]
                    .try_into()
                    .map_err(|_| "неверный счётчик журнала")?,
            ),
            dropped: u64::from_be_bytes(
                frame.body[8..16]
                    .try_into()
                    .map_err(|_| "неверный счётчик вытесненных записей")?,
            ),
            count: u32::from_be_bytes(
                frame.body[16..20]
                    .try_into()
                    .map_err(|_| "неверное число записей снимка")?,
            ),
        })
    }
}

fn journal_kind_id(kind: R2oFlowJournalKind) -> u8 {
    match kind {
        R2oFlowJournalKind::Observation => 0,
        R2oFlowJournalKind::Hello => 1,
        R2oFlowJournalKind::PlanApplied => 2,
        R2oFlowJournalKind::PlanRefused => 3,
        R2oFlowJournalKind::Exchange => 4,
        R2oFlowJournalKind::Shape => 5,
        R2oFlowJournalKind::Suspect => 6,
        R2oFlowJournalKind::PlanDone => 7,
        R2oFlowJournalKind::PlanUnsent => 8,
        R2oFlowJournalKind::PlanDamaged => 9,
        R2oFlowJournalKind::R2oVoiceSuspect => 10,
        R2oFlowJournalKind::R2oQuicSuspect => 11,
        R2oFlowJournalKind::R2oTcpSilent => 12,
        R2oFlowJournalKind::R2oTcpStall => 13,
        R2oFlowJournalKind::R2oTcpFinRetry => 14,
        R2oFlowJournalKind::R2oTcpRstAfterApp => 15,
        R2oFlowJournalKind::R2oVoiceProof => 16,
        R2oFlowJournalKind::R2oQuicStall => 17,
        R2oFlowJournalKind::R2oTcpRstCut => 18,
        R2oFlowJournalKind::R2oTcpRst => 19,
    }
}

fn journal_kind_from_id(id: u8) -> Result<R2oFlowJournalKind, &'static str> {
    match id {
        0 => Ok(R2oFlowJournalKind::Observation),
        1 => Ok(R2oFlowJournalKind::Hello),
        2 => Ok(R2oFlowJournalKind::PlanApplied),
        3 => Ok(R2oFlowJournalKind::PlanRefused),
        4 => Ok(R2oFlowJournalKind::Exchange),
        5 => Ok(R2oFlowJournalKind::Shape),
        6 => Ok(R2oFlowJournalKind::Suspect),
        7 => Ok(R2oFlowJournalKind::PlanDone),
        8 => Ok(R2oFlowJournalKind::PlanUnsent),
        9 => Ok(R2oFlowJournalKind::PlanDamaged),
        10 => Ok(R2oFlowJournalKind::R2oVoiceSuspect),
        11 => Ok(R2oFlowJournalKind::R2oQuicSuspect),
        12 => Ok(R2oFlowJournalKind::R2oTcpSilent),
        13 => Ok(R2oFlowJournalKind::R2oTcpStall),
        14 => Ok(R2oFlowJournalKind::R2oTcpFinRetry),
        15 => Ok(R2oFlowJournalKind::R2oTcpRstAfterApp),
        16 => Ok(R2oFlowJournalKind::R2oVoiceProof),
        17 => Ok(R2oFlowJournalKind::R2oQuicStall),
        18 => Ok(R2oFlowJournalKind::R2oTcpRstCut),
        19 => Ok(R2oFlowJournalKind::R2oTcpRst),
        _ => Err("неизвестный вид записи журнала"),
    }
}

fn take_journal<'a>(
    body: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], &'static str> {
    let end = cursor
        .checked_add(length)
        .ok_or("переполнение смещения записи журнала")?;
    let value = body.get(*cursor..end).ok_or("обрезанное событие журнала")?;
    *cursor = end;
    Ok(value)
}

fn take_journal_u16(body: &[u8], cursor: &mut usize) -> Result<u16, &'static str> {
    Ok(u16::from_be_bytes(
        take_journal(body, cursor, 2)?
            .try_into()
            .map_err(|_| "неверное число в событии журнала")?,
    ))
}

fn take_journal_u32(body: &[u8], cursor: &mut usize) -> Result<u32, &'static str> {
    Ok(u32::from_be_bytes(
        take_journal(body, cursor, 4)?
            .try_into()
            .map_err(|_| "неверное число в событии журнала")?,
    ))
}

fn take_journal_u64(body: &[u8], cursor: &mut usize) -> Result<u64, &'static str> {
    Ok(u64::from_be_bytes(
        take_journal(body, cursor, 8)?
            .try_into()
            .map_err(|_| "неверное число в событии журнала")?,
    ))
}

fn decode_journal_bool(value: u8) -> Result<bool, &'static str> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("неверный логический признак события журнала"),
    }
}

fn valid_journal_key(key: &[u8; KEY_LEN]) -> bool {
    matches!(key[0], 4 | 6)
        && matches!(key[37], 6 | 17)
        && (key[0] != 4
            || (key[5..17].iter().all(|byte| *byte == 0)
                && key[21..33].iter().all(|byte| *byte == 0)))
}

/// Заметка по умолчанию, как в C `add_entry`/`d2k_journal_add_fate_bound`.
fn default_journal_note(kind: R2oFlowJournalKind, code: u8) -> Option<&'static str> {
    use R2oFlowJournalKind::*;
    match kind {
        Suspect | R2oQuicSuspect | R2oTcpSilent | R2oTcpStall | R2oTcpFinRetry
        | R2oTcpRstAfterApp | R2oQuicStall | R2oTcpRstCut | R2oTcpRst => {
            Some(r2o_suspect_text(code))
        }
        PlanRefused | PlanUnsent | PlanDamaged => Some(r2o_refuse_text(code)),
        PlanDone => Some("план доисполнен"),
        _ => None,
    }
}

pub struct R2oFlowJournal {
    entries: Vec<R2oFlowJournalEntry>,
    length: usize,
    head: usize,
    dropped: u64,
    added: u64,
}

impl R2oFlowJournal {
    pub fn with_capacity(capacity: usize) -> Result<Self, std::collections::TryReserveError> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(capacity)?;
        entries.resize_with(capacity, R2oFlowJournalEntry::default);
        Ok(Self {
            entries,
            length: 0,
            head: 0,
            dropped: 0,
            added: 0,
        })
    }

    pub fn push(&mut self, mut entry: R2oFlowJournalEntry) {
        if entry.note.is_none() {
            entry.note = default_journal_note(entry.kind, entry.code);
        }
        self.added = self.added.wrapping_add(1);
        let capacity = self.entries.len();
        if capacity == 0 {
            return;
        }
        if self.length == capacity {
            self.dropped = self.dropped.wrapping_add(1);
        } else {
            self.length += 1;
        }
        self.entries[self.head] = entry;
        self.head = (self.head + 1) % capacity;
    }

    pub fn record_hello_body(&mut self, at_ns: u64, body: &[u8]) -> bool {
        let Some(key_bytes) = body.get(..KEY_LEN) else {
            return false;
        };
        let Ok(key) = <[u8; KEY_LEN]>::try_from(key_bytes) else {
            return false;
        };
        if !matches!(key[0], 4 | 6)
            || !matches!(key[37], 6 | 17)
            || (key[0] == 4
                && (key[5..17].iter().any(|byte| *byte != 0)
                    || key[21..33].iter().any(|byte| *byte != 0)))
        {
            return false;
        }
        let Some(&name_length) = body.get(KEY_LEN) else {
            return false;
        };
        let name_start = KEY_LEN + 1;
        let Some(name_end) = name_start.checked_add(usize::from(name_length)) else {
            return false;
        };
        let Some(name) = body.get(name_start..name_end) else {
            return false;
        };
        let Some(details) = body.get(name_end..) else {
            return false;
        };
        let client_shape = details.first().copied().unwrap_or_default();
        let num = match details.len() {
            0 | 1 => 0,
            3 if body[37] == 6 => u32::from(u16::from_be_bytes([details[1], details[2]])),
            length if body[37] == 17 && length >= 3 => {
                let snapshot_len = usize::from(u16::from_be_bytes([details[1], details[2]]));
                if snapshot_len == 0 || snapshot_len != length - 3 {
                    return false;
                }
                snapshot_len as u32
            }
            _ => return false,
        };
        let mut entry = R2oFlowJournalEntry {
            at_ns,
            key,
            kind: R2oFlowJournalKind::Hello,
            client_shape,
            num,
            ..R2oFlowJournalEntry::default()
        };
        entry.set_name(name);
        self.push(entry);
        true
    }

    pub fn record_shape(&mut self, at_ns: u64, key: [u8; KEY_LEN]) -> bool {
        if !valid_journal_key(&key) {
            return false;
        }
        self.push(R2oFlowJournalEntry {
            at_ns,
            key,
            kind: R2oFlowJournalKind::Shape,
            ..R2oFlowJournalEntry::default()
        });
        true
    }

    pub fn record_applied(&mut self, at_ns: u64, event: &AppliedEvent) -> bool {
        // C `d2k_journal_add_fate_bound`: plan/trial/execution/binding
        // пишутся байт-в-байт, без проверки события.
        self.push(R2oFlowJournalEntry {
            at_ns,
            execution_id: event.execution_id,
            binding: Some(event.binding),
            key: event.key,
            kind: R2oFlowJournalKind::PlanDone,
            plan_id: event.plan_id,
            trial_id: event.trial_id,
            ..R2oFlowJournalEntry::default()
        });
        true
    }

    pub fn record_plan_prepared(&mut self, at_ns: u64, event: &AppliedEvent) -> bool {
        // C `d2k_journal_add_applied`: plan/trial копируются без проверок.
        self.push(R2oFlowJournalEntry {
            at_ns,
            execution_id: event.execution_id,
            binding: Some(event.binding),
            key: event.key,
            kind: R2oFlowJournalKind::PlanApplied,
            plan_id: event.plan_id,
            trial_id: event.trial_id,
            ..R2oFlowJournalEntry::default()
        });
        true
    }

    pub fn record_plan_refused(
        &mut self,
        at_ns: u64,
        key: [u8; KEY_LEN],
        code: u8,
        plan_id: [u8; 16],
        trial_id: [u8; 16],
        execution_id: u64,
        binding: Option<BindingContext>,
    ) -> bool {
        // C `d2k_journal_add_refused` пишет любой code (включая NONE) и не
        // проверяет ни ключ, ни binding: отсев проба/NONE делает вызывающий
        // `refuse_coded`, а не журнал.
        self.push(R2oFlowJournalEntry {
            at_ns,
            execution_id,
            binding,
            key,
            kind: R2oFlowJournalKind::PlanRefused,
            code,
            plan_id,
            trial_id,
            ..R2oFlowJournalEntry::default()
        });
        true
    }

    pub fn record_execution_failure(
        &mut self,
        at_ns: u64,
        event: &AppliedEvent,
        code: u8,
        damaged: bool,
    ) -> bool {
        // C `d2k_journal_add_fate_bound`: без проверки события.
        self.push(R2oFlowJournalEntry {
            at_ns,
            execution_id: event.execution_id,
            binding: Some(event.binding),
            key: event.key,
            kind: R2oFlowJournalKind::PlanUnsent,
            code,
            plan_id: event.plan_id,
            trial_id: event.trial_id,
            ..R2oFlowJournalEntry::default()
        });
        if damaged {
            self.push(R2oFlowJournalEntry {
                at_ns,
                execution_id: event.execution_id,
                binding: Some(event.binding),
                key: event.key,
                kind: R2oFlowJournalKind::PlanDamaged,
                code: R2O_JOURNAL_REFUSE_DAMAGED,
                plan_id: event.plan_id,
                trial_id: event.trial_id,
                ..R2oFlowJournalEntry::default()
            });
        }
        true
    }

    /// C `d2k_journal_add_fate` (`journal.c:178-182`): обёртка
    /// `add_fate_bound` без execution и binding — они остаются нулевыми.
    pub fn record_fate(
        &mut self,
        at_ns: u64,
        key: [u8; KEY_LEN],
        kind: R2oFlowJournalKind,
        code: u8,
        plan_id: [u8; 16],
        trial_id: [u8; 16],
    ) -> bool {
        self.push(R2oFlowJournalEntry {
            at_ns,
            key,
            kind,
            code,
            plan_id,
            trial_id,
            ..R2oFlowJournalEntry::default()
        });
        true
    }

    pub fn record_tcp_exchange(&mut self, at_ns: u64, event: &R2oTcpExchangeEvent) {
        self.push(R2oFlowJournalEntry {
            at_ns,
            key: event.key,
            kind: R2oFlowJournalKind::Exchange,
            code: event.code,
            num: event.num,
            tos: event.tos,
            server_hello: event.server_hello,
            planned: event.planned,
            ..R2oFlowJournalEntry::default()
        });
    }

    pub fn record_tcp_rst_cut(&mut self, at_ns: u64, event: &R2oTcpRstCutEvent) {
        self.push(R2oFlowJournalEntry {
            at_ns,
            key: event.key,
            kind: R2oFlowJournalKind::R2oTcpRstCut,
            code: 4,
            ttl: event.ttl,
            reference_ttl: event.reference_ttl,
            tos: event.traffic_class,
            server_hello: event.server_hello,
            planned: event.planned,
            client_shape: event.client_shape,
            client_is_low: Some(event.client_is_low),
            ip_id: event.ip_id,
            ..R2oFlowJournalEntry::default()
        });
    }

    pub fn record_tcp_rst(&mut self, at_ns: u64, event: &R2oTcpRstEvent) {
        self.push(R2oFlowJournalEntry {
            at_ns,
            key: event.key,
            kind: R2oFlowJournalKind::R2oTcpRst,
            code: 1,
            ttl: event.ttl,
            reference_ttl: event.reference_ttl,
            tos: event.traffic_class,
            server_hello: event.server_hello,
            planned: event.planned,
            client_shape: event.client_shape,
            client_is_low: Some(event.client_is_low),
            ip_id: event.ip_id,
            ..R2oFlowJournalEntry::default()
        });
    }

    pub fn record_udp_exchange(&mut self, at_ns: u64, event: &R2oUdpExchangeEvent) {
        self.push(R2oFlowJournalEntry {
            at_ns,
            key: event.key,
            kind: R2oFlowJournalKind::Exchange,
            code: event.code,
            num: event.num,
            ..R2oFlowJournalEntry::default()
        });
    }

    pub fn record_control_event(&mut self, at_ns: u64, event_type: u16, body: &[u8]) -> bool {
        if event_type == EVENT_HELLO {
            return self.record_hello_body(at_ns, body);
        }
        let frame = Frame {
            kind: event_type,
            body: body.to_vec(),
        };
        if event_type == EVENT_APPLIED {
            return decode_applied(&frame).is_ok_and(|event| self.record_applied(at_ns, &event));
        }
        match event_type {
            EVENT_R2O_VOICE_SUSPECT => decode_r2o_voice_suspect(&frame).map(|event| {
                self.record_direction_event(
                    at_ns,
                    event.key,
                    R2oFlowJournalKind::R2oVoiceSuspect,
                    event.client_is_low,
                    0,
                    0,
                    0,
                    0,
                )
            }),
            EVENT_R2O_QUIC_SUSPECT => decode_r2o_quic_suspect(&frame).map(|event| {
                self.record_direction_event(
                    at_ns,
                    event.key,
                    R2oFlowJournalKind::R2oQuicSuspect,
                    event.client_is_low,
                    u8::from(event.planned),
                    0,
                    0,
                    0,
                )
            }),
            EVENT_R2O_QUIC_STALL => decode_r2o_quic_stall(&frame).map(|event| {
                self.record_direction_event(
                    at_ns,
                    event.key,
                    R2oFlowJournalKind::R2oQuicStall,
                    event.client_is_low,
                    u8::from(event.planned),
                    0,
                    0,
                    7,
                )
            }),
            EVENT_R2O_TCP_SILENT => decode_r2o_tcp_silence(&frame).map(|event| {
                self.record_direction_event(
                    at_ns,
                    event.key,
                    R2oFlowJournalKind::R2oTcpSilent,
                    event.client_is_low,
                    u8::from(event.planned),
                    event.elapsed_ms,
                    0,
                    3,
                )
            }),
            EVENT_R2O_TCP_STALL => decode_r2o_tcp_stall(&frame).map(|event| {
                self.record_tcp_stall_event(at_ns, &event);
            }),
            EVENT_R2O_TCP_FIN_RETRY => decode_r2o_tcp_fin_retry(&frame).map(|event| {
                self.record_direction_event(
                    at_ns,
                    event.key,
                    R2oFlowJournalKind::R2oTcpFinRetry,
                    event.client_is_low,
                    u8::from(event.planned),
                    0,
                    0,
                    6,
                )
            }),
            EVENT_R2O_TCP_RST_AFTER_APP => decode_r2o_tcp_rst_after_app(&frame).map(|event| {
                self.record_direction_event(
                    at_ns,
                    event.key,
                    R2oFlowJournalKind::R2oTcpRstAfterApp,
                    event.client_is_low,
                    u8::from(event.planned),
                    0,
                    0,
                    5,
                )
            }),
            EVENT_R2O_TCP_EARLY_RST => decode_r2o_tcp_early_rst(&frame).map(|_| ()),
            EVENT_R2O_TCP_RST_CUT => decode_r2o_tcp_rst_cut_signal(&frame).map(|_| ()),
            EVENT_R2O_TCP_CLEAN_HANDSHAKE => decode_r2o_tcp_clean_handshake(&frame).map(|_| ()),
            EVENT_R2O_TCP_REPEAT => decode_r2o_tcp_repeat(&frame).map(|event| {
                self.push(R2oFlowJournalEntry {
                    at_ns,
                    key: event.key,
                    kind: R2oFlowJournalKind::Suspect,
                    code: 2,
                    planned: u8::from(event.planned),
                    client_is_low: Some(event.client_is_low),
                    ..R2oFlowJournalEntry::default()
                });
            }),
            EVENT_R2O_VOICE_PROOF | EVENT_R2O_VOICE_STUN_PROOF | EVENT_R2O_VOICE_RTP_PROOF => {
                decode_r2o_voice_proof(&frame).map(|event| {
                    let (code, mapped_ip, mapped_port, num) = match event.proof {
                        r2k_core::control::R2oVoiceProofKind::DiscordDiscovery {
                            mapped_ip,
                            mapped_port,
                        } => (1, mapped_ip.octets(), mapped_port, 0),
                        r2k_core::control::R2oVoiceProofKind::StunBinding => (2, [0; 4], 0, 0),
                        r2k_core::control::R2oVoiceProofKind::RtpMedia {
                            outbound_packets,
                            inbound_packets,
                        } => (
                            3,
                            [0; 4],
                            0,
                            u32::from(outbound_packets) << 8 | u32::from(inbound_packets),
                        ),
                    };
                    self.push(R2oFlowJournalEntry {
                        at_ns,
                        key: event.key,
                        kind: R2oFlowJournalKind::R2oVoiceProof,
                        code,
                        num,
                        trial_id: event.trial_id,
                        mapped_ip,
                        mapped_port,
                        ..R2oFlowJournalEntry::default()
                    });
                })
            }
            _ => return false,
        }
        .is_ok()
    }

    fn record_tcp_stall_event(&mut self, at_ns: u64, event: &r2k_core::control::R2oTcpStallEvent) {
        // C `suspect_num`: detail.server_hello из потока, planned и num.
        self.push(R2oFlowJournalEntry {
            at_ns,
            key: event.key,
            kind: R2oFlowJournalKind::R2oTcpStall,
            code: 8,
            client_is_low: Some(event.client_is_low),
            planned: u8::from(event.planned),
            elapsed_ms: event.elapsed_ms,
            num: event.estimated_packets,
            server_hello: event.server_hello,
            ..R2oFlowJournalEntry::default()
        });
    }

    fn record_direction_event(
        &mut self,
        at_ns: u64,
        key: [u8; KEY_LEN],
        kind: R2oFlowJournalKind,
        client_is_low: bool,
        planned: u8,
        elapsed_ms: u32,
        num: u32,
        code: u8,
    ) {
        self.push(R2oFlowJournalEntry {
            at_ns,
            key,
            kind,
            client_is_low: Some(client_is_low),
            planned,
            elapsed_ms,
            num,
            code,
            ..R2oFlowJournalEntry::default()
        });
    }

    pub fn count(&self) -> usize {
        self.length
    }

    pub fn get(&self, index: usize) -> Option<&R2oFlowJournalEntry> {
        if index >= self.length {
            return None;
        }
        let start = if self.length == self.entries.len() {
            self.head
        } else {
            0
        };
        Some(&self.entries[(start + index) % self.entries.len()])
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn added(&self) -> u64 {
        self.added
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &R2oFlowJournalEntry> {
        (0..self.length).map(|index| self.get(index).expect("индекс кольца проверен"))
    }
}

#[cfg(test)]
mod journal_parity_tests {
    use super::{
        R2oFlowJournal, R2oFlowJournalEntry, R2oFlowJournalKind, r2o_refuse_text, r2o_suspect_text,
    };

    /// Векторы сняты с production C `d2k_suspect_text`/`d2k_refuse_text`.
    #[test]
    fn journal_note_texts_match_d2o() {
        let suspects = [
            (1, "сброс в ответ на приветствие"),
            (2, "приветствие повторено"),
            (3, "ответа на приветствие не было"),
            (4, "снят чужой сброс в ответ на приветствие"),
            (
                5,
                "сброс клиента или сервера после TLS app-data; проверить объём ответа",
            ),
            (
                7,
                "QUIC: сервер замолчал после рукопожатия, клиент повторяет; проверить ответ своим запросом",
            ),
            (
                8,
                "TCP: сервер замолчал на бюджете коробки, соединение открыто; проверить объём ответа",
            ),
            (
                6,
                "FIN клиента повторён без ответа после ответа сервера; проверить объём ответа",
            ),
        ];
        for (code, text) in suspects {
            assert_eq!(r2o_suspect_text(code), text, "suspect {code}");
        }
        assert_eq!(r2o_suspect_text(0), "подозрение без кода");
        assert_eq!(r2o_suspect_text(9), "подозрение без кода");

        let refusals = [
            (0, "причина не названа"),
            (1, "ядро отвергло посылку"),
            (2, "очередь отложенной отправки не приняла посылку"),
            (3, "посылка длиннее того, что унесёт способ отправки"),
            (4, "поток испорчен недоисполнением плана"),
            (
                5,
                "исполнитель отверг план на этом пакете (причина — в записи)",
            ),
            (
                6,
                "поток клиента не несёт того, что план требует (причина — в записи)",
            ),
        ];
        for (code, text) in refusals {
            assert_eq!(r2o_refuse_text(code), text, "refuse {code}");
        }
        assert_eq!(r2o_refuse_text(7), "отказ без кода");
    }

    #[test]
    fn journal_push_sets_c_default_notes() {
        let mut journal = R2oFlowJournal::with_capacity(4).unwrap();
        let mut key = [0; r2k_core::control::KEY_LEN];
        key[0] = 4;
        key[37] = 6;
        journal.push(R2oFlowJournalEntry {
            key,
            kind: R2oFlowJournalKind::Suspect,
            code: 1,
            ..R2oFlowJournalEntry::default()
        });
        journal.push(R2oFlowJournalEntry {
            key,
            kind: R2oFlowJournalKind::PlanUnsent,
            code: 3,
            ..R2oFlowJournalEntry::default()
        });
        journal.push(R2oFlowJournalEntry {
            key,
            kind: R2oFlowJournalKind::PlanDone,
            ..R2oFlowJournalEntry::default()
        });
        assert_eq!(
            journal.get(0).unwrap().note,
            Some("сброс в ответ на приветствие")
        );
        assert_eq!(
            journal.get(1).unwrap().note,
            Some("посылка длиннее того, что унесёт способ отправки")
        );
        assert_eq!(journal.get(2).unwrap().note, Some("план доисполнен"));
    }
}
