use crate::plan::{PROTO_HTTP, PROTO_VOICE, Plan};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

pub const PROTOCOL_VERSION: u16 = 47;
pub const FRAME_MAX: usize = 65_536;
pub const KEY_LEN: usize = 38;
pub const MAX_DNS_NAME_LEN: usize = 253;
pub const TCP_TIMESTAMP_METADATA_MARKER: u8 = 0xa5;
pub const EVENT_HELLO: u16 = 0x0001;
pub const EVENT_REFUSED: u16 = 0x0004;
pub const EVENT_APPLIED: u16 = 0x0009;
pub const EVENT_ACK: u16 = 0x0008;
pub const EVENT_PROTOCOL: u16 = 0x000a;
pub const EVENT_HTTP_PORTAL: u16 = 0x000b;
pub const EVENT_HTTP_RESPONSE: u16 = 0x000c;
pub const EVENT_R2O_VOICE_SUSPECT: u16 = 0x000d;
pub const EVENT_R2O_VOICE_PROOF: u16 = 0x000e;
pub const EVENT_R2O_QUIC_SUSPECT: u16 = 0x000f;
pub const EVENT_R2O_TCP_SILENT: u16 = 0x0010;
pub const EVENT_R2O_TCP_STALL: u16 = 0x0011;
pub const EVENT_R2O_TCP_FIN_RETRY: u16 = 0x0012;
pub const EVENT_R2O_TCP_RST_AFTER_APP: u16 = 0x0013;
pub const EVENT_R2O_QUIC_STALL: u16 = 0x0016;
pub const EVENT_CLIENT_SHAPE: u16 = 0x0017;
pub const EVENT_R2O_TCP_CLEAN_HANDSHAKE: u16 = 0x0018;
pub const EVENT_R2O_TCP_EARLY_RST: u16 = 0x0019;
pub const EVENT_R2O_TCP_REPEAT: u16 = 0x001a;
pub const EVENT_R2O_TCP_RST_CUT: u16 = 0x001b;
pub const EVENT_R2O_TCP_EXCHANGE: u16 = 0x001c;
pub const EVENT_R2O_VOICE_STUN_PROOF: u16 = 0x001d;
pub const EVENT_R2O_VOICE_RTP_PROOF: u16 = 0x001e;
pub const EVENT_R2O_JOURNAL_ENTRY: u16 = 0x0014;
pub const EVENT_R2O_JOURNAL_END: u16 = 0x0015;
pub const COMMAND_SET_NAME: u16 = 0x0081;
pub const COMMAND_SET_ADDR: u16 = 0x0082;
pub const COMMAND_DEL_NAME: u16 = 0x0083;
pub const COMMAND_DEL_ADDR: u16 = 0x0084;
pub const COMMAND_CLEAR: u16 = 0x0085;
pub const COMMAND_STATS: u16 = 0x0086;
pub const COMMAND_ARM_SHAPE: u16 = 0x0087;
pub const COMMAND_SET_NAME_PROBE: u16 = 0x0088;
pub const COMMAND_DEL_NAME_PROBE: u16 = 0x008b;
pub const COMMAND_SET_SUFFIX: u16 = 0x008c;
pub const COMMAND_DEL_SUFFIX: u16 = 0x008d;
pub const COMMAND_SET_BYPASS: u16 = 0x008e;
pub const COMMAND_DEL_BYPASS: u16 = 0x008f;
pub const COMMAND_SET_HTTPS: u16 = 0x0090;
pub const COMMAND_SET_VOICE_ADDR: u16 = 0x0091;
pub const COMMAND_SET_VOICE_ADDR_PROBE: u16 = 0x0092;
pub const COMMAND_DEL_VOICE_ADDR_PROBE: u16 = 0x0093;
pub const COMMAND_SET_ADDR_PROBE: u16 = 0x0094;
pub const COMMAND_DEL_ADDR_PROBE: u16 = 0x0095;
pub const COMMAND_SET_TCP_STALL_BUDGETS: u16 = 0x0096;
pub const MAX_TCP_STALL_BUDGETS: usize = 8;
pub const VOICE_ADDR_PROBE_LEASE_MAX_MS: u32 = 120_000;
pub const VOICE_RTP_PROOF_MIN_PACKETS: u8 = 3;
pub const ADDR_PROBE_LEASE_MAX_MS: u32 = 120_000;
pub const MAX_HTTPS_TTL_SECONDS: u32 = 6 * 60 * 60;
pub const ACK_OK: u8 = 0;
pub const ACK_BAD_PLAN: u8 = 1;
pub const ACK_NO_ROOM: u8 = 2;
pub const ACK_BAD_ARGS: u8 = 3;

pub const SHAPE_MODERN: u8 = 1;
pub const SHAPE_LEGACY: u8 = 2;
pub const SHAPE_QUIC: u8 = 3;
pub const SHAPE_VOICE: u8 = 5;
pub const SHAPE_ECH_TCP: u8 = 6;
pub const SHAPE_HTTP: u8 = 7;

const HTTP_CONTEXT_HEADER_LEN: usize = 50;
const HTTP_BINDING_LEN: usize = 28;
const HTTP_RESPONSE_SUFFIX_LEN: usize = 18;
const EXECUTION_CONTEXT_LEN: usize = 36;
const ACK_BINDING_CONTEXT_MAGIC: &[u8; 4] = b"R2BC";
const ACK_BINDING_CONTEXT_LEN: usize = 4 + HTTP_BINDING_LEN;

pub const RELEASE_ID: &str = match option_env!("R2O_RELEASE_ID") {
    Some(value) => value,
    None => "dev",
};

/// Вернуть путь отдельного канала наблюдения для ClientHello.
pub fn r2k_snapshot_socket_path(control_path: &Path) -> PathBuf {
    let mut path = OsString::from(control_path.as_os_str());
    path.push(".snapshot");
    PathBuf::from(path)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: u16,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArmShapeCommand {
    pub name: Vec<u8>,
    pub transport: u8,
    pub family: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Greeting {
    pub version: u16,
    pub send_maxlen: u32,
    pub release_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ack {
    pub command: u16,
    pub ok: bool,
    pub reason: u8,
    pub trial_id: Option<[u8; 16]>,
    pub binding_context: Option<BindingContext>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingContext {
    pub generation: u64,
    pub kind: u8,
    pub family: u8,
    pub shape: u8,
    pub temporary: bool,
    pub epoch: [u8; 16],
}

impl BindingContext {
    pub fn is_known(&self) -> bool {
        self.generation != 0 && self.epoch.iter().any(|byte| *byte != 0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedEvent {
    pub key: [u8; KEY_LEN],
    pub plan_id: [u8; 16],
    pub trial_id: [u8; 16],
    pub execution_id: u64,
    pub binding: BindingContext,
}

impl AppliedEvent {
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key) || !valid_binding(&self.binding) {
            return None;
        }
        let mut body = Vec::with_capacity(KEY_LEN + 16 + 16 + EXECUTION_CONTEXT_LEN);
        body.extend_from_slice(&self.key);
        body.extend_from_slice(&self.plan_id);
        body.extend_from_slice(&self.trial_id);
        body.extend_from_slice(&self.execution_id.to_be_bytes());
        body.extend_from_slice(&self.binding.generation.to_be_bytes());
        body.extend_from_slice(&[
            self.binding.kind,
            self.binding.family,
            self.binding.shape,
            u8::from(self.binding.temporary),
        ]);
        body.extend_from_slice(&self.binding.epoch);
        Some(body)
    }
}

/// Refused or incompletely sent plan, correlated with its original trial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefusedEvent {
    pub key: [u8; KEY_LEN],
    pub code: u8,
    pub plan_id: [u8; 16],
    pub trial_id: [u8; 16],
    pub client_shape: Option<u8>,
    pub execution_id: Option<u64>,
    pub binding: Option<BindingContext>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelloEvent {
    pub key: [u8; KEY_LEN],
    pub host: Option<Vec<u8>>,
    /// Форма захваченного ClientHello; отсутствует только в старом формате события.
    pub shape: Option<u8>,
    /// Длина полной TLS-записи TCP вместе с пятибайтовым заголовком.
    pub r2o_wire_len: Option<usize>,
    /// Исходные QUIC Initial для последующей точной пробы.
    pub quic_snapshot: Option<Vec<u8>>,
    /// Есть ли TCP timestamp option в начальном SYN клиента; None — SYN не наблюдался.
    pub tcp_has_timestamp: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientShapeEvent {
    pub key: [u8; KEY_LEN],
    pub host: Vec<u8>,
    pub shape: u8,
    pub client_hello: Vec<u8>,
    /// Есть ли TCP timestamp option в начальном SYN клиента; None — SYN не наблюдался.
    pub tcp_has_timestamp: Option<bool>,
}

impl ClientShapeEvent {
    /// Закодировать полный ClientHello вместе с потоком и проверяемой формой.
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key)
            || self.key[37] != 6
            || self.host.is_empty()
            || self.host.len() > MAX_DNS_NAME_LEN
            || !matches!(self.shape, SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP)
            || self.client_hello.len() > 4096
            || self.client_hello.len() < 5
        {
            return None;
        }
        let tls = crate::tls::parse(&self.client_hello);
        let client_shape = if tls.ech_offer {
            SHAPE_ECH_TCP
        } else if tls.is_tls13 {
            SHAPE_MODERN
        } else {
            SHAPE_LEGACY
        };
        let sni = tls
            .sni_range
            .as_ref()
            .and_then(|range| self.client_hello.get(range.clone()));
        if !tls.is_client_hello
            || tls.extensions_truncated
            || tls.record_end != Some(self.client_hello.len())
            || client_shape != self.shape
            || sni.is_none_or(|name| !name.eq_ignore_ascii_case(&self.host))
        {
            return None;
        }
        let mut body = Vec::with_capacity(
            KEY_LEN
                + 1
                + self.host.len()
                + 5
                + self.client_hello.len()
                + 2 * usize::from(self.tcp_has_timestamp.is_some()),
        );
        body.extend_from_slice(&self.key);
        body.push(self.host.len() as u8);
        body.extend_from_slice(&self.host);
        body.push(self.shape);
        body.extend_from_slice(&(self.client_hello.len() as u16).to_be_bytes());
        body.extend_from_slice(&(self.client_hello.len() as u16).to_be_bytes());
        body.extend_from_slice(&self.client_hello);
        if let Some(tcp_has_timestamp) = self.tcp_has_timestamp {
            body.push(TCP_TIMESTAMP_METADATA_MARKER);
            body.push(u8::from(tcp_has_timestamp));
        }
        Some(body)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oVoiceSuspectEvent {
    pub key: [u8; KEY_LEN],
    pub client_is_low: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oQuicSuspectEvent {
    pub key: [u8; KEY_LEN],
    pub client_is_low: bool,
    pub planned: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oTcpSilenceEvent {
    pub key: [u8; KEY_LEN],
    pub client_is_low: bool,
    pub planned: bool,
    pub elapsed_ms: u32,
}

/// Чистое TCP-рукопожатие без применённого плана.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oTcpCleanHandshakeEvent {
    pub key: [u8; KEY_LEN],
}

impl R2oTcpCleanHandshakeEvent {
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key) || self.key[37] != 6 {
            return None;
        }
        Some(self.key.to_vec())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oTcpEarlyRstEvent {
    pub key: [u8; KEY_LEN],
    pub client_is_low: bool,
    pub planned: bool,
    pub ttl: u8,
    pub reference_ttl: u8,
    pub traffic_class: u8,
    pub ip_id: u16,
}

/// TCP RST, снятый защитой до первого ответа на ClientHello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oTcpRstCutSignalEvent {
    pub key: [u8; KEY_LEN],
    pub client_is_low: bool,
    pub ttl: u8,
    pub reference_ttl: u8,
    pub traffic_class: u8,
    pub ip_id: u16,
}

/// Полный ответный TLS-обмен одного TCP-потока, нужный для точечной проверки.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oTcpExchangeEvent {
    pub key: [u8; KEY_LEN],
    pub first_record_type: u8,
    pub bytes_after_client_hello: u32,
    /// Биты типов TLS-записей 20–23.
    pub record_types: u8,
    pub server_hello: bool,
    pub planned: bool,
}

impl R2oTcpExchangeEvent {
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key) || self.key[37] != 6 || self.record_types & !0x0f != 0 {
            return None;
        }
        let mut body = Vec::with_capacity(KEY_LEN + 8);
        body.extend_from_slice(&self.key);
        body.push(self.first_record_type);
        body.extend_from_slice(&self.bytes_after_client_hello.to_be_bytes());
        body.push(self.record_types);
        body.push(u8::from(self.server_hello));
        body.push(u8::from(self.planned));
        Some(body)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Повторный ClientHello TCP без распознанного ответа сервера.
pub struct R2oTcpRepeatEvent {
    pub key: [u8; KEY_LEN],
    pub client_is_low: bool,
    pub planned: bool,
}

impl R2oTcpRepeatEvent {
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key) || self.key[37] != 6 {
            return None;
        }
        let mut body = Vec::with_capacity(KEY_LEN + 2);
        body.extend_from_slice(&self.key);
        body.push(u8::from(self.client_is_low));
        body.push(u8::from(self.planned));
        Some(body)
    }
}

impl R2oTcpEarlyRstEvent {
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key) || self.key[37] != 6 {
            return None;
        }
        let mut body = Vec::with_capacity(KEY_LEN + 7);
        body.extend_from_slice(&self.key);
        body.push(u8::from(self.client_is_low));
        body.push(u8::from(self.planned));
        body.push(self.ttl);
        body.push(self.reference_ttl);
        body.push(self.traffic_class);
        body.extend_from_slice(&self.ip_id.to_be_bytes());
        Some(body)
    }
}

impl R2oTcpRstCutSignalEvent {
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key) || self.key[37] != 6 {
            return None;
        }
        let mut body = Vec::with_capacity(KEY_LEN + 6);
        body.extend_from_slice(&self.key);
        body.push(u8::from(self.client_is_low));
        body.push(self.ttl);
        body.push(self.reference_ttl);
        body.push(self.traffic_class);
        body.extend_from_slice(&self.ip_id.to_be_bytes());
        Some(body)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oTcpStallEvent {
    pub key: [u8; KEY_LEN],
    pub client_is_low: bool,
    pub elapsed_ms: u32,
    pub estimated_packets: u32,
    pub planned: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oTcpFinRetryEvent {
    pub key: [u8; KEY_LEN],
    pub client_is_low: bool,
    pub planned: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oTcpRstAfterAppEvent {
    pub key: [u8; KEY_LEN],
    pub client_is_low: bool,
    pub planned: bool,
}

impl R2oTcpFinRetryEvent {
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key) || self.key[37] != 6 {
            return None;
        }
        let mut body = Vec::with_capacity(KEY_LEN + 2);
        body.extend_from_slice(&self.key);
        body.push(u8::from(self.client_is_low));
        body.push(u8::from(self.planned));
        Some(body)
    }
}

impl R2oTcpRstAfterAppEvent {
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key) || self.key[37] != 6 {
            return None;
        }
        let mut body = Vec::with_capacity(KEY_LEN + 2);
        body.extend_from_slice(&self.key);
        body.push(u8::from(self.client_is_low));
        body.push(u8::from(self.planned));
        Some(body)
    }
}

impl R2oTcpStallEvent {
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key)
            || self.key[37] != 6
            || self.elapsed_ms == 0
            || self.estimated_packets == 0
        {
            return None;
        }
        let mut body = Vec::with_capacity(KEY_LEN + 10);
        body.extend_from_slice(&self.key);
        body.push(u8::from(self.client_is_low));
        body.extend_from_slice(&self.elapsed_ms.to_be_bytes());
        body.extend_from_slice(&self.estimated_packets.to_be_bytes());
        body.push(u8::from(self.planned));
        Some(body)
    }
}

impl R2oTcpSilenceEvent {
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key) || self.key[37] != 6 || self.elapsed_ms == 0 {
            return None;
        }
        let mut body = Vec::with_capacity(KEY_LEN + 6);
        body.extend_from_slice(&self.key);
        body.push(u8::from(self.client_is_low));
        body.push(u8::from(self.planned));
        body.extend_from_slice(&self.elapsed_ms.to_be_bytes());
        Some(body)
    }
}

impl R2oQuicSuspectEvent {
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key) || self.key[37] != 17 {
            return None;
        }
        let mut body = Vec::with_capacity(KEY_LEN + 2);
        body.extend_from_slice(&self.key);
        body.push(u8::from(self.client_is_low));
        body.push(u8::from(self.planned));
        Some(body)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oVoiceProofKind {
    DiscordDiscovery {
        mapped_ip: std::net::Ipv4Addr,
        mapped_port: u16,
    },
    StunBinding,
    RtpMedia {
        outbound_packets: u8,
        inbound_packets: u8,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oVoiceProofEvent {
    pub key: [u8; KEY_LEN],
    pub trial_id: [u8; 16],
    pub proof: R2oVoiceProofKind,
}

impl R2oVoiceProofEvent {
    pub fn event_type(&self) -> u16 {
        match self.proof {
            R2oVoiceProofKind::DiscordDiscovery { .. } => EVENT_R2O_VOICE_PROOF,
            R2oVoiceProofKind::StunBinding => EVENT_R2O_VOICE_STUN_PROOF,
            R2oVoiceProofKind::RtpMedia { .. } => EVENT_R2O_VOICE_RTP_PROOF,
        }
    }

    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key)
            || self.key[0] != 4
            || self.key[37] != 17
            || self.trial_id.iter().all(|byte| *byte == 0)
        {
            return None;
        }
        let extra_len = match self.proof {
            R2oVoiceProofKind::DiscordDiscovery {
                mapped_ip,
                mapped_port,
            } if mapped_ip.is_unspecified() || mapped_ip.is_multicast() || mapped_port == 0 => {
                return None;
            }
            R2oVoiceProofKind::DiscordDiscovery { .. } => 22,
            R2oVoiceProofKind::StunBinding => 0,
            R2oVoiceProofKind::RtpMedia {
                outbound_packets,
                inbound_packets,
            } if outbound_packets < VOICE_RTP_PROOF_MIN_PACKETS
                || inbound_packets < VOICE_RTP_PROOF_MIN_PACKETS =>
            {
                return None;
            }
            R2oVoiceProofKind::RtpMedia { .. } => 2,
        };
        let mut r2o_body = Vec::with_capacity(KEY_LEN + 16 + extra_len);
        r2o_body.extend_from_slice(&self.key);
        r2o_body.extend_from_slice(&self.trial_id);
        if let R2oVoiceProofKind::DiscordDiscovery {
            mapped_ip,
            mapped_port,
        } = self.proof
        {
            r2o_body.extend_from_slice(&mapped_ip.octets());
            r2o_body.extend_from_slice(&mapped_port.to_be_bytes());
        }
        if let R2oVoiceProofKind::RtpMedia {
            outbound_packets,
            inbound_packets,
        } = self.proof
        {
            r2o_body.extend_from_slice(&[outbound_packets, inbound_packets]);
        }
        Some(r2o_body)
    }
}

impl R2oVoiceSuspectEvent {
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key) || self.key[0] != 4 || self.key[37] != 17 {
            return None;
        }
        let mut body = Vec::with_capacity(KEY_LEN + 1);
        body.extend_from_slice(&self.key);
        body.push(u8::from(self.client_is_low));
        Some(body)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpPortalEvent {
    pub key: [u8; KEY_LEN],
    /// Успел ли r2o-datapath ответить клиенту перенаправлением на HTTPS.
    pub answered: bool,
    pub host: Vec<u8>,
}

impl HttpPortalEvent {
    /// Кодирует минимальное событие HTTP-портала протокола r2o v22.
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if self.key[37] != 6 || self.host.is_empty() || self.host.len() > MAX_DNS_NAME_LEN {
            return None;
        }
        let mut body = Vec::with_capacity(KEY_LEN + 2 + self.host.len());
        body.extend_from_slice(&self.key);
        body.push(u8::from(self.answered));
        body.push(self.host.len() as u8);
        body.extend_from_slice(&self.host);
        Some(body)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponseEvent {
    pub key: [u8; KEY_LEN],
    /// Исход: 1 — полный ответ, 2 — неизвестен, 3 — портал, 4 — обрыв.
    pub code: u8,
    pub host: Vec<u8>,
    pub execution_id: u64,
    pub plan_id: [u8; 16],
    pub trial_id: [u8; 16],
    pub request_ms: u64,
    pub path: Vec<u8>,
    pub binding: BindingContext,
    pub status: u16,
    pub body_bytes: u64,
    pub request_no: u64,
}

impl HttpResponseEvent {
    pub fn event_body(&self) -> Option<Vec<u8>> {
        if !valid_flow_key(&self.key)
            || self.key[37] != 6
            || self.host.is_empty()
            || self.host.len() > u8::MAX as usize
            || self.path.len() >= 1024
            || !matches!(self.code, 1..=4)
            || self.status > 599
            || self.code == 1 && self.status < 200
            || self.request_no == 0
            || !valid_binding(&self.binding)
        {
            return None;
        }

        let mut body = Vec::with_capacity(
            KEY_LEN
                + 2
                + self.host.len()
                + HTTP_CONTEXT_HEADER_LEN
                + self.path.len()
                + HTTP_BINDING_LEN
                + HTTP_RESPONSE_SUFFIX_LEN,
        );
        body.extend_from_slice(&self.key);
        body.push(self.code);
        body.push(self.host.len() as u8);
        body.extend_from_slice(&self.host);
        body.extend_from_slice(&self.execution_id.to_be_bytes());
        body.extend_from_slice(&self.plan_id);
        body.extend_from_slice(&self.trial_id);
        body.extend_from_slice(&self.request_ms.to_be_bytes());
        body.extend_from_slice(&(self.path.len() as u16).to_be_bytes());
        body.extend_from_slice(&self.path);
        body.extend_from_slice(&self.binding.generation.to_be_bytes());
        body.extend_from_slice(&[
            self.binding.kind,
            self.binding.family,
            self.binding.shape,
            u8::from(self.binding.temporary),
        ]);
        body.extend_from_slice(&self.binding.epoch);
        body.extend_from_slice(&self.status.to_be_bytes());
        body.extend_from_slice(&self.body_bytes.to_be_bytes());
        body.extend_from_slice(&self.request_no.to_be_bytes());
        Some(body)
    }
}

/// Request one retained or future ClientHello snapshot for a name and address family.
pub fn encode_arm_shape(name: &str, transport: u8, family: u8) -> Result<Vec<u8>, &'static str> {
    if name.is_empty()
        || name.len() > MAX_DNS_NAME_LEN
        || !matches!(transport, 6 | 17)
        || !matches!(family, 4 | 6)
    {
        return Err("запрос снимка требует имя, транспорт и IP family из протокола");
    }
    let mut body = Vec::with_capacity(name.len() + 3);
    body.push(name.len() as u8);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(&[transport, family]);
    encode_frame(COMMAND_ARM_SHAPE, &body)
}

pub fn decode_arm_shape(frame: &Frame) -> Result<ArmShapeCommand, &'static str> {
    if frame.kind != COMMAND_ARM_SHAPE || frame.body.len() < 3 {
        return Err("неверная команда ARM_SHAPE");
    }
    let name_len = usize::from(frame.body[0]);
    if name_len == 0
        || name_len > MAX_DNS_NAME_LEN
        || frame.body.len() != name_len + 3
        || !matches!(frame.body[name_len + 1], 6 | 17)
        || !matches!(frame.body[name_len + 2], 4 | 6)
    {
        return Err("неверные имя, транспорт или IP family команды ARM_SHAPE");
    }
    Ok(ArmShapeCommand {
        name: frame.body[1..name_len + 1].to_vec(),
        transport: frame.body[name_len + 1],
        family: frame.body[name_len + 2],
    })
}

pub fn encode_frame(kind: u16, body: &[u8]) -> Result<Vec<u8>, &'static str> {
    let length = body.len().checked_add(2).ok_or("кадр слишком длинный")?;
    if length > FRAME_MAX {
        return Err("кадр слишком длинный");
    }
    let mut frame = Vec::with_capacity(length + 4);
    frame.extend_from_slice(&(length as u32).to_be_bytes());
    frame.extend_from_slice(&kind.to_be_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

pub fn read_frame(reader: &mut impl Read) -> io::Result<Frame> {
    let mut header = [0; 6];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header[..4].try_into().expect("fixed frame header")) as usize;
    if !(2..=FRAME_MAX).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "длина управляющего кадра вне допустимого диапазона",
        ));
    }
    let mut body = vec![0; length - 2];
    reader.read_exact(&mut body)?;
    Ok(Frame {
        kind: u16::from_be_bytes([header[4], header[5]]),
        body,
    })
}

pub fn write_frame(writer: &mut impl Write, kind: u16, body: &[u8]) -> io::Result<()> {
    let frame = encode_frame(kind, body)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    writer.write_all(&frame)
}

pub fn encode_greeting(send_maxlen: u32) -> Result<Vec<u8>, &'static str> {
    if !valid_release_id(RELEASE_ID) {
        return Err("R2O_RELEASE_ID имеет недопустимый формат");
    }
    let release_id = RELEASE_ID.as_bytes();
    let mut body = vec![0; KEY_LEN + 7 + release_id.len()];
    body[0] = 4;
    body[KEY_LEN..KEY_LEN + 2].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    body[KEY_LEN + 2..KEY_LEN + 6].copy_from_slice(&send_maxlen.to_be_bytes());
    body[KEY_LEN + 6] = release_id.len() as u8;
    body[KEY_LEN + 7..].copy_from_slice(release_id);
    encode_frame(EVENT_PROTOCOL, &body)
}

pub fn decode_greeting(frame: &Frame) -> Result<Greeting, &'static str> {
    if frame.kind != EVENT_PROTOCOL || frame.body.len() < KEY_LEN + 7 {
        return Err("неверное приветствие датапата");
    }
    validate_zero_key(&frame.body[..KEY_LEN])?;
    let version = u16::from_be_bytes([frame.body[KEY_LEN], frame.body[KEY_LEN + 1]]);
    let send_maxlen = u32::from_be_bytes(
        frame.body[KEY_LEN + 2..KEY_LEN + 6]
            .try_into()
            .expect("fixed greeting header"),
    );
    let release_len = usize::from(frame.body[KEY_LEN + 6]);
    let release = frame
        .body
        .get(KEY_LEN + 7..KEY_LEN + 7 + release_len)
        .filter(|_| frame.body.len() == KEY_LEN + 7 + release_len)
        .ok_or("обрезанный release ID в приветствии")?;
    let release_id = std::str::from_utf8(release).map_err(|_| "release ID не UTF-8")?;
    if !valid_release_id(release_id) {
        return Err("release ID в приветствии недопустим");
    }
    Ok(Greeting {
        version,
        send_maxlen,
        release_id: release_id.to_owned(),
    })
}

pub fn encode_set_name(
    name: &str,
    shape: u8,
    family: u8,
    plan_records: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if name.is_empty() || name.len() > u8::MAX as usize {
        return Err("имя должно занимать от 1 до 255 байт");
    }
    if !matches!(family, 4 | 6) {
        return Err("семейство должно быть 4 или 6");
    }
    if !matches!(
        shape,
        SHAPE_MODERN | SHAPE_LEGACY | SHAPE_QUIC | SHAPE_VOICE | SHAPE_ECH_TCP | SHAPE_HTTP
    ) {
        return Err("форма приветствия не поддерживается");
    }
    let mut body = Vec::with_capacity(3 + name.len() + plan_records.len());
    body.push(name.len() as u8);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(&[shape, family]);
    body.extend_from_slice(plan_records);
    encode_frame(COMMAND_SET_NAME, &body)
}

pub fn encode_set_addr(
    address: IpAddr,
    shape: u8,
    plan_records: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if !valid_addr_shape(shape) || !valid_addr_plan_records(shape, plan_records) {
        return Err("адресная привязка требует поддерживаемые форму и совместимый план");
    }
    let mut body = Vec::with_capacity(18 + plan_records.len());
    match address {
        IpAddr::V4(address) => {
            body.push(4);
            body.extend_from_slice(&address.octets());
            body.extend_from_slice(&[0; 12]);
        }
        IpAddr::V6(address) => {
            body.push(6);
            body.extend_from_slice(&address.octets());
        }
    }
    body.push(shape);
    body.extend_from_slice(plan_records);
    encode_frame(COMMAND_SET_ADDR, &body)
}

pub fn encode_delete_addr(address: IpAddr, shape: u8) -> Result<Vec<u8>, &'static str> {
    if !valid_addr_shape(shape) {
        return Err("адресная привязка требует поддерживаемую форму");
    }
    let mut body = Vec::with_capacity(18);
    match address {
        IpAddr::V4(address) => {
            body.push(4);
            body.extend_from_slice(&address.octets());
            body.extend_from_slice(&[0; 12]);
        }
        IpAddr::V6(address) => {
            body.push(6);
            body.extend_from_slice(&address.octets());
        }
    }
    body.push(shape);
    encode_frame(COMMAND_DEL_ADDR, &body)
}

fn valid_addr_shape(shape: u8) -> bool {
    matches!(
        shape,
        SHAPE_MODERN | SHAPE_LEGACY | SHAPE_QUIC | SHAPE_VOICE | SHAPE_ECH_TCP
    )
}

fn valid_addr_plan_records(shape: u8, records: &[u8]) -> bool {
    Plan::parse(records).is_ok_and(|plan| match shape {
        SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP => plan.transport == 6 && plan.proto == 1,
        SHAPE_QUIC => plan.r2k_is_quic_address_plan(),
        SHAPE_VOICE => plan.transport == 17 && plan.proto == PROTO_VOICE,
        _ => false,
    })
}

pub fn encode_set_suffix(
    suffix: &str,
    shape: u8,
    family: u8,
    plan_records: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if suffix.is_empty() || suffix.len() > MAX_DNS_NAME_LEN {
        return Err("суффикс должен занимать от 1 до 253 байт");
    }
    if !matches!(family, 4 | 6)
        || !matches!(
            shape,
            SHAPE_MODERN | SHAPE_LEGACY | SHAPE_QUIC | SHAPE_ECH_TCP
        )
        || !valid_domain_plan_records(shape, plan_records)
    {
        return Err("суффикс требует поддерживаемые форму, семейство и план");
    }
    let mut body = Vec::with_capacity(3 + suffix.len() + plan_records.len());
    body.push(suffix.len() as u8);
    body.extend_from_slice(suffix.as_bytes());
    body.extend_from_slice(&[shape, family]);
    body.extend_from_slice(plan_records);
    encode_frame(COMMAND_SET_SUFFIX, &body)
}

pub fn encode_delete_suffix(
    suffix: &str,
    transport: u8,
    shape: u8,
    family: u8,
) -> Result<Vec<u8>, &'static str> {
    encode_domain_area_key(COMMAND_DEL_SUFFIX, suffix, transport, shape, family)
}

pub fn encode_set_bypass(
    name: &str,
    transport: u8,
    shape: u8,
    family: u8,
) -> Result<Vec<u8>, &'static str> {
    encode_domain_area_key(COMMAND_SET_BYPASS, name, transport, shape, family)
}

pub fn encode_delete_bypass(
    name: &str,
    transport: u8,
    shape: u8,
    family: u8,
) -> Result<Vec<u8>, &'static str> {
    encode_domain_area_key(COMMAND_DEL_BYPASS, name, transport, shape, family)
}

fn encode_domain_area_key(
    command: u16,
    name: &str,
    transport: u8,
    shape: u8,
    family: u8,
) -> Result<Vec<u8>, &'static str> {
    if name.is_empty() || name.len() > MAX_DNS_NAME_LEN {
        return Err("имя области должно занимать от 1 до 253 байт");
    }
    if !valid_domain_area_context(transport, shape, family) {
        return Err("область требует поддерживаемые транспорт, форму и семейство");
    }
    let mut body = Vec::with_capacity(4 + name.len());
    body.push(name.len() as u8);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(&[transport, shape, family]);
    encode_frame(command, &body)
}

fn valid_domain_area_context(transport: u8, shape: u8, family: u8) -> bool {
    matches!(family, 4 | 6)
        && ((transport == 6 && matches!(shape, SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP))
            || (transport == 17 && shape == SHAPE_QUIC))
}

fn valid_domain_plan_records(shape: u8, records: &[u8]) -> bool {
    Plan::parse(records).is_ok_and(|plan| match shape {
        SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP => plan.transport == 6 && plan.proto == 1,
        SHAPE_QUIC => plan.r2k_is_quic_address_plan(),
        _ => false,
    })
}

pub fn encode_set_voice_addr(
    server: std::net::Ipv4Addr,
    plan_records: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if server.is_unspecified() || server.is_multicast() || !valid_voice_plan_records(plan_records) {
        return Err("адресная голосовая привязка требует IPv4 и UDP voice-план");
    }
    let mut body = Vec::with_capacity(4 + plan_records.len());
    body.extend_from_slice(&server.octets());
    body.extend_from_slice(plan_records);
    encode_frame(COMMAND_SET_VOICE_ADDR, &body)
}

pub fn encode_set_voice_addr_probe(
    client: std::net::Ipv4Addr,
    server: std::net::SocketAddrV4,
    lease_ms: u32,
    plan_records: &[u8],
    trial_id: [u8; 16],
) -> Result<Vec<u8>, &'static str> {
    if client.is_unspecified()
        || client.is_multicast()
        || server.ip().is_unspecified()
        || server.ip().is_multicast()
        || server.port() == 0
        || lease_ms == 0
        || lease_ms > VOICE_ADDR_PROBE_LEASE_MAX_MS
        || trial_id.iter().all(|byte| *byte == 0)
        || !valid_voice_plan_records(plan_records)
    {
        return Err("временная голосовая привязка имеет недопустимые параметры");
    }
    let mut body = Vec::with_capacity(14 + plan_records.len() + trial_id.len());
    body.extend_from_slice(&client.octets());
    body.extend_from_slice(&server.ip().octets());
    body.extend_from_slice(&server.port().to_be_bytes());
    body.extend_from_slice(&lease_ms.to_be_bytes());
    body.extend_from_slice(plan_records);
    body.extend_from_slice(&trial_id);
    encode_frame(COMMAND_SET_VOICE_ADDR_PROBE, &body)
}

pub fn encode_delete_voice_addr_probe(
    client: std::net::Ipv4Addr,
    server: std::net::SocketAddrV4,
    trial_id: [u8; 16],
) -> Result<Vec<u8>, &'static str> {
    if client.is_unspecified()
        || client.is_multicast()
        || server.ip().is_unspecified()
        || server.ip().is_multicast()
        || server.port() == 0
        || trial_id.iter().all(|byte| *byte == 0)
    {
        return Err("удаление временной голосовой привязки имеет недопустимые параметры");
    }
    let mut body = Vec::with_capacity(10 + trial_id.len());
    body.extend_from_slice(&client.octets());
    body.extend_from_slice(&server.ip().octets());
    body.extend_from_slice(&server.port().to_be_bytes());
    body.extend_from_slice(&trial_id);
    encode_frame(COMMAND_DEL_VOICE_ADDR_PROBE, &body)
}

pub fn encode_set_addr_probe(
    source: SocketAddr,
    destination: SocketAddr,
    lease_ms: u32,
    plan_records: &[u8],
    trial_id: [u8; 16],
) -> Result<Vec<u8>, &'static str> {
    let flow = udp_addr_probe_flow(source, destination)?;
    if lease_ms == 0
        || lease_ms > ADDR_PROBE_LEASE_MAX_MS
        || trial_id.iter().all(|byte| *byte == 0)
        || !valid_addr_plan_records(SHAPE_QUIC, plan_records)
    {
        return Err("временная QUIC-привязка имеет недопустимые параметры");
    }
    let mut body = Vec::with_capacity(KEY_LEN + 20 + plan_records.len());
    body.extend_from_slice(&flow);
    body.extend_from_slice(&trial_id);
    body.extend_from_slice(&lease_ms.to_be_bytes());
    body.extend_from_slice(plan_records);
    encode_frame(COMMAND_SET_ADDR_PROBE, &body)
}

pub fn encode_delete_addr_probe(
    source: SocketAddr,
    destination: SocketAddr,
    trial_id: [u8; 16],
) -> Result<Vec<u8>, &'static str> {
    let flow = udp_addr_probe_flow(source, destination)?;
    if trial_id.iter().all(|byte| *byte == 0) {
        return Err("идентификатор временной QUIC-привязки не может быть нулевым");
    }
    let mut body = Vec::with_capacity(KEY_LEN + 16);
    body.extend_from_slice(&flow);
    body.extend_from_slice(&trial_id);
    encode_frame(COMMAND_DEL_ADDR_PROBE, &body)
}

fn udp_addr_probe_flow(
    source: SocketAddr,
    destination: SocketAddr,
) -> Result<[u8; KEY_LEN], &'static str> {
    if source.is_ipv4() != destination.is_ipv4()
        || source.ip().is_unspecified()
        || destination.ip().is_unspecified()
        || source.port() == 0
        || destination.port() == 0
    {
        return Err("UDP-поток временной привязки имеет недопустимые адреса или порты");
    }
    let mut flow = [0; KEY_LEN];
    flow[0] = if source.is_ipv4() { 4 } else { 6 };
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            flow[1..5].copy_from_slice(&source.octets());
            flow[17..21].copy_from_slice(&destination.octets());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            flow[1..17].copy_from_slice(&source.octets());
            flow[17..33].copy_from_slice(&destination.octets());
        }
        _ => return Err("семейства адресов UDP-потока не совпадают"),
    }
    flow[33..35].copy_from_slice(&source.port().to_be_bytes());
    flow[35..37].copy_from_slice(&destination.port().to_be_bytes());
    flow[37] = 17;
    Ok(flow)
}

pub fn valid_udp_addr_probe_flow(flow: &[u8; KEY_LEN]) -> bool {
    if !matches!(flow[0], 4 | 6) || flow[37] != 17 {
        return false;
    }
    if u16::from_be_bytes([flow[33], flow[34]]) == 0
        || u16::from_be_bytes([flow[35], flow[36]]) == 0
    {
        return false;
    }
    if flow[0] == 4 {
        flow[5..17].iter().all(|byte| *byte == 0)
            && flow[21..33].iter().all(|byte| *byte == 0)
            && flow[1..5].iter().any(|byte| *byte != 0)
            && flow[17..21].iter().any(|byte| *byte != 0)
    } else {
        flow[1..17].iter().any(|byte| *byte != 0) && flow[17..33].iter().any(|byte| *byte != 0)
    }
}

fn valid_voice_plan_records(plan_records: &[u8]) -> bool {
    Plan::parse(plan_records).is_ok_and(|plan| plan.transport == 17 && plan.proto == PROTO_VOICE)
}

pub fn decode_r2o_voice_proof(frame: &Frame) -> Result<R2oVoiceProofEvent, &'static str> {
    let proof = match frame.kind {
        EVENT_R2O_VOICE_PROOF if frame.body.len() == KEY_LEN + 22 => {
            let mapped_ip = std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(&frame.body[KEY_LEN + 16..KEY_LEN + 20])
                    .map_err(|_| "неверный адрес ответа Discord Discovery")?,
            );
            let mapped_port = u16::from_be_bytes(
                frame.body[KEY_LEN + 20..KEY_LEN + 22]
                    .try_into()
                    .map_err(|_| "неверный порт ответа Discord Discovery")?,
            );
            R2oVoiceProofKind::DiscordDiscovery {
                mapped_ip,
                mapped_port,
            }
        }
        EVENT_R2O_VOICE_STUN_PROOF if frame.body.len() == KEY_LEN + 16 => {
            R2oVoiceProofKind::StunBinding
        }
        EVENT_R2O_VOICE_RTP_PROOF if frame.body.len() == KEY_LEN + 18 => {
            R2oVoiceProofKind::RtpMedia {
                outbound_packets: frame.body[KEY_LEN + 16],
                inbound_packets: frame.body[KEY_LEN + 17],
            }
        }
        EVENT_R2O_VOICE_PROOF => {
            return Err("неверное событие подтверждения Discord Discovery");
        }
        EVENT_R2O_VOICE_STUN_PROOF => return Err("неверное событие подтверждения STUN"),
        _ => return Err("неизвестный тип подтверждения голосового потока"),
    };
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ подтверждения Discord Discovery")?;
    if !valid_flow_key(&key) || key[0] != 4 || key[37] != 17 {
        return Err("подтверждение Discord Discovery содержит неверный IPv4 UDP-поток");
    }
    let trial_id: [u8; 16] = frame.body[KEY_LEN..KEY_LEN + 16]
        .try_into()
        .map_err(|_| "неверный идентификатор опыта Discord Discovery")?;
    let event = R2oVoiceProofEvent {
        key,
        trial_id,
        proof,
    };
    if event.event_body().is_none() {
        return Err("подтверждение Discord Discovery содержит пустую или недопустимую метку");
    }
    Ok(event)
}

pub fn encode_set_https(name: &str, ttl_seconds: u32) -> Result<Vec<u8>, &'static str> {
    if !valid_control_dns_name(name) {
        return Err("имя HTTPS должно быть корректным DNS-именем длиной до 253 байт");
    }
    if ttl_seconds > MAX_HTTPS_TTL_SECONDS {
        return Err("срок проверки HTTPS превышает шесть часов");
    }
    let mut body = Vec::with_capacity(5 + name.len());
    body.push(name.len() as u8);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(&ttl_seconds.to_be_bytes());
    encode_frame(COMMAND_SET_HTTPS, &body)
}

/// Кодирует полевой бюджет и измеренные пороги потока TCP.
pub fn encode_set_tcp_stall_budgets(budgets: &[u16]) -> Result<Vec<u8>, &'static str> {
    if budgets.len() > MAX_TCP_STALL_BUDGETS || budgets.contains(&0) {
        return Err("для бюджета TCP допустимы не более восьми ненулевых значений");
    }
    let mut body = Vec::with_capacity(1 + budgets.len() * 2);
    body.push(budgets.len() as u8);
    for budget in budgets {
        body.extend_from_slice(&budget.to_be_bytes());
    }
    encode_frame(COMMAND_SET_TCP_STALL_BUDGETS, &body)
}

/// Разбирает список бюджетов TCP; пустой список возвращает полевой порог.
pub fn decode_set_tcp_stall_budgets(frame: &Frame) -> Result<Vec<u16>, &'static str> {
    if frame.kind != COMMAND_SET_TCP_STALL_BUDGETS || frame.body.is_empty() {
        return Err("неверный кадр установки бюджета TCP");
    }
    let count = usize::from(frame.body[0]);
    if count > MAX_TCP_STALL_BUDGETS || frame.body.len() != 1 + count * 2 {
        return Err("неверная длина списка бюджетов TCP");
    }
    let mut budgets = Vec::with_capacity(count);
    for pair in frame.body[1..].chunks_exact(2) {
        let budget = u16::from_be_bytes([pair[0], pair[1]]);
        if budget == 0 {
            return Err("бюджет TCP не может быть нулевым");
        }
        budgets.push(budget);
    }
    Ok(budgets)
}

pub fn encode_set_name_probe(
    name: &str,
    shape: u8,
    family: u8,
    source_port: u16,
    plan_records: &[u8],
    trial_id: [u8; 16],
) -> Result<Vec<u8>, &'static str> {
    if name.is_empty() || name.len() > u8::MAX as usize {
        return Err("имя должно занимать от 1 до 255 байт");
    }
    if !valid_name_probe_plan_records(shape, plan_records)
        || !matches!(family, 4 | 6)
        || source_port == 0
    {
        return Err(
            "временная TCP-проба требует совместимые форму и план, IP family и ненулевой source port",
        );
    }
    let mut body = Vec::with_capacity(5 + name.len() + plan_records.len() + trial_id.len());
    body.push(name.len() as u8);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(&[shape, family]);
    body.extend_from_slice(&source_port.to_be_bytes());
    body.extend_from_slice(plan_records);
    body.extend_from_slice(&trial_id);
    encode_frame(COMMAND_SET_NAME_PROBE, &body)
}

pub fn encode_delete_name(
    name: &str,
    transport: u8,
    shape: u8,
    family: u8,
) -> Result<Vec<u8>, &'static str> {
    if name.is_empty() || name.len() > u8::MAX as usize {
        return Err("имя должно занимать от 1 до 255 байт");
    }
    if !matches!(family, 4 | 6)
        || !(transport == 6
            && matches!(
                shape,
                SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP | SHAPE_HTTP
            )
            || transport == 17 && matches!(shape, SHAPE_VOICE | SHAPE_QUIC))
    {
        return Err("привязка требует поддерживаемые транспорт, форму и семейство");
    }
    let mut body = Vec::with_capacity(4 + name.len());
    body.push(name.len() as u8);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(&[transport, shape, family]);
    encode_frame(COMMAND_DEL_NAME, &body)
}

pub fn encode_delete_name_probe(
    name: &str,
    shape: u8,
    family: u8,
    source_port: u16,
) -> Result<Vec<u8>, &'static str> {
    if name.is_empty() || name.len() > u8::MAX as usize {
        return Err("имя должно занимать от 1 до 255 байт");
    }
    if !valid_tcp_probe_shape(shape) || !matches!(family, 4 | 6) || source_port == 0 {
        return Err(
            "удаление временной TCP-пробы требует поддерживаемую форму, IP family и ненулевой source port",
        );
    }
    let mut body = Vec::with_capacity(5 + name.len());
    body.push(name.len() as u8);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(&[shape, family]);
    body.extend_from_slice(&source_port.to_be_bytes());
    encode_frame(COMMAND_DEL_NAME_PROBE, &body)
}

fn valid_tcp_probe_shape(shape: u8) -> bool {
    matches!(
        shape,
        SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP | SHAPE_HTTP
    )
}

fn valid_name_probe_plan_records(shape: u8, records: &[u8]) -> bool {
    Plan::parse(records).is_ok_and(|plan| match shape {
        SHAPE_HTTP => plan.transport == 6 && plan.proto == PROTO_HTTP,
        SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP => plan.transport == 6 && plan.proto == 1,
        _ => false,
    })
}

pub fn encode_ack(command: u16, ok: bool, reason: u8) -> Result<Vec<u8>, &'static str> {
    encode_ack_for_trial(command, ok, reason, None)
}

pub fn encode_ack_for_trial(
    command: u16,
    ok: bool,
    reason: u8,
    trial_id: Option<[u8; 16]>,
) -> Result<Vec<u8>, &'static str> {
    encode_ack_with_binding(command, ok, reason, trial_id, None)
}

pub fn encode_ack_with_binding(
    command: u16,
    ok: bool,
    reason: u8,
    trial_id: Option<[u8; 16]>,
    binding_context: Option<BindingContext>,
) -> Result<Vec<u8>, &'static str> {
    if trial_id.is_some()
        && !matches!(
            command,
            COMMAND_SET_NAME_PROBE
                | COMMAND_SET_VOICE_ADDR_PROBE
                | COMMAND_DEL_VOICE_ADDR_PROBE
                | COMMAND_SET_ADDR_PROBE
                | COMMAND_DEL_ADDR_PROBE
        )
    {
        return Err("trial ID ACK разрешён только для временной привязки");
    }
    if let Some(binding) = binding_context
        && (!ok
            || trial_id.is_some()
            || command != COMMAND_SET_NAME
            || !binding.is_known()
            || binding.kind != 1
            || !matches!(binding.family, 4 | 6)
            || binding.shape != SHAPE_HTTP
            || binding.temporary)
    {
        return Err("контекст привязки ACK допустим только для постоянного HTTP-плана имени");
    }
    let mut body = Vec::with_capacity(
        KEY_LEN
            + 4
            + trial_id.map_or(0, |_| 16)
            + binding_context.map_or(0, |_| ACK_BINDING_CONTEXT_LEN),
    );
    body.resize(KEY_LEN + 4, 0);
    body[0] = 4;
    body[KEY_LEN..KEY_LEN + 2].copy_from_slice(&command.to_be_bytes());
    body[KEY_LEN + 2] = u8::from(ok);
    body[KEY_LEN + 3] = if ok { ACK_OK } else { reason };
    if let Some(trial_id) = trial_id {
        body.extend_from_slice(&trial_id);
    }
    if let Some(binding) = binding_context {
        body.extend_from_slice(ACK_BINDING_CONTEXT_MAGIC);
        body.extend_from_slice(&binding.generation.to_be_bytes());
        body.extend_from_slice(&[
            binding.kind,
            binding.family,
            binding.shape,
            u8::from(binding.temporary),
        ]);
        body.extend_from_slice(&binding.epoch);
    }
    encode_frame(EVENT_ACK, &body)
}

pub fn decode_ack(frame: &Frame) -> Result<Ack, &'static str> {
    if frame.kind != EVENT_ACK || frame.body.len() < KEY_LEN + 4 {
        return Err("неверное подтверждение команды");
    }
    validate_zero_key(&frame.body[..KEY_LEN])?;
    let command = u16::from_be_bytes([frame.body[KEY_LEN], frame.body[KEY_LEN + 1]]);
    let ok = match frame.body[KEY_LEN + 2] {
        0 => false,
        1 => true,
        _ => return Err("неверный признак успеха в подтверждении"),
    };
    let reason = frame.body[KEY_LEN + 3];
    if ok && reason != ACK_OK {
        return Err("успешное подтверждение содержит код отказа");
    }
    let supports_trial_id = matches!(
        command,
        COMMAND_SET_NAME_PROBE
            | COMMAND_SET_VOICE_ADDR_PROBE
            | COMMAND_DEL_VOICE_ADDR_PROBE
            | COMMAND_SET_ADDR_PROBE
            | COMMAND_DEL_ADDR_PROBE
    );
    let mut cursor = KEY_LEN + 4;
    let remaining = frame.body.len() - cursor;
    let trial_id = if remaining == 16 && supports_trial_id {
        let trial_id = frame.body[cursor..]
            .try_into()
            .map_err(|_| "неверный trial ID в подтверждении")?;
        cursor += 16;
        Some(trial_id)
    } else {
        None
    };
    let binding_context = if cursor == frame.body.len() {
        None
    } else if command == COMMAND_SET_NAME
        && frame.body.len() == cursor + ACK_BINDING_CONTEXT_LEN
        && frame.body[cursor..cursor + 4] == *ACK_BINDING_CONTEXT_MAGIC
    {
        let context = &frame.body[cursor + 4..];
        let binding = BindingContext {
            generation: u64::from_be_bytes(
                context[..8]
                    .try_into()
                    .map_err(|_| "неверное поколение привязки ACK")?,
            ),
            kind: context[8],
            family: context[9],
            shape: context[10],
            temporary: match context[11] {
                0 => false,
                1 => true,
                _ => return Err("неверный признак временной привязки ACK"),
            },
            epoch: context[12..28]
                .try_into()
                .map_err(|_| "неверная эпоха таблицы привязок ACK")?,
        };
        if !binding.is_known()
            || binding.kind != 1
            || !matches!(binding.family, 4 | 6)
            || binding.shape != SHAPE_HTTP
            || binding.temporary
            || !ok
        {
            return Err("ACK содержит неверный HTTP-контекст привязки");
        }
        Some(binding)
    } else {
        return Err("неверная длина подтверждения команды");
    };
    Ok(Ack {
        command,
        ok,
        reason,
        trial_id,
        binding_context,
    })
}

#[cfg(test)]
mod ack_binding_context_tests {
    use super::{
        BindingContext, COMMAND_SET_NAME, SHAPE_HTTP, decode_ack, encode_ack_for_trial,
        encode_ack_with_binding, read_frame,
    };
    use std::io::Cursor;

    #[test]
    fn ack_round_trips_current_permanent_binding_context() {
        let binding = BindingContext {
            generation: 42,
            kind: 1,
            family: 4,
            shape: SHAPE_HTTP,
            temporary: false,
            epoch: [7; 16],
        };
        let bytes = encode_ack_with_binding(COMMAND_SET_NAME, true, 0, None, Some(binding))
            .expect("valid HTTP ACK context");
        let frame = read_frame(&mut Cursor::new(bytes)).unwrap();
        let ack = decode_ack(&frame).unwrap();
        assert_eq!(ack.command, COMMAND_SET_NAME);
        assert_eq!(ack.binding_context, Some(binding));
    }

    #[test]
    fn legacy_ack_without_binding_context_remains_valid() {
        let bytes =
            encode_ack_for_trial(super::COMMAND_SET_NAME_PROBE, true, 0, Some([9; 16])).unwrap();
        let frame = read_frame(&mut Cursor::new(bytes)).unwrap();
        let ack = decode_ack(&frame).unwrap();
        assert_eq!(ack.trial_id, Some([9; 16]));
        assert_eq!(ack.binding_context, None);
    }

    #[test]
    fn ack_rejects_malformed_runtime_binding_context() {
        let binding = BindingContext {
            generation: 42,
            kind: 1,
            family: 4,
            shape: SHAPE_HTTP,
            temporary: false,
            epoch: [7; 16],
        };
        let bytes = encode_ack_with_binding(COMMAND_SET_NAME, true, 0, None, Some(binding))
            .expect("valid HTTP ACK context");
        let mut frame = read_frame(&mut Cursor::new(bytes)).unwrap();
        let family_offset = super::KEY_LEN + 4 + 4 + 8 + 1;
        frame.body[family_offset] = 0;
        assert!(decode_ack(&frame).is_err());

        let temporary = BindingContext {
            temporary: true,
            ..binding
        };
        assert!(encode_ack_with_binding(COMMAND_SET_NAME, true, 0, None, Some(temporary)).is_err());
    }
}

pub fn decode_applied(frame: &Frame) -> Result<AppliedEvent, &'static str> {
    if frame.kind != EVENT_APPLIED || frame.body.len() != KEY_LEN + 16 + 16 + EXECUTION_CONTEXT_LEN
    {
        return Err("неверный размер события APPLIED");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ события APPLIED")?;
    if !valid_flow_key(&key) {
        return Err("событие APPLIED содержит неверный ключ потока");
    }
    let plan_id = frame.body[KEY_LEN..KEY_LEN + 16]
        .try_into()
        .map_err(|_| "неверный идентификатор плана в событии APPLIED")?;
    let trial_id = frame.body[KEY_LEN + 16..KEY_LEN + 32]
        .try_into()
        .map_err(|_| "неверный идентификатор испытания в событии APPLIED")?;
    let context = &frame.body[KEY_LEN + 32..];
    let binding = BindingContext {
        generation: u64::from_be_bytes(
            context[8..16]
                .try_into()
                .map_err(|_| "неверное поколение привязки APPLIED")?,
        ),
        kind: context[16],
        family: context[17],
        shape: context[18],
        temporary: match context[19] {
            0 => false,
            1 => true,
            _ => return Err("неверный признак временной привязки APPLIED"),
        },
        epoch: context[20..36]
            .try_into()
            .map_err(|_| "неверная эпоха таблицы привязок APPLIED")?,
    };
    if !valid_binding(&binding) {
        return Err("событие APPLIED содержит неверную привязку");
    }
    Ok(AppliedEvent {
        key,
        plan_id,
        trial_id,
        execution_id: u64::from_be_bytes(
            context[..8]
                .try_into()
                .map_err(|_| "неверный идентификатор исполнения APPLIED")?,
        ),
        binding,
    })
}

pub fn decode_refused(frame: &Frame) -> Result<RefusedEvent, &'static str> {
    const BASE_LEN: usize = KEY_LEN + 1 + 16 + 16;
    if frame.kind != EVENT_REFUSED
        || !(frame.body.len() == BASE_LEN
            || frame.body.len() == BASE_LEN + 1
            || frame.body.len() == BASE_LEN + 1 + EXECUTION_CONTEXT_LEN)
    {
        return Err("неверный размер события REFUSED");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ события REFUSED")?;
    if !valid_flow_key(&key) {
        return Err("событие REFUSED содержит неверный ключ потока");
    }
    let code = frame.body[KEY_LEN];
    let plan_start = KEY_LEN + 1;
    let plan_id = frame.body[plan_start..plan_start + 16]
        .try_into()
        .map_err(|_| "неверный идентификатор плана в событии REFUSED")?;
    let trial_start = plan_start + 16;
    let trial_id = frame.body[trial_start..trial_start + 16]
        .try_into()
        .map_err(|_| "неверный идентификатор испытания в событии REFUSED")?;
    let client_shape = if frame.body.len() > BASE_LEN {
        let shape = frame.body[BASE_LEN];
        if shape > SHAPE_HTTP {
            return Err("событие REFUSED содержит неизвестную форму ClientHello");
        }
        Some(shape)
    } else {
        None
    };

    let (execution_id, binding) = if frame.body.len() == BASE_LEN + 1 + EXECUTION_CONTEXT_LEN {
        let context = &frame.body[BASE_LEN + 1..];
        let binding = BindingContext {
            generation: u64::from_be_bytes(
                context[8..16]
                    .try_into()
                    .map_err(|_| "неверное поколение привязки REFUSED")?,
            ),
            kind: context[16],
            family: context[17],
            shape: context[18],
            temporary: match context[19] {
                0 => false,
                1 => true,
                _ => return Err("неверный признак временной привязки REFUSED"),
            },
            epoch: context[20..36]
                .try_into()
                .map_err(|_| "неверная эпоха таблицы привязок REFUSED")?,
        };
        if !valid_binding(&binding) {
            return Err("событие REFUSED содержит неверную привязку");
        }
        (
            Some(u64::from_be_bytes(
                context[..8]
                    .try_into()
                    .map_err(|_| "неверный идентификатор исполнения REFUSED")?,
            )),
            Some(binding),
        )
    } else {
        (None, None)
    };

    Ok(RefusedEvent {
        key,
        code,
        plan_id,
        trial_id,
        client_shape,
        execution_id,
        binding,
    })
}

#[cfg(test)]
mod refused_event_tests {
    use super::{
        BindingContext, EVENT_REFUSED, Frame, KEY_LEN, RefusedEvent, SHAPE_LEGACY, decode_refused,
    };

    fn key() -> [u8; KEY_LEN] {
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 5]);
        key[17..21].copy_from_slice(&[198, 51, 100, 9]);
        key[33..35].copy_from_slice(&443_u16.to_be_bytes());
        key[35..37].copy_from_slice(&51_234_u16.to_be_bytes());
        key[37] = 6;
        key
    }

    #[test]
    fn refused_decodes_exact_trial_and_execution_context() {
        let expected = RefusedEvent {
            key: key(),
            code: 3,
            plan_id: [7; 16],
            trial_id: [8; 16],
            client_shape: Some(SHAPE_LEGACY),
            execution_id: Some(9),
            binding: Some(BindingContext {
                generation: 10,
                kind: 1,
                family: 4,
                shape: SHAPE_LEGACY,
                temporary: true,
                epoch: [11; 16],
            }),
        };
        let mut body = Vec::new();
        body.extend_from_slice(&expected.key);
        body.push(expected.code);
        body.extend_from_slice(&expected.plan_id);
        body.extend_from_slice(&expected.trial_id);
        body.push(expected.client_shape.unwrap());
        body.extend_from_slice(&expected.execution_id.unwrap().to_be_bytes());
        body.extend_from_slice(&expected.binding.unwrap().generation.to_be_bytes());
        body.extend_from_slice(&[
            expected.binding.unwrap().kind,
            expected.binding.unwrap().family,
            expected.binding.unwrap().shape,
            u8::from(expected.binding.unwrap().temporary),
        ]);
        body.extend_from_slice(&expected.binding.unwrap().epoch);

        assert_eq!(
            decode_refused(&Frame {
                kind: EVENT_REFUSED,
                body,
            }),
            Ok(expected)
        );
    }

    #[test]
    fn refused_accepts_legacy_identity_and_rejects_truncation() {
        let mut body = Vec::new();
        body.extend_from_slice(&key());
        body.push(0);
        body.extend_from_slice(&[1; 16]);
        body.extend_from_slice(&[2; 16]);
        let frame = Frame {
            kind: EVENT_REFUSED,
            body,
        };
        let event = decode_refused(&frame).unwrap();
        assert_eq!(event.code, 0);
        assert_eq!(event.client_shape, None);
        assert_eq!(event.execution_id, None);
        assert_eq!(event.binding, None);

        let mut truncated = frame;
        truncated.body.pop();
        assert!(decode_refused(&truncated).is_err());
    }
}

pub fn decode_hello(frame: &Frame) -> Result<HelloEvent, &'static str> {
    if frame.kind != EVENT_HELLO || frame.body.len() < KEY_LEN + 1 {
        return Err("неверное событие TLS ClientHello");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ TLS ClientHello")?;
    if !matches!(key[0], 4 | 6) || !matches!(key[37], 6 | 17) {
        return Err("событие ClientHello содержит неверный ключ транспорта");
    }
    let host_len = usize::from(frame.body[KEY_LEN]);
    if host_len > MAX_DNS_NAME_LEN {
        return Err("неверная длина имени в событии ClientHello");
    }
    let host_end = KEY_LEN + 1 + host_len;
    let (shape, r2o_wire_len, quic_snapshot, tcp_has_timestamp) = match frame.body.len() {
        length if length == host_end && key[37] == 6 => (None, None, None, None),
        length if length == host_end + 1 || length >= host_end + 3 => {
            let shape = frame.body[host_end];
            let valid_shape = match key[37] {
                6 => matches!(
                    shape,
                    SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP | SHAPE_HTTP
                ),
                17 => shape == SHAPE_QUIC,
                _ => false,
            };
            if !valid_shape {
                return Err("событие ClientHello содержит неизвестную форму");
            }
            if length == host_end + 1 {
                (Some(shape), None, None, None)
            } else if key[37] == 6 {
                if length != host_end + 3 && length != host_end + 5 {
                    return Err("неверная длина события TLS ClientHello");
                }
                if !matches!(shape, SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP) {
                    return Err("длина TLS разрешена только для ClientHello TCP");
                }
                let r2o_wire_len = usize::from(u16::from_be_bytes([
                    frame.body[host_end + 1],
                    frame.body[host_end + 2],
                ]));
                if !(5..=4096).contains(&r2o_wire_len) {
                    return Err("неверная длина TLS-записи в событии ClientHello");
                }
                let tcp_has_timestamp = if length == host_end + 5 {
                    if frame.body[host_end + 3] != TCP_TIMESTAMP_METADATA_MARKER {
                        return Err("неверная метка TCP timestamp metadata");
                    }
                    match frame.body[host_end + 4] {
                        0 => Some(false),
                        1 => Some(true),
                        _ => return Err("неверный признак TCP timestamp option"),
                    }
                } else {
                    None
                };
                (Some(shape), Some(r2o_wire_len), None, tcp_has_timestamp)
            } else {
                if shape != SHAPE_QUIC {
                    return Err("снимок разрешён только для QUIC Initial");
                }
                let snapshot_len = usize::from(u16::from_be_bytes([
                    frame.body[host_end + 1],
                    frame.body[host_end + 2],
                ]));
                let snapshot_end = host_end + 3 + snapshot_len;
                if snapshot_len == 0 || snapshot_end != length {
                    return Err("неверная длина снимка QUIC Initial");
                }
                let snapshot = &frame.body[host_end + 3..snapshot_end];
                let parsed = crate::quic_snapshot::r2k_quic_snapshot_parse(snapshot)
                    .ok_or("неверный снимок QUIC Initial")?;
                let snapshot_host =
                    crate::quic::r2k_quic_initial_sni_result_from_datagrams(parsed.datagrams())
                        .map_err(|_| "снимок QUIC не содержит полного ClientHello")?;
                if snapshot_host.as_deref()
                    != (host_len != 0).then_some(&frame.body[KEY_LEN + 1..host_end])
                {
                    return Err("имя события не совпадает со снимком QUIC");
                }
                (Some(shape), None, Some(snapshot.to_vec()), None)
            }
        }
        _ => return Err("неверная длина события ClientHello"),
    };
    let host = (host_len != 0).then(|| frame.body[KEY_LEN + 1..host_end].to_vec());
    Ok(HelloEvent {
        key,
        host,
        shape,
        r2o_wire_len,
        quic_snapshot,
        tcp_has_timestamp,
    })
}

pub fn decode_client_shape(frame: &Frame) -> Result<ClientShapeEvent, &'static str> {
    if frame.kind != EVENT_CLIENT_SHAPE || frame.body.len() < KEY_LEN + 6 {
        return Err("неверное событие полного ClientHello TCP");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ события полного ClientHello")?;
    if !valid_flow_key(&key) || key[37] != 6 {
        return Err("снимок ClientHello привязан не к TCP-потоку");
    }
    let host_len = usize::from(frame.body[KEY_LEN]);
    if host_len == 0 || host_len > MAX_DNS_NAME_LEN {
        return Err("неверная длина имени полного ClientHello");
    }
    let shape_at = KEY_LEN + 1 + host_len;
    let wire_len_at = shape_at + 1;
    let snapshot_len_at = wire_len_at + 2;
    let snapshot_at = snapshot_len_at + 2;
    if frame.body.len() < snapshot_at {
        return Err("усечён заголовок полного ClientHello");
    }
    let shape = frame.body[shape_at];
    if !matches!(shape, SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP) {
        return Err("полный ClientHello имеет неподдерживаемую форму");
    }
    let wire_len = usize::from(u16::from_be_bytes([
        frame.body[wire_len_at],
        frame.body[wire_len_at + 1],
    ]));
    let snapshot_len = usize::from(u16::from_be_bytes([
        frame.body[snapshot_len_at],
        frame.body[snapshot_len_at + 1],
    ]));
    let snapshot_end = snapshot_at
        .checked_add(snapshot_len)
        .ok_or("переполнена длина полного ClientHello")?;
    let has_tcp_timestamp = frame.body.len() == snapshot_end + 2;
    if !(5..=4096).contains(&snapshot_len)
        || wire_len != snapshot_len
        || (frame.body.len() != snapshot_end && !has_tcp_timestamp)
    {
        return Err("неверная длина полного ClientHello");
    }
    let event = ClientShapeEvent {
        key,
        host: frame.body[KEY_LEN + 1..shape_at].to_vec(),
        shape,
        client_hello: frame.body[snapshot_at..snapshot_end].to_vec(),
        tcp_has_timestamp: if has_tcp_timestamp {
            if frame.body[snapshot_end] != TCP_TIMESTAMP_METADATA_MARKER {
                return Err("неверная метка TCP timestamp metadata");
            }
            match frame.body[snapshot_end + 1] {
                0 => Some(false),
                1 => Some(true),
                _ => return Err("неверный признак TCP timestamp option"),
            }
        } else {
            None
        },
    };
    if event.event_body().is_none() {
        return Err("форма, SNI или TLS-запись не совпадает со снимком ClientHello");
    }
    Ok(event)
}

fn valid_flow_key(key: &[u8; KEY_LEN]) -> bool {
    matches!(key[0], 4 | 6)
        && matches!(key[37], 6 | 17)
        && (key[0] != 4
            || key[5..17].iter().all(|byte| *byte == 0)
                && key[21..33].iter().all(|byte| *byte == 0))
}

#[cfg(test)]
mod r2o_tcp_exchange_control_tests {
    use super::{EVENT_R2O_TCP_EXCHANGE, Frame, R2oTcpExchangeEvent, decode_r2o_tcp_exchange};

    fn event() -> R2oTcpExchangeEvent {
        let mut key = [0; super::KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 4]);
        key[17..21].copy_from_slice(&[198, 51, 100, 7]);
        key[33..35].copy_from_slice(&443_u16.to_be_bytes());
        key[35..37].copy_from_slice(&52_314_u16.to_be_bytes());
        key[37] = 6;
        R2oTcpExchangeEvent {
            key,
            first_record_type: 22,
            bytes_after_client_hello: 1_380,
            record_types: 0x0c,
            server_hello: true,
            planned: true,
        }
    }

    #[test]
    fn tcp_exchange_round_trips_server_hello_and_application_record_evidence() {
        let expected = event();
        let frame = Frame {
            kind: EVENT_R2O_TCP_EXCHANGE,
            body: expected.event_body().unwrap(),
        };
        assert_eq!(decode_r2o_tcp_exchange(&frame), Ok(expected));
    }

    #[test]
    fn tcp_exchange_rejects_invalid_tls_type_bits_and_non_tcp_keys() {
        let mut expected = event();
        expected.record_types = 0x10;
        assert!(expected.event_body().is_none());

        let mut frame = Frame {
            kind: EVENT_R2O_TCP_EXCHANGE,
            body: event().event_body().unwrap(),
        };
        frame.body[super::KEY_LEN + 7] = 2;
        assert!(decode_r2o_tcp_exchange(&frame).is_err());
    }
}

pub fn decode_r2o_voice_suspect(frame: &Frame) -> Result<R2oVoiceSuspectEvent, &'static str> {
    if frame.kind != EVENT_R2O_VOICE_SUSPECT || frame.body.len() != KEY_LEN + 1 {
        return Err("неверное событие подозрения голосового потока");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ голосового потока")?;
    if !valid_flow_key(&key) || key[0] != 4 || key[37] != 17 || frame.body[KEY_LEN] > 1 {
        return Err("подозрение содержит неверный IPv4 UDP-поток или направление клиента");
    }
    Ok(R2oVoiceSuspectEvent {
        key,
        client_is_low: frame.body[KEY_LEN] == 1,
    })
}

pub fn decode_r2o_quic_suspect(frame: &Frame) -> Result<R2oQuicSuspectEvent, &'static str> {
    if frame.kind != EVENT_R2O_QUIC_SUSPECT || frame.body.len() != KEY_LEN + 2 {
        return Err("неверное событие подозрения молчания QUIC");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ UDP-потока QUIC")?;
    if !valid_flow_key(&key)
        || key[37] != 17
        || frame.body[KEY_LEN] > 1
        || frame.body[KEY_LEN + 1] > 1
    {
        return Err("подозрение содержит неверный UDP-поток или направление клиента");
    }
    Ok(R2oQuicSuspectEvent {
        key,
        client_is_low: frame.body[KEY_LEN] == 1,
        planned: frame.body[KEY_LEN + 1] == 1,
    })
}

pub fn decode_r2o_quic_stall(frame: &Frame) -> Result<R2oQuicSuspectEvent, &'static str> {
    if frame.kind != EVENT_R2O_QUIC_STALL || frame.body.len() != KEY_LEN + 2 {
        return Err("неверное событие зависания QUIC после ответа");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ зависшего UDP-потока QUIC")?;
    if !valid_flow_key(&key)
        || key[37] != 17
        || frame.body[KEY_LEN] > 1
        || frame.body[KEY_LEN + 1] > 1
    {
        return Err("зависание содержит неверный UDP-поток или направление клиента");
    }
    Ok(R2oQuicSuspectEvent {
        key,
        client_is_low: frame.body[KEY_LEN] == 1,
        planned: frame.body[KEY_LEN + 1] == 1,
    })
}

pub fn decode_r2o_tcp_silence(frame: &Frame) -> Result<R2oTcpSilenceEvent, &'static str> {
    if frame.kind != EVENT_R2O_TCP_SILENT || frame.body.len() != KEY_LEN + 6 {
        return Err("неверная длина события молчания TCP");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ TCP-потока")?;
    let client_is_low = frame.body[KEY_LEN];
    let planned = frame.body[KEY_LEN + 1];
    let elapsed_ms = u32::from_be_bytes(
        frame.body[KEY_LEN + 2..KEY_LEN + 6]
            .try_into()
            .map_err(|_| "обрезан интервал молчания TCP")?,
    );
    if !valid_flow_key(&key) || key[37] != 6 || client_is_low > 1 || planned > 1 || elapsed_ms == 0
    {
        return Err("событие молчания содержит неверный TCP-поток");
    }
    Ok(R2oTcpSilenceEvent {
        key,
        client_is_low: client_is_low == 1,
        planned: planned == 1,
        elapsed_ms,
    })
}

pub fn decode_r2o_tcp_clean_handshake(
    frame: &Frame,
) -> Result<R2oTcpCleanHandshakeEvent, &'static str> {
    if frame.kind != EVENT_R2O_TCP_CLEAN_HANDSHAKE || frame.body.len() != KEY_LEN {
        return Err("неверный размер события чистого TCP-рукопожатия");
    }
    let key: [u8; KEY_LEN] = frame.body[..]
        .try_into()
        .map_err(|_| "неверный ключ чистого TCP-рукопожатия")?;
    if !valid_flow_key(&key) || key[37] != 6 {
        return Err("событие чистого рукопожатия содержит неверный TCP-поток");
    }
    Ok(R2oTcpCleanHandshakeEvent { key })
}

pub fn decode_r2o_tcp_early_rst(frame: &Frame) -> Result<R2oTcpEarlyRstEvent, &'static str> {
    if frame.kind != EVENT_R2O_TCP_EARLY_RST || frame.body.len() != KEY_LEN + 7 {
        return Err("неверная длина события раннего TCP RST");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ раннего TCP RST")?;
    let client_is_low = frame.body[KEY_LEN];
    let planned = frame.body[KEY_LEN + 1];
    if !valid_flow_key(&key) || key[37] != 6 || client_is_low > 1 || planned > 1 {
        return Err("событие раннего TCP RST содержит неверный поток");
    }
    Ok(R2oTcpEarlyRstEvent {
        key,
        client_is_low: client_is_low == 1,
        planned: planned == 1,
        ttl: frame.body[KEY_LEN + 2],
        reference_ttl: frame.body[KEY_LEN + 3],
        traffic_class: frame.body[KEY_LEN + 4],
        ip_id: u16::from_be_bytes([frame.body[KEY_LEN + 5], frame.body[KEY_LEN + 6]]),
    })
}

pub fn decode_r2o_tcp_exchange(frame: &Frame) -> Result<R2oTcpExchangeEvent, &'static str> {
    if frame.kind != EVENT_R2O_TCP_EXCHANGE || frame.body.len() != KEY_LEN + 8 {
        return Err("неверная длина события TCP-обмена");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ события TCP-обмена")?;
    let first_record_type = frame.body[KEY_LEN];
    let bytes_after_client_hello = u32::from_be_bytes(
        frame.body[KEY_LEN + 1..KEY_LEN + 5]
            .try_into()
            .expect("длина проверена"),
    );
    let record_types = frame.body[KEY_LEN + 5];
    let server_hello = frame.body[KEY_LEN + 6];
    let planned = frame.body[KEY_LEN + 7];
    if !valid_flow_key(&key)
        || key[37] != 6
        || record_types & !0x0f != 0
        || server_hello > 1
        || planned > 1
    {
        return Err("событие TCP-обмена содержит неверный поток или признаки");
    }
    Ok(R2oTcpExchangeEvent {
        key,
        first_record_type,
        bytes_after_client_hello,
        record_types,
        server_hello: server_hello == 1,
        planned: planned == 1,
    })
}

pub fn decode_r2o_tcp_rst_cut_signal(
    frame: &Frame,
) -> Result<R2oTcpRstCutSignalEvent, &'static str> {
    if frame.kind != EVENT_R2O_TCP_RST_CUT || frame.body.len() != KEY_LEN + 6 {
        return Err("неверная длина события защитно снятого TCP RST");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ защитно снятого TCP RST")?;
    if !valid_flow_key(&key) || key[37] != 6 || frame.body[KEY_LEN] > 1 {
        return Err("событие защитно снятого RST содержит неверный поток или направление");
    }
    Ok(R2oTcpRstCutSignalEvent {
        key,
        client_is_low: frame.body[KEY_LEN] == 1,
        ttl: frame.body[KEY_LEN + 1],
        reference_ttl: frame.body[KEY_LEN + 2],
        traffic_class: frame.body[KEY_LEN + 3],
        ip_id: u16::from_be_bytes([frame.body[KEY_LEN + 4], frame.body[KEY_LEN + 5]]),
    })
}

pub fn decode_r2o_tcp_repeat(frame: &Frame) -> Result<R2oTcpRepeatEvent, &'static str> {
    if frame.kind != EVENT_R2O_TCP_REPEAT || frame.body.len() != KEY_LEN + 2 {
        return Err("неверная длина события повторного ClientHello TCP");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ повторного ClientHello TCP")?;
    let client_is_low = frame.body[KEY_LEN];
    let planned = frame.body[KEY_LEN + 1];
    if !valid_flow_key(&key) || key[37] != 6 || client_is_low > 1 || planned > 1 {
        return Err("повтор ClientHello содержит неверный TCP-поток");
    }
    Ok(R2oTcpRepeatEvent {
        key,
        client_is_low: client_is_low == 1,
        planned: planned == 1,
    })
}

pub fn decode_r2o_tcp_fin_retry(frame: &Frame) -> Result<R2oTcpFinRetryEvent, &'static str> {
    if frame.kind != EVENT_R2O_TCP_FIN_RETRY || frame.body.len() != KEY_LEN + 2 {
        return Err("неверная длина события повтора FIN в TCP");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ TCP-потока с повтором FIN")?;
    let client_is_low = frame.body[KEY_LEN];
    let planned = frame.body[KEY_LEN + 1];
    if !valid_flow_key(&key) || key[37] != 6 || client_is_low > 1 || planned > 1 {
        return Err("событие повтора FIN содержит неверный TCP-поток");
    }
    Ok(R2oTcpFinRetryEvent {
        key,
        client_is_low: client_is_low == 1,
        planned: planned == 1,
    })
}

pub fn decode_r2o_tcp_rst_after_app(frame: &Frame) -> Result<R2oTcpRstAfterAppEvent, &'static str> {
    if frame.kind != EVENT_R2O_TCP_RST_AFTER_APP || frame.body.len() != KEY_LEN + 2 {
        return Err("неверная длина события позднего RST после TLS app-data");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ TCP-потока с поздним RST")?;
    let client_is_low = frame.body[KEY_LEN];
    let planned = frame.body[KEY_LEN + 1];
    if !valid_flow_key(&key) || key[37] != 6 || client_is_low > 1 || planned > 1 {
        return Err("событие позднего RST содержит неверный TCP-поток");
    }
    Ok(R2oTcpRstAfterAppEvent {
        key,
        client_is_low: client_is_low == 1,
        planned: planned == 1,
    })
}

pub fn decode_r2o_tcp_stall(frame: &Frame) -> Result<R2oTcpStallEvent, &'static str> {
    if frame.kind != EVENT_R2O_TCP_STALL || frame.body.len() != KEY_LEN + 10 {
        return Err("неверный размер события зависшего TCP-потока");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ зависшего TCP-потока")?;
    if !valid_flow_key(&key) || key[37] != 6 {
        return Err("событие зависшего TCP-потока содержит неверный ключ");
    }
    let client_is_low = match frame.body[KEY_LEN] {
        0 => false,
        1 => true,
        _ => return Err("неверное направление события зависшего TCP-потока"),
    };
    let elapsed_ms = u32::from_be_bytes(
        frame.body[KEY_LEN + 1..KEY_LEN + 5]
            .try_into()
            .expect("длина проверена"),
    );
    let estimated_packets = u32::from_be_bytes(
        frame.body[KEY_LEN + 5..KEY_LEN + 9]
            .try_into()
            .expect("длина проверена"),
    );
    let planned = frame.body[KEY_LEN + 9];
    if elapsed_ms == 0 || estimated_packets == 0 || planned > 1 {
        return Err("событие зависшего TCP-потока содержит пустую оценку");
    }
    Ok(R2oTcpStallEvent {
        key,
        client_is_low,
        elapsed_ms,
        estimated_packets,
        planned: planned == 1,
    })
}

fn valid_binding(binding: &BindingContext) -> bool {
    binding.kind <= 4 && matches!(binding.family, 0 | 4 | 6) && binding.shape <= SHAPE_HTTP
}

/// Разбирает событие HTTP-портала v22 с необязательным контекстом запроса.
pub fn decode_http_portal(frame: &Frame) -> Result<HttpPortalEvent, &'static str> {
    if frame.kind != EVENT_HTTP_PORTAL || frame.body.len() < KEY_LEN + 2 {
        return Err("неверное событие HTTP portal");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ HTTP portal")?;
    if !matches!(key[0], 4 | 6) || key[37] != 6 {
        return Err("HTTP portal содержит неверный TCP-ключ");
    }
    let rest = &frame.body[KEY_LEN..];
    if rest[0] > 1 {
        return Err("HTTP portal содержит неверный признак HTTPS-ответа");
    }
    let host_len = usize::from(rest[1]);
    let context_offset = 2 + host_len;
    if host_len == 0 || host_len > MAX_DNS_NAME_LEN || rest.len() < context_offset {
        return Err("HTTP portal содержит обрезанное имя");
    }
    let context_len = rest.len() - context_offset;
    if context_len != 0 {
        if context_len < HTTP_CONTEXT_HEADER_LEN {
            return Err("HTTP portal содержит обрезанный контекст запроса");
        }
        let path_len = usize::from(u16::from_be_bytes([
            rest[context_offset + 48],
            rest[context_offset + 49],
        ]));
        if path_len >= 1024
            || !matches!(
                context_len,
                length if length == HTTP_CONTEXT_HEADER_LEN + path_len
                    || length == HTTP_CONTEXT_HEADER_LEN + path_len + HTTP_BINDING_LEN
            )
        {
            return Err("HTTP portal содержит неверную длину пути или привязки");
        }
    }
    Ok(HttpPortalEvent {
        key,
        answered: rest[0] != 0,
        host: rest[2..context_offset].to_vec(),
    })
}

pub fn decode_http_response(frame: &Frame) -> Result<HttpResponseEvent, &'static str> {
    if frame.kind != EVENT_HTTP_RESPONSE || frame.body.len() < KEY_LEN + 2 {
        return Err("неверное событие HTTP_RESPONSE");
    }
    let key: [u8; KEY_LEN] = frame.body[..KEY_LEN]
        .try_into()
        .map_err(|_| "неверный ключ HTTP_RESPONSE")?;
    if !valid_flow_key(&key) || key[37] != 6 {
        return Err("HTTP_RESPONSE содержит неверный TCP-ключ");
    }

    let rest = &frame.body[KEY_LEN..];
    let code = rest[0];
    let host_len = usize::from(rest[1]);
    if !matches!(code, 1..=4) || host_len == 0 {
        return Err("HTTP_RESPONSE содержит неверный исход или пустое имя");
    }
    let context_offset = 2 + host_len;
    let minimum_len =
        context_offset + HTTP_CONTEXT_HEADER_LEN + HTTP_BINDING_LEN + HTTP_RESPONSE_SUFFIX_LEN;
    if rest.len() < minimum_len {
        return Err("HTTP_RESPONSE содержит обрезанный контекст");
    }

    let context = &rest[context_offset..];
    let path_len = usize::from(u16::from_be_bytes([context[48], context[49]]));
    if path_len >= 1024
        || context.len()
            != HTTP_CONTEXT_HEADER_LEN + path_len + HTTP_BINDING_LEN + HTTP_RESPONSE_SUFFIX_LEN
    {
        return Err("HTTP_RESPONSE содержит неверную длину пути или данных");
    }

    let binding_offset = HTTP_CONTEXT_HEADER_LEN + path_len;
    let binding_bytes = &context[binding_offset..binding_offset + HTTP_BINDING_LEN];
    let binding = BindingContext {
        generation: u64::from_be_bytes(
            binding_bytes[..8]
                .try_into()
                .map_err(|_| "неверное поколение привязки HTTP_RESPONSE")?,
        ),
        kind: binding_bytes[8],
        family: binding_bytes[9],
        shape: binding_bytes[10],
        temporary: match binding_bytes[11] {
            0 => false,
            1 => true,
            _ => return Err("неверный признак временной привязки HTTP_RESPONSE"),
        },
        epoch: binding_bytes[12..28]
            .try_into()
            .map_err(|_| "неверная эпоха привязки HTTP_RESPONSE")?,
    };
    if !valid_binding(&binding) {
        return Err("HTTP_RESPONSE содержит неверную привязку");
    }

    let response = &context[binding_offset + HTTP_BINDING_LEN..];
    let status = u16::from_be_bytes([response[0], response[1]]);
    let body_bytes = u64::from_be_bytes(
        response[2..10]
            .try_into()
            .map_err(|_| "неверный размер тела HTTP_RESPONSE")?,
    );
    let request_no = u64::from_be_bytes(
        response[10..18]
            .try_into()
            .map_err(|_| "неверный номер запроса HTTP_RESPONSE")?,
    );
    if status > 599 || code == 1 && status < 200 || request_no == 0 {
        return Err("HTTP_RESPONSE содержит неверный статус или номер запроса");
    }

    Ok(HttpResponseEvent {
        key,
        code,
        host: rest[2..context_offset].to_vec(),
        execution_id: u64::from_be_bytes(
            context[..8]
                .try_into()
                .map_err(|_| "неверный execution ID HTTP_RESPONSE")?,
        ),
        plan_id: context[8..24]
            .try_into()
            .map_err(|_| "неверный plan ID HTTP_RESPONSE")?,
        trial_id: context[24..40]
            .try_into()
            .map_err(|_| "неверный trial ID HTTP_RESPONSE")?,
        request_ms: u64::from_be_bytes(
            context[40..48]
                .try_into()
                .map_err(|_| "неверное время запроса HTTP_RESPONSE")?,
        ),
        path: context[HTTP_CONTEXT_HEADER_LEN..binding_offset].to_vec(),
        binding,
        status,
        body_bytes,
        request_no,
    })
}

fn validate_zero_key(key: &[u8]) -> Result<(), &'static str> {
    if key.len() != KEY_LEN || key[0] != 4 || key[1..].iter().any(|byte| *byte != 0) {
        return Err("ожидался нулевой IPv4-ключ события");
    }
    Ok(())
}

fn valid_release_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes.iter().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || index > 0 && matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_control_dns_name(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_DNS_NAME_LEN || !value.is_ascii() {
        return false;
    }
    let value = value.strip_suffix('.').unwrap_or(value);
    let labels = value.split('.').collect::<Vec<_>>();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        && labels
            .iter()
            .any(|label| label.bytes().any(|byte| !byte.is_ascii_digit()))
}

#[cfg(test)]
mod clean_handshake_event_tests {
    use super::{
        EVENT_R2O_TCP_CLEAN_HANDSHAKE, Frame, KEY_LEN, R2oTcpCleanHandshakeEvent,
        decode_r2o_tcp_clean_handshake,
    };

    #[test]
    fn событие_чистого_tcp_рукопожатия_принимает_только_tcp_ключ() {
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 80]);
        key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&443_u16.to_be_bytes());
        key[37] = 6;
        let event = R2oTcpCleanHandshakeEvent { key };
        let frame = Frame {
            kind: EVENT_R2O_TCP_CLEAN_HANDSHAKE,
            body: event.event_body().unwrap(),
        };

        assert_eq!(decode_r2o_tcp_clean_handshake(&frame), Ok(event));

        let mut udp_key = key;
        udp_key[37] = 17;
        assert!(
            R2oTcpCleanHandshakeEvent { key: udp_key }
                .event_body()
                .is_none()
        );
    }
}

#[cfg(test)]
mod early_rst_event_tests {
    use super::{
        EVENT_R2O_TCP_EARLY_RST, Frame, KEY_LEN, R2oTcpEarlyRstEvent, decode_r2o_tcp_early_rst,
    };

    #[test]
    fn событие_раннего_rst_проверяет_tcp_направление_и_исполнение_плана() {
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 80]);
        key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&443_u16.to_be_bytes());
        key[37] = 6;
        let event = R2oTcpEarlyRstEvent {
            key,
            client_is_low: true,
            planned: false,
            ttl: 127,
            reference_ttl: 61,
            traffic_class: 0x88,
            ip_id: 54321,
        };
        let frame = Frame {
            kind: EVENT_R2O_TCP_EARLY_RST,
            body: event.event_body().unwrap(),
        };

        assert_eq!(decode_r2o_tcp_early_rst(&frame), Ok(event));

        let mut invalid = frame;
        invalid.body[KEY_LEN + 1] = 2;
        assert!(decode_r2o_tcp_early_rst(&invalid).is_err());
    }
}

#[cfg(test)]
mod tcp_repeat_event_tests {
    use super::{EVENT_R2O_TCP_REPEAT, Frame, KEY_LEN, R2oTcpRepeatEvent, decode_r2o_tcp_repeat};

    #[test]
    fn событие_повторного_clienthello_проверяет_ключ_направление_и_план() {
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 80]);
        key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&443_u16.to_be_bytes());
        key[37] = 6;
        let event = R2oTcpRepeatEvent {
            key,
            client_is_low: true,
            planned: false,
        };
        let frame = Frame {
            kind: EVENT_R2O_TCP_REPEAT,
            body: event.event_body().unwrap(),
        };

        assert_eq!(decode_r2o_tcp_repeat(&frame), Ok(event));

        let mut invalid = frame;
        invalid.body[KEY_LEN] = 2;
        assert!(decode_r2o_tcp_repeat(&invalid).is_err());
    }
}

#[cfg(test)]
mod quic_suspect_event_tests {
    use super::{
        EVENT_R2O_QUIC_SUSPECT, Frame, KEY_LEN, R2oQuicSuspectEvent, decode_r2o_quic_suspect,
    };

    #[test]
    fn событие_молчания_quic_сохраняет_направление_и_применение_плана() {
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 80]);
        key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&443_u16.to_be_bytes());
        key[37] = 17;
        let event = R2oQuicSuspectEvent {
            key,
            client_is_low: true,
            planned: true,
        };
        let frame = Frame {
            kind: EVENT_R2O_QUIC_SUSPECT,
            body: event.event_body().unwrap(),
        };

        assert_eq!(decode_r2o_quic_suspect(&frame), Ok(event));

        let mut invalid = frame;
        invalid.body[KEY_LEN + 1] = 2;
        assert!(decode_r2o_quic_suspect(&invalid).is_err());
    }
}

#[cfg(test)]
mod tcp_rst_cut_event_tests {
    use super::{
        EVENT_R2O_TCP_RST_CUT, Frame, KEY_LEN, R2oTcpRstCutSignalEvent,
        decode_r2o_tcp_rst_cut_signal,
    };

    #[test]
    fn защитно_снятый_rst_передаёт_направление_потока() {
        let mut key = [0; KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        key[17..21].copy_from_slice(&[198, 51, 100, 80]);
        key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
        key[35..37].copy_from_slice(&443_u16.to_be_bytes());
        key[37] = 6;
        let event = R2oTcpRstCutSignalEvent {
            key,
            client_is_low: true,
            ttl: 126,
            reference_ttl: 62,
            traffic_class: 0x88,
            ip_id: 12345,
        };
        let frame = Frame {
            kind: EVENT_R2O_TCP_RST_CUT,
            body: event.event_body().unwrap(),
        };

        assert_eq!(decode_r2o_tcp_rst_cut_signal(&frame), Ok(event));

        let mut invalid = frame;
        invalid.body[KEY_LEN] = 2;
        assert!(decode_r2o_tcp_rst_cut_signal(&invalid).is_err());
    }
}

#[cfg(test)]
mod arm_shape_command_tests {
    use super::{COMMAND_ARM_SHAPE, Frame, decode_arm_shape, encode_arm_shape};

    #[test]
    fn arm_shape_roundtrips_name_transport_and_family() {
        let bytes = encode_arm_shape("ask.example", 6, 6).unwrap();
        let frame = super::read_frame(&mut std::io::Cursor::new(bytes)).unwrap();
        assert_eq!(frame.kind, COMMAND_ARM_SHAPE);
        assert_eq!(
            decode_arm_shape(&frame),
            Ok(super::ArmShapeCommand {
                name: b"ask.example".to_vec(),
                transport: 6,
                family: 6,
            })
        );
    }

    #[test]
    fn arm_shape_rejects_invalid_transport_family_and_empty_name() {
        assert!(encode_arm_shape("", 6, 4).is_err());
        assert!(encode_arm_shape("ask.example", 17, 4).is_ok());
        assert!(encode_arm_shape("ask.example", 6, 5).is_err());

        let frame = Frame {
            kind: COMMAND_ARM_SHAPE,
            body: vec![3, b'a', b'b', b'c', 5, 4],
        };
        assert!(decode_arm_shape(&frame).is_err());
    }
}
