use crate::engine::validate_runtime_plan;
use r2k_core::addr::Address;
use r2k_core::control::{
    self, Ack, AppliedEvent, BindingContext, COMMAND_ARM_SHAPE, COMMAND_CLEAR, COMMAND_DEL_ADDR,
    COMMAND_DEL_ADDR_PROBE, COMMAND_DEL_BYPASS, COMMAND_DEL_NAME, COMMAND_DEL_NAME_BOUND,
    COMMAND_DEL_NAME_PROBE, COMMAND_DEL_SUFFIX, COMMAND_DEL_VOICE_ADDR_PROBE, COMMAND_SET_ADDR,
    COMMAND_SET_ADDR_PROBE, COMMAND_SET_BYPASS, COMMAND_SET_HTTPS, COMMAND_SET_NAME,
    COMMAND_SET_NAME_BOUND, COMMAND_SET_NAME_PROBE, COMMAND_SET_SUFFIX, COMMAND_SET_VOICE_ADDR,
    COMMAND_SET_VOICE_ADDR_PROBE, Frame, MAX_HTTPS_TTL_SECONDS, SHAPE_ECH_NO_TS, SHAPE_ECH_TCP,
    SHAPE_ECH_TS, SHAPE_GRANDFATHER, SHAPE_HTTP, SHAPE_LEGACY, SHAPE_MODERN, SHAPE_MODERN_NO_TS,
    SHAPE_MODERN_TS, SHAPE_QUIC, SHAPE_VOICE, TCP_PROFILE_UNKNOWN, decode_arm_shape,
    decode_client_shape, is_tcp_context_shape, is_tcp_plan_shape, r2k_link_shape_tcp_base,
    r2k_link_shape_tcp_context,
};
use r2k_core::packet::PacketView;
#[cfg(test)]
use r2k_core::plan::PLAN_MAGIC;
use r2k_core::plan::{PROTO_HTTP, PROTO_VOICE, Plan};
use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// C `D2K_CTL_OUT_RING` (`datapath/ctl.c:21`) — ровно 65536 байт.
const MAX_CONTROL_OUTPUT: usize = 64 * 1024;
pub const MAX_NAME_PLANS: usize = 2048;
/// C `probes[cap]` создаётся на `d2k_plantab_new(d2k_track_capacity(flows))`,
/// где `--flows` по умолчанию 2048 (`d2kd.c:1141`, `session.c:334`).
const MAX_FLOW_PROBES: usize = 2048;
const MAX_HTTPS_NAMES: usize = 256;
const MAX_VOICE_ADDR_PLANS: usize = 128;

const MAX_SUFFIX_PLANS: usize = 64;
const MAX_DOMAIN_BYPASSES: usize = 256;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct NamePlanKey {
    host: String,
    family: u8,
    shape: u8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct AddrPlanKey {
    address: Address,
    shape: u8,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct NameProbeKey {
    name: NamePlanKey,
    source_port: u16,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct VoiceProbeKey {
    client: Ipv4Addr,
    server: Ipv4Addr,
    server_port: u16,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SuffixPlanKey {
    suffix: String,
    transport: u8,
    family: u8,
    shape: u8,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DomainBypassKey {
    name: String,
    transport: u8,
    family: u8,
    shape: u8,
}

pub struct NamePlans {
    plans: HashMap<NamePlanKey, InstalledPlan>,
    addr_plans: HashMap<AddrPlanKey, InstalledPlan>,
    suffix_plans: HashMap<SuffixPlanKey, InstalledPlan>,
    domain_bypasses: HashSet<DomainBypassKey>,
    probes: HashMap<NameProbeKey, ProbePlan>,
    voice_addr_plans: HashMap<Ipv4Addr, InstalledPlan>,
    voice_addr_probes: HashMap<VoiceProbeKey, VoiceProbePlan>,
    addr_probes: HashMap<[u8; control::KEY_LEN], AddrProbePlan>,
    https_names: Vec<HttpsNameSlot>,
    exact_capacity: usize,
    plan_clock: Cell<u64>,
    /// C `next_binding`: монотонный номер привязки, не зависящий от revision.
    binding_generation: Cell<u64>,
    shape_misses: Cell<u64>,
    send_maxlen: usize,
    revision: u64,
    epoch: [u8; 16],
}

struct InstalledPlan {
    plan: Plan,
    generation: u64,
    last_used: Cell<u64>,
}

struct ProbePlan {
    plan: Plan,
    trial_id: [u8; 16],
    generation: u64,
    last_used: Cell<u64>,
}

struct VoiceProbePlan {
    plan: Plan,
    trial_id: [u8; 16],
    generation: u64,
    expires: Instant,
}

struct AddrProbePlan {
    plan: Plan,
    trial_id: [u8; 16],
    generation: u64,
    expires: Instant,
}

/// C `char name[254]` + `uint64_t expires` (`datapath/http80.c:23-27`):
/// фиксированные 256 слотов, вытеснение по минимальному `expires` с выбором
/// первого слота при равенстве — порядок слотов наблюдаем.
const HTTPS_NAME_BYTES: usize = 254;

#[derive(Clone, Copy)]
struct HttpsNameSlot {
    name: [u8; HTTPS_NAME_BYTES],
    len: u16,
    expires: Option<Instant>,
}

impl Default for HttpsNameSlot {
    fn default() -> Self {
        Self {
            name: [0; HTTPS_NAME_BYTES],
            len: 0,
            expires: None,
        }
    }
}

impl HttpsNameSlot {
    fn matches(&self, host: &[u8]) -> bool {
        let len = usize::from(self.len);
        len != 0 && &self.name[..len] == host
    }

    fn is_free(&self) -> bool {
        self.len == 0
    }

    fn assign(&mut self, host: &[u8], expires: Instant) {
        self.name = [0; HTTPS_NAME_BYTES];
        let len = host.len().min(HTTPS_NAME_BYTES - 1);
        self.name[..len].copy_from_slice(&host[..len]);
        self.len = len as u16;
        self.expires = Some(expires);
    }

    fn clear(&mut self) {
        self.name = [0; HTTPS_NAME_BYTES];
        self.len = 0;
        self.expires = None;
    }
}

#[derive(Clone, Copy)]
struct PlanBinding {
    trial_id: [u8; 16],
    generation: u64,
    shape: u8,
    temporary: bool,
}

enum ExactVictim {
    Name(NamePlanKey),
    Addr(AddrPlanKey),
    Probe(NameProbeKey),
}

impl Default for NamePlans {
    fn default() -> Self {
        Self::with_capacity(MAX_NAME_PLANS)
    }
}

impl NamePlans {
    pub fn with_capacity(exact_capacity: usize) -> Self {
        let mut epoch = [0; 16];
        if std::fs::File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut epoch))
            .is_err()
        {
            epoch = [0; 16];
        }
        Self {
            plans: HashMap::new(),
            addr_plans: HashMap::new(),
            suffix_plans: HashMap::new(),
            domain_bypasses: HashSet::new(),
            probes: HashMap::new(),
            voice_addr_plans: HashMap::new(),
            voice_addr_probes: HashMap::new(),
            addr_probes: HashMap::new(),
            https_names: vec![HttpsNameSlot::default(); MAX_HTTPS_NAMES],
            exact_capacity: exact_capacity.max(1),
            plan_clock: Cell::new(0),
            binding_generation: Cell::new(0),
            shape_misses: Cell::new(0),
            send_maxlen: 0,
            revision: 0,
            epoch,
        }
    }

    /// Задаёт предел одной raw-посылки, чтобы отклонять неподходящие планы до установки.
    pub fn r2o_set_send_maxlen(&mut self, maxlen: usize) {
        self.send_maxlen = maxlen;
    }

    /// Число записей `v[]` в терминах C: имена и адреса. Name-пробы в C
    /// лежат в `v[]` с `only_sport`, но отдельного `probe_used` не имеют,
    /// поэтому в этот счётчик не входят (`plans.c:1238-1240`).
    pub fn r2o_plan_count(&self) -> usize {
        self.plans.len() + self.addr_plans.len()
    }

    fn exact_usage(&self) -> usize {
        self.plans.len() + self.addr_plans.len() + self.probes.len()
    }

    pub const fn r2o_plan_capacity(&self) -> usize {
        self.exact_capacity
    }

    /// Число занятых адресных опытов так, как его видит C: `probe_used`
    /// включает QUIC- и VOICE-записи, а истёкшие удаляются лениво, поэтому
    /// счётчик не фильтрует по времени (`plans.c:1020-1022`).
    pub fn r2o_probe_count(&self, _now: Instant) -> usize {
        self.flow_probe_count()
    }

    fn flow_probe_count(&self) -> usize {
        self.addr_probes.len() + self.voice_addr_probes.len()
    }

    /// Ленивое удаление истёкших flow-проб, как C `probe_drop` внутри
    /// `find_probe`/`set_addr_probe` (`plans.c:985-987,931-934`).
    pub fn prune_expired_probes(&mut self, now: Instant) {
        let before = self.flow_probe_count();
        self.addr_probes.retain(|_, probe| probe.expires > now);
        self.voice_addr_probes
            .retain(|_, probe| probe.expires > now);
        if self.flow_probe_count() != before {
            self.revision = self.revision.wrapping_add(1);
        }
    }

    pub fn r2o_shape_misses(&self) -> u64 {
        self.shape_misses.get()
    }

    fn next_plan_clock(&self) -> u64 {
        let next = self.plan_clock.get().wrapping_add(1);
        self.plan_clock.set(next);
        next
    }

    fn touch(entry: &InstalledPlan, clock: u64) {
        entry.last_used.set(clock);
    }

    fn touch_probe(entry: &ProbePlan, clock: u64) {
        entry.last_used.set(clock);
    }

    fn exact_victim(&self) -> Option<ExactVictim> {
        let mut oldest: Option<(u64, ExactVictim)> = None;
        for (key, entry) in &self.plans {
            let used = entry.last_used.get();
            if oldest.as_ref().is_none_or(|(oldest, _)| used < *oldest) {
                oldest = Some((used, ExactVictim::Name(key.clone())));
            }
        }
        for (key, entry) in &self.addr_plans {
            let used = entry.last_used.get();
            if oldest.as_ref().is_none_or(|(oldest, _)| used < *oldest) {
                oldest = Some((used, ExactVictim::Addr(*key)));
            }
        }
        for (key, entry) in &self.probes {
            let used = entry.last_used.get();
            if oldest.as_ref().is_none_or(|(oldest, _)| used < *oldest) {
                oldest = Some((used, ExactVictim::Probe(key.clone())));
            }
        }
        oldest.map(|(_, victim)| victim)
    }

    fn make_room_exact(&mut self) -> bool {
        if self.exact_usage() < self.exact_capacity {
            return true;
        }
        match self.exact_victim() {
            Some(ExactVictim::Name(key)) => {
                self.plans.remove(&key);
                true
            }
            Some(ExactVictim::Addr(key)) => {
                self.addr_plans.remove(&key);
                true
            }
            Some(ExactVictim::Probe(key)) => {
                self.probes.remove(&key);
                true
            }
            None => false,
        }
    }

    fn r2o_plan_valid(&self, plan: &Plan) -> bool {
        validate_runtime_plan(plan).is_ok()
            && (self.send_maxlen == 0 || plan.max_emit() <= self.send_maxlen)
    }

    pub fn handle(&mut self, frame: &Frame) -> Ack {
        let addr_probe = matches!(frame.kind, COMMAND_SET_ADDR_PROBE | COMMAND_DEL_ADDR_PROBE);
        let area_command = matches!(
            frame.kind,
            COMMAND_SET_SUFFIX | COMMAND_DEL_SUFFIX | COMMAND_SET_BYPASS | COMMAND_DEL_BYPASS
        );
        let trial_id = if addr_probe {
            frame
                .body
                .get(control::KEY_LEN..control::KEY_LEN + 16)
                .and_then(|bytes| bytes.try_into().ok())
        } else if frame.kind == COMMAND_SET_NAME_BOUND {
            Some(
                frame
                    .body
                    .get(frame.body.len().saturating_sub(16)..)
                    .filter(|_| frame.body.len() >= 16)
                    .and_then(|bytes| bytes.try_into().ok())
                    .unwrap_or([0; 16]),
            )
        } else if matches!(
            frame.kind,
            COMMAND_SET_NAME_BOUND
                | COMMAND_SET_NAME_PROBE
                | COMMAND_SET_VOICE_ADDR_PROBE
                | COMMAND_DEL_VOICE_ADDR_PROBE
        ) && frame.body.len() >= 16
        {
            frame.body[frame.body.len() - 16..].try_into().ok()
        } else {
            None
        };
        let area_id = area_command.then(|| {
            frame
                .body
                .get(frame.body.len().saturating_sub(16)..)
                .filter(|_| frame.body.len() >= 16)
                .and_then(|bytes| bytes.try_into().ok())
                .unwrap_or([0; 16])
        });
        let body = if addr_probe {
            &frame.body
        } else if area_command && frame.body.len() >= 16 {
            &frame.body[..frame.body.len() - 16]
        } else if trial_id.is_some() && frame.body.len() >= 16 {
            &frame.body[..frame.body.len() - 16]
        } else {
            &frame.body
        };
        let (ok, reason) = if area_command && frame.body.len() < 16 {
            (false, control::ACK_BAD_ARGS)
        } else {
            match frame.kind {
                COMMAND_SET_NAME => self.set_name(body),
                COMMAND_SET_NAME_BOUND => self.set_name_bound(body),
                COMMAND_SET_ADDR => self.set_addr(body),
                COMMAND_SET_SUFFIX => self.set_suffix(body),
                COMMAND_DEL_SUFFIX => self.delete_domain_area(body, true),
                COMMAND_SET_BYPASS => self.set_domain_bypass(body),
                COMMAND_DEL_BYPASS => self.delete_domain_area(body, false),
                COMMAND_SET_NAME_PROBE => self.set_name_probe(body, trial_id),
                COMMAND_SET_VOICE_ADDR => self.set_voice_addr(body),
                COMMAND_SET_VOICE_ADDR_PROBE => self.set_voice_addr_probe(body, trial_id),
                COMMAND_DEL_VOICE_ADDR_PROBE => self.delete_voice_addr_probe(body, trial_id),
                COMMAND_SET_ADDR_PROBE => self.set_addr_probe(body),
                COMMAND_DEL_ADDR_PROBE => self.delete_addr_probe(body, trial_id),
                COMMAND_DEL_NAME => self.delete_name(body),
                COMMAND_DEL_NAME_BOUND => self.delete_name_bound(body),
                COMMAND_DEL_ADDR => self.delete_addr(body),
                COMMAND_DEL_NAME_PROBE => self.delete_name_probe(body),
                COMMAND_SET_HTTPS => self.set_https(body),
                COMMAND_CLEAR if frame.body.is_empty() => {
                    self.plans.clear();
                    self.addr_plans.clear();
                    self.suffix_plans.clear();
                    self.domain_bypasses.clear();
                    self.probes.clear();
                    self.voice_addr_plans.clear();
                    self.voice_addr_probes.clear();
                    self.addr_probes.clear();
                    for slot in &mut self.https_names {
                        slot.clear();
                    }
                    (true, control::ACK_OK)
                }
                COMMAND_CLEAR => (false, control::ACK_BAD_ARGS),
                _ => (false, control::ACK_BAD_ARGS),
            }
        };
        if ok && frame.kind != COMMAND_DEL_NAME_BOUND {
            self.revision = self.revision.wrapping_add(1);
        }
        Ack {
            command: frame.kind,
            ok,
            reason,
            trial_id,
            area_id,
            binding_context: if frame.kind == COMMAND_SET_NAME_BOUND {
                Some(if ok {
                    self.http_name_binding_context(body).unwrap_or_default()
                } else {
                    Default::default()
                })
            } else if ok && frame.kind == COMMAND_SET_NAME {
                self.http_name_binding_context(body)
            } else {
                None
            },
        }
    }

    fn set_name_bound(&mut self, body: &[u8]) -> (bool, u8) {
        let Some(name_len) = body.first().copied().map(usize::from) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if body.get(1 + name_len).copied() != Some(SHAPE_HTTP) {
            return (false, control::ACK_BAD_ARGS);
        }
        self.set_name(body)
    }

    fn http_name_binding_context(&self, body: &[u8]) -> Option<BindingContext> {
        let name_len = usize::from(*body.first()?);
        let fields_end = 3_usize.checked_add(name_len)?;
        if body.len() <= fields_end || body.get(1 + name_len).copied()? != SHAPE_HTTP {
            return None;
        }
        let family = body.get(2 + name_len).copied()?;
        if !matches!(family, 4 | 6) {
            return None;
        }
        let host = canonical_plan_name(&body[1..1 + name_len], SHAPE_HTTP)?;
        let plan = Plan::parse_wire(&body[fields_end..]).ok()?;
        let installed = self.plans.get(&NamePlanKey {
            host,
            family,
            shape: SHAPE_HTTP,
        })?;
        if installed.plan.id != plan.id {
            return None;
        }
        Some(BindingContext {
            generation: installed.generation,
            kind: 1,
            family,
            shape: SHAPE_HTTP,
            temporary: false,
            epoch: self.epoch,
        })
    }

    pub fn select(&self, packet: &[u8]) -> Option<&Plan> {
        self.select_with_quic_host_at_hook(packet, None, None)
    }

    /// Выбирает план по QUIC SNI, уже извлечённому циклом обработки пакетов.
    pub fn select_with_quic_host(&self, packet: &[u8], quic_host: Option<&[u8]>) -> Option<&Plan> {
        self.select_with_quic_host_at_hook(packet, quic_host, None)
    }

    /// Выбор плана для TCP-пакета с признаком управляющей пробы.
    pub fn select_with_quic_host_probe(
        &self,
        packet: &[u8],
        quic_host: Option<&[u8]>,
        controller_probe: bool,
    ) -> Option<&Plan> {
        self.select_with_quic_host_at_hook_probe(packet, quic_host, None, controller_probe)
    }

    pub fn select_with_quic_host_at_hook(
        &self,
        packet: &[u8],
        quic_host: Option<&[u8]>,
        hook: Option<u8>,
    ) -> Option<&Plan> {
        self.select_with_quic_host_at_hook_probe(packet, quic_host, hook, false)
    }

    /// Наблюдённая форма TCP ClientHello — ровно та же, что C кладёт в
    /// `fl->client_shape` (`session.c:2306-2357`) и передаёт в выбор плана.
    pub fn r2o_observed_tcp_shape(&self, packet: &[u8], controller_probe: bool) -> Option<u8> {
        let view = PacketView::parse(packet)?;
        if view.protocol != 6 {
            return None;
        }
        let tcp = view.tcp_segment(packet)?;
        let payload = packet.get(tcp.payload.clone())?;
        let tls = r2k_core::tls::parse(payload);
        if !tls.is_client_hello {
            return None;
        }
        let sni = tls
            .sni_range
            .filter(|range| range.end <= payload.len())
            .and_then(|range| payload.get(range));
        let probe_port = if controller_probe { tcp.source_port } else { 0 };
        let base_shape = if tls.ech_offer {
            SHAPE_ECH_TCP
        } else if tls.is_tls13 {
            // C `session.c:2325-2334`: оборванный блок расширений при живом
            // ECH-таргете не даёт объявлять MODERN.
            let any_shape = tls.extensions_truncated
                && sni.is_some_and(|sni| {
                    self.has_ech_target(Some(sni), Some(view.dst), view.family, probe_port)
                });
            if any_shape { 0 } else { SHAPE_MODERN }
        } else if tls.extensions_truncated {
            // Признака нет, а блок оборван — формы не объявляем.
            0
        } else {
            SHAPE_LEGACY
        };
        // D2O берёт TCP-профиль из самого ClientHello: при известном профиле
        // форма переходит в контекст 8–13.
        let tcp_profile = packet.get(tcp.options.clone()).map_or(
            TCP_PROFILE_UNKNOWN,
            PacketView::tcp_options_timestamp_profile,
        );
        Some(r2k_link_shape_tcp_context(base_shape, tcp_profile))
    }

    /// То же, но с признаком управляющей пробы: C передаёт `probe_port` в
    /// `d2k_plantab_has_ech_target` только для `controller_probe`.
    pub fn select_with_quic_host_at_hook_probe(
        &self,
        packet: &[u8],
        quic_host: Option<&[u8]>,
        hook: Option<u8>,
        controller_probe: bool,
    ) -> Option<&Plan> {
        let view = PacketView::parse(packet)?;
        if view.protocol == 17 {
            if let Some(probe) = self.addr_probe_binding_at_hook(packet, hook) {
                return Some(&probe.plan);
            }
            let payload = packet.get(view.udp_payload_range(packet)?)?;
            let destination_port = packet
                .get(view.l4_offset + 2..view.l4_offset + 4)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u16::from_be_bytes)?;
            if r2k_core::stun::is_discord_voice_request(payload, destination_port) {
                if let Some((r2o_plan, _, _, _)) = self.voice_address_binding(packet) {
                    return Some(r2o_plan);
                }
                let plan = self
                    .find_exact(b"@discord-voice", view.family, SHAPE_VOICE)
                    .or_else(|| {
                        self.find_addr_fallback(
                            view.dst,
                            Some(b"@discord-voice"),
                            view.family,
                            SHAPE_VOICE,
                            17,
                        )
                    });
                if plan.is_none() {
                    self.note_shape_miss(
                        Some(b"@discord-voice"),
                        view.dst,
                        view.family,
                        SHAPE_VOICE,
                    );
                }
                return plan;
            }
            if r2k_core::stun::is_binding_request(payload) {
                if let Some((r2o_plan, _, _, _)) = self.voice_address_binding(packet) {
                    return Some(r2o_plan);
                }
                let plan = self.find_addr(view.dst, SHAPE_VOICE);
                if plan.is_none() {
                    self.note_shape_miss(None, view.dst, view.family, SHAPE_VOICE);
                }
                return plan;
            }
            let source_port = packet
                .get(view.l4_offset..view.l4_offset + 2)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u16::from_be_bytes)?;
            if view.fragment & 0x3fff != 0
                || !crate::r2o_quic::r2o_quic_client_direction(source_port, destination_port, hook)
                || !r2k_core::quic::is_authenticated_initial(payload)
            {
                return None;
            }
            let derived_quic_host = quic_host
                .is_none()
                .then(|| r2k_core::quic::initial_client_hello_sni(payload))
                .flatten();
            let quic_host = quic_host.or(derived_quic_host.as_deref());
            return if let Some(quic_host) = quic_host {
                let plan = self
                    .find_exact(quic_host, view.family, SHAPE_QUIC)
                    .or_else(|| self.find_in_domain(quic_host, view.family, SHAPE_QUIC, 17))
                    .or_else(|| {
                        self.find_addr_fallback(
                            view.dst,
                            Some(quic_host),
                            view.family,
                            SHAPE_QUIC,
                            17,
                        )
                    });
                if plan.is_none() {
                    self.note_shape_miss(Some(quic_host), view.dst, view.family, SHAPE_QUIC);
                }
                plan
            } else {
                let plan = r2k_core::quic::is_authenticated_initial(payload)
                    .then(|| self.find_addr(view.dst, SHAPE_QUIC))
                    .flatten();
                if plan.is_none() {
                    self.note_shape_miss(None, view.dst, view.family, SHAPE_QUIC);
                }
                plan
            };
        }
        if view.protocol != 6 {
            return None;
        }
        let tcp = view.tcp_segment(packet)?;
        let payload = packet.get(tcp.payload)?;
        if let Some(host_range) = r2k_core::httpup::request_host_range(payload) {
            if tcp.destination_port == 80
                && let Some(probe) = self.probes.get(&NameProbeKey {
                    name: NamePlanKey {
                        host: canonical_plan_name(payload.get(host_range.clone())?, SHAPE_HTTP)?,
                        family: view.family,
                        shape: SHAPE_HTTP,
                    },
                    source_port: tcp.source_port,
                })
            {
                Self::touch_probe(probe, self.next_plan_clock());
                return Some(&probe.plan);
            }
            return self.find_exact(payload.get(host_range)?, view.family, SHAPE_HTTP);
        }
        let tls = r2k_core::tls::parse(payload);
        let sni = tls
            .sni_range
            .filter(|range| range.end <= payload.len())
            .and_then(|range| payload.get(range));
        let probe_port = if controller_probe { tcp.source_port } else { 0 };
        // Та же форма, что C сохраняет в `fl->client_shape` и отдаёт в
        // журнале отказа: считается одним методом с выбором плана.
        let shape = self.r2o_observed_tcp_shape(packet, controller_probe)?;
        // R2O-контроллер пока ставит планы в базовой форме 1/2/6, а D2O —
        // в контексте 8–13. Точный контекст имеет приоритет; базовая форма
        // остаётся совместимым мостом для уже установленных R2O-планов.
        let bridge_shape = r2k_link_shape_tcp_base(shape);
        let fallback_shape = match shape {
            SHAPE_ECH_TCP => Some(SHAPE_MODERN),
            SHAPE_ECH_NO_TS => Some(SHAPE_MODERN_NO_TS),
            SHAPE_ECH_TS => Some(SHAPE_MODERN_TS),
            _ => None,
        };
        let Some(sni) = sni else {
            if !tls.is_client_hello || tls.extensions_truncated {
                return None;
            }
            let plan = self
                .find_addr(view.dst, shape)
                .or_else(|| self.find_addr(view.dst, bridge_shape))
                .or_else(|| self.find_addr_shape_fits(view.dst, shape));
            if plan.is_none() {
                self.note_shape_miss(None, view.dst, view.family, shape);
            }
            return plan;
        };
        // C `find_target` с формой ANY: точная портовая проба без сверки
        // формы, затем записи ANY/GRANDFATHER и адресная совместимость.
        if shape == 0 {
            let plan = self.find_target(Some(sni), Some(view.dst), view.family, 0, probe_port);
            if plan.is_none() {
                self.note_shape_miss(Some(sni), view.dst, view.family, 0);
            }
            return plan;
        }
        if let Some(probe) = self
            .probes
            .get(&NameProbeKey {
                name: NamePlanKey {
                    host: canonical_plan_name(sni, shape)?,
                    family: view.family,
                    shape,
                },
                source_port: tcp.source_port,
            })
            .or_else(|| {
                self.probes.get(&NameProbeKey {
                    name: NamePlanKey {
                        host: canonical_plan_name(sni, bridge_shape)?,
                        family: view.family,
                        shape: bridge_shape,
                    },
                    source_port: tcp.source_port,
                })
            })
        {
            Self::touch_probe(probe, self.next_plan_clock());
            return Some(&probe.plan);
        }
        let plan = self
            .find_exact(sni, view.family, shape)
            .or_else(|| self.find_exact(sni, view.family, bridge_shape))
            .or_else(|| {
                fallback_shape.and_then(|fallback| self.find_exact(sni, view.family, fallback))
            })
            .or_else(|| self.find_exact(sni, view.family, SHAPE_GRANDFATHER))
            .or_else(|| self.find_shape_fits(sni, view.family, shape))
            .or_else(|| self.find_in_domain(sni, view.family, shape, 6))
            .or_else(|| self.find_in_domain(sni, view.family, bridge_shape, 6))
            .or_else(|| {
                fallback_shape
                    .and_then(|fallback| self.find_in_domain(sni, view.family, fallback, 6))
            })
            .or_else(|| self.find_addr_fallback(view.dst, Some(sni), view.family, shape, 6))
            .or_else(|| self.find_addr_fallback(view.dst, Some(sni), view.family, bridge_shape, 6))
            .or_else(|| self.find_addr_shape_fits(view.dst, shape));
        if plan.is_none() {
            self.note_shape_miss(Some(sni), view.dst, view.family, shape);
        }
        plan
    }

    /// C `scan_name`/`scan_addr` + `find_target`: цель известна, но плана
    /// наблюдаемой формы нет (`plans.c:1209,1233`).
    ///
    /// TCP: любая запись имени (кроме HTTP) уже даёт промах.
    /// UDP: запись имени другого транспорта не мешает адресному переходу;
    /// промах считается, если у имени есть своя UDP/ANY-запись или у адреса
    /// есть любая запись, не подошедшая по форме.
    fn note_shape_miss(&self, host: Option<&[u8]>, address: Address, family: u8, seen_shape: u8) {
        if let Some(host) = host {
            if self.name_has_udp_binding(host, family) {
                self.shape_misses
                    .set(self.shape_misses.get().saturating_add(1));
                return;
            }
            if !r2o_shape_is_udp(seen_shape) && self.name_has_any_binding(host, family) {
                self.shape_misses
                    .set(self.shape_misses.get().saturating_add(1));
                return;
            }
        }
        if self.addr_plans.keys().any(|key| key.address == address) {
            self.shape_misses
                .set(self.shape_misses.get().saturating_add(1));
        }
    }

    /// Есть ли у имени своя UDP-запись (QUIC/VOICE) или ANY, не подошедшая
    /// по форме. TCP-запись сюда не входит: для UDP она уступает адресу.
    fn name_has_udp_binding(&self, bytes: &[u8], family: u8) -> bool {
        let Some(host) = canonical_name(bytes) else {
            return false;
        };
        self.plans.keys().any(|key| {
            key.host == host
                && key.family == family
                && key.shape != SHAPE_HTTP
                && (r2o_shape_is_udp(key.shape) || key.shape == 0)
        })
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn has_verified_https(&self, host: &[u8], now: Instant) -> bool {
        let Some(host) = canonical_https_name(host) else {
            return false;
        };
        self.https_names.iter().any(|slot| {
            slot.matches(host.as_bytes()) && slot.expires.is_some_and(|expires| expires > now)
        })
    }

    /// Удаляет временные испытания после отключения контроллера.
    ///
    /// C `d2k_plantab_clear_probes` снимает ещё и постоянные name-записи с
    /// `qdeny`: запрет QUIC — не знание каталога, и без контроллера снимать
    /// его некому (`plans.c:897-910`).
    pub fn clear_probes(&mut self) {
        let mut cleared = false;
        self.plans.retain(|_, entry| {
            if entry.plan.quic_deny() {
                cleared = true;
                false
            } else {
                true
            }
        });
        if !self.probes.is_empty()
            || !self.voice_addr_probes.is_empty()
            || !self.addr_probes.is_empty()
        {
            self.probes.clear();
            self.voice_addr_probes.clear();
            self.addr_probes.clear();
            cleared = true;
        }
        if cleared {
            self.revision = self.revision.wrapping_add(1);
        }
    }

    pub fn has_tls_candidate(&self, family: u8) -> bool {
        self.plans.iter().any(|(key, entry)| {
            key.family == family && key.shape != SHAPE_HTTP && entry.plan.stream_input()
        }) || self.suffix_plans.iter().any(|(key, entry)| {
            key.transport == 6 && key.family == family && entry.plan.stream_input()
        }) || self.addr_plans.iter().any(|(key, entry)| {
            key.address.family() == family
                && matches!(key.shape, SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP)
                && entry.plan.stream_input()
        })
    }

    /// C `stream_candidate_target`: префильтр с именем/адресом/портом,
    /// `only_sport` и BYPASS для не-точных записей.
    pub fn has_tls_candidate_target(
        &self,
        name: Option<&[u8]>,
        address: Option<Address>,
        family: u8,
        source_port: u16,
    ) -> bool {
        let host = name.and_then(canonical_name);
        let exact = host.as_ref().is_some_and(|host| {
            self.plans.iter().any(|(key, entry)| {
                key.family == family
                    && key.shape != SHAPE_HTTP
                    && key.host == *host
                    && entry.plan.stream_input()
            })
        });
        let probes = host.as_ref().is_some_and(|host| {
            self.probes.iter().any(|(key, probe)| {
                key.name.family == family
                    && key.name.shape != SHAPE_HTTP
                    && key.name.host == *host
                    && key.source_port == source_port
                    && probe.plan.stream_input()
            })
        });
        let suffix = host.as_ref().is_some_and(|host| {
            self.suffix_plans.iter().any(|(key, entry)| {
                key.transport == 6
                    && key.family == family
                    && entry.plan.stream_input()
                    && domain_suffix_member(host, &key.suffix)
                    && !self.name_is_bypassed(host.as_bytes(), family, key.shape, 6)
            })
        });
        let addr = address.is_some_and(|address| {
            self.addr_plans.iter().any(|(key, entry)| {
                key.address == address
                    && key.address.family() == family
                    && matches!(key.shape, SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP)
                    && entry.plan.stream_input()
                    && host.as_ref().is_none_or(|host| {
                        !self.name_is_bypassed(host.as_bytes(), family, key.shape, 6)
                    })
            })
        });
        exact || probes || suffix || addr
    }

    /// C `d2k_plantab_http_candidate`: при `sport==0` подходит постоянная
    /// HTTP-запись (`only_sport==0`), при ненулевом — только проба этого порта
    /// (`plans.c:414-422`; `session.c:2821-2822`).
    pub fn has_http_candidate(&self, family: u8, source_port: u16) -> bool {
        if source_port == 0 {
            self.plans
                .keys()
                .any(|key| key.family == family && key.shape == SHAPE_HTTP)
        } else {
            self.probes.keys().any(|key| {
                key.name.family == family
                    && key.name.shape == SHAPE_HTTP
                    && key.source_port == source_port
            })
        }
    }

    pub fn has_quic_candidate(&self, family: u8) -> bool {
        self.plans
            .keys()
            .any(|key| key.family == family && key.shape == SHAPE_QUIC)
            || self
                .suffix_plans
                .keys()
                .any(|key| key.transport == 17 && key.family == family && key.shape == SHAPE_QUIC)
            || self
                .addr_plans
                .keys()
                .any(|key| key.address.family() == family && key.shape == SHAPE_QUIC)
    }

    pub fn applied_event_for_packet(
        &self,
        packet: &[u8],
        execution_id: u64,
    ) -> Option<AppliedEvent> {
        self.applied_event_for_packet_at_hook(packet, execution_id, None)
    }

    pub fn applied_event_for_packet_at_hook(
        &self,
        packet: &[u8],
        execution_id: u64,
        hook: Option<u8>,
    ) -> Option<AppliedEvent> {
        if execution_id == 0 {
            return None;
        }
        let view = PacketView::parse(packet)?;
        let kind = match view.protocol {
            6 => 1,
            17 => 2,
            _ => return None,
        };
        let plan = self.select_with_quic_host_at_hook(packet, None, hook)?;
        let binding = self.binding_for_plan(plan)?;
        let key = if view.protocol == 6 {
            crate::capture::TcpFlowKey::from_packet(packet)?.wire_key()
        } else {
            r2o_udp_flow_wire_key(packet)?
        };
        Some(AppliedEvent {
            key,
            plan_id: plan.id,
            trial_id: binding.trial_id,
            execution_id,
            binding: BindingContext {
                generation: binding.generation,
                kind,
                family: view.family,
                shape: binding.shape,
                temporary: binding.temporary,
                epoch: self.epoch,
            },
        })
    }

    fn binding_for_plan(&self, plan: &Plan) -> Option<PlanBinding> {
        for (key, installed) in &self.plans {
            if std::ptr::eq(&installed.plan, plan) {
                return Some(PlanBinding {
                    trial_id: [0; 16],
                    generation: installed.generation,
                    shape: key.shape,
                    temporary: false,
                });
            }
        }
        for (key, installed) in &self.addr_plans {
            if std::ptr::eq(&installed.plan, plan) {
                return Some(PlanBinding {
                    trial_id: [0; 16],
                    generation: installed.generation,
                    shape: key.shape,
                    temporary: false,
                });
            }
        }
        for (key, installed) in &self.suffix_plans {
            if std::ptr::eq(&installed.plan, plan) {
                return Some(PlanBinding {
                    trial_id: [0; 16],
                    generation: installed.generation,
                    shape: key.shape,
                    temporary: false,
                });
            }
        }
        for (key, probe) in &self.probes {
            if std::ptr::eq(&probe.plan, plan) {
                return Some(PlanBinding {
                    trial_id: probe.trial_id,
                    generation: probe.generation,
                    shape: key.name.shape,
                    temporary: true,
                });
            }
        }
        for probe in self.voice_addr_probes.values() {
            if std::ptr::eq(&probe.plan, plan) && probe.expires > Instant::now() {
                return Some(PlanBinding {
                    trial_id: probe.trial_id,
                    generation: probe.generation,
                    shape: flow_probe_shape(&probe.plan),
                    temporary: true,
                });
            }
        }
        for installed in self.voice_addr_plans.values() {
            if std::ptr::eq(&installed.plan, plan) {
                return Some(PlanBinding {
                    trial_id: [0; 16],
                    generation: installed.generation,
                    shape: SHAPE_VOICE,
                    temporary: false,
                });
            }
        }
        for probe in self.addr_probes.values() {
            if std::ptr::eq(&probe.plan, plan) && probe.expires > Instant::now() {
                return Some(PlanBinding {
                    trial_id: probe.trial_id,
                    generation: probe.generation,
                    shape: flow_probe_shape(&probe.plan),
                    temporary: true,
                });
            }
        }
        None
    }

    fn voice_address_binding(&self, packet: &[u8]) -> Option<(&Plan, [u8; 16], u64, bool)> {
        let view = PacketView::parse(packet)?;
        if view.family != 4 || view.protocol != 17 || view.fragment & 0x3fff != 0 {
            return None;
        }
        let r2o_udp = packet.get(view.l4_offset..view.total_len)?;
        if r2o_udp.len() < 8 {
            return None;
        }
        let r2o_source_port = u16::from_be_bytes([r2o_udp[0], r2o_udp[1]]);
        let r2o_destination_port = u16::from_be_bytes([r2o_udp[2], r2o_udp[3]]);
        let r2o_payload = packet.get(view.udp_payload_range(packet)?)?;
        if !r2k_core::stun::is_discord_voice_request(r2o_payload, r2o_destination_port)
            && !r2k_core::stun::is_binding_request(r2o_payload)
        {
            return None;
        }
        let r2o_source = Ipv4Addr::from(<[u8; 4]>::try_from(&view.src.bytes()[..4]).ok()?);
        let r2o_server = Ipv4Addr::from(<[u8; 4]>::try_from(&view.dst.bytes()[..4]).ok()?);
        let r2o_key = VoiceProbeKey {
            client: r2o_source,
            server: r2o_server,
            server_port: r2o_destination_port,
        };
        let r2o_now = Instant::now();
        // Точный voice-опыт из generic SET_ADDR_PROBE лежит в addr_probes:
        // C `find_voice_probe` находит и его, и wildcard.
        if let Some(key) = r2o_udp_addr_probe_flow_key(packet)
            && let Some(r2o_probe) = self.addr_probes.get(&key)
            && r2o_probe.expires > r2o_now
        {
            return Some((
                &r2o_probe.plan,
                r2o_probe.trial_id,
                r2o_probe.generation,
                true,
            ));
        }
        if let Some(r2o_probe) = self.voice_addr_probes.get(&r2o_key)
            && r2o_probe.expires > r2o_now
            && r2o_source_port != 0
        {
            return Some((
                &r2o_probe.plan,
                r2o_probe.trial_id,
                r2o_probe.generation,
                true,
            ));
        }
        let r2o_plan = self.voice_addr_plans.get(&r2o_server)?;
        Some((&r2o_plan.plan, [0; 16], r2o_plan.generation, false))
    }

    fn addr_probe_binding_at_hook(
        &self,
        packet: &[u8],
        hook: Option<u8>,
    ) -> Option<&AddrProbePlan> {
        let view = PacketView::parse(packet)?;
        if view.protocol != 17 || view.fragment & 0x3fff != 0 {
            return None;
        }
        let udp = packet.get(view.l4_offset..view.total_len)?;
        if udp.len() < 8
            || !crate::r2o_quic::r2o_quic_client_direction(
                u16::from_be_bytes([udp[0], udp[1]]),
                u16::from_be_bytes([udp[2], udp[3]]),
                hook,
            )
            || !r2k_core::quic::is_authenticated_initial(
                packet.get(view.udp_payload_range(packet)?)?,
            )
        {
            return None;
        }
        let key = r2o_udp_addr_probe_flow_key(packet)?;
        self.addr_probes
            .get(&key)
            .filter(|probe| probe.expires > Instant::now())
    }

    fn set_name(&mut self, body: &[u8]) -> (bool, u8) {
        let Some(name_len) = body.first().copied().map(usize::from) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let Some(fields_end) = 3_usize.checked_add(name_len) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if name_len == 0 || body.len() < fields_end {
            return (false, control::ACK_BAD_ARGS);
        }
        let shape = body[1 + name_len];
        let Some(host) = canonical_plan_name(&body[1..1 + name_len], shape) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let family = body[2 + name_len];
        if !matches!(family, 4 | 6) {
            return (false, control::ACK_BAD_ARGS);
        }
        let key = NamePlanKey {
            host,
            family,
            shape,
        };
        let plan = match Plan::parse_wire(&body[fields_end..]) {
            Ok(plan) => plan,
            Err(_) => return (false, control::ACK_BAD_PLAN),
        };
        let compatible = match shape {
            SHAPE_HTTP => plan.transport == 6 && plan.proto == PROTO_HTTP,
            SHAPE_MODERN | SHAPE_LEGACY | SHAPE_GRANDFATHER | SHAPE_ECH_TCP => {
                plan.transport == 6 && plan.proto == 1
            }
            _ if is_tcp_context_shape(shape) => plan.transport == 6 && plan.proto == 1,
            SHAPE_QUIC => valid_quic_plan(&plan),
            SHAPE_VOICE => plan.transport == 17 && plan.proto == PROTO_VOICE,
            _ => false,
        };
        if !compatible || !self.r2o_plan_valid(&plan) {
            return (false, control::ACK_BAD_PLAN);
        }
        // C `set_name_family` для grandfather не заводит отдельную форму:
        // обновляет уже измеренную запись имени (HTTP и grandfather не в счёт).
        if shape == SHAPE_GRANDFATHER
            && let Some(existing) = self.find_name_skip(&key.host, key.family, true)
            && existing.shape != SHAPE_GRANDFATHER
        {
            let clock = self.next_plan_clock();
            let generation = self.next_generation();
            if let Some(installed) = self.plans.get_mut(&existing) {
                installed.plan = plan;
                installed.last_used.set(clock);
                installed.generation = generation;
            }
            self.revision = self.revision.wrapping_add(1);
            return (true, control::ACK_OK);
        }
        if !self.plans.contains_key(&key) && !self.make_room_exact() {
            return (false, control::ACK_NO_ROOM);
        }
        if self.plans.try_reserve(1).is_err() {
            return (false, control::ACK_NO_ROOM);
        }
        let generation = self.next_generation();
        let last_used = Cell::new(self.next_plan_clock());
        self.plans.insert(
            key,
            InstalledPlan {
                plan,
                generation,
                last_used,
            },
        );
        (true, control::ACK_OK)
    }

    fn set_addr(&mut self, body: &[u8]) -> (bool, u8) {
        if body.len() <= 18 {
            return (false, control::ACK_BAD_ARGS);
        }
        let Some((address, shape)) = addr_plan_key(&body[..18]) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if !valid_addr_shape(shape) {
            return (false, control::ACK_BAD_ARGS);
        }
        let plan = match Plan::parse_wire(&body[18..]) {
            Ok(plan) => plan,
            Err(_) => return (false, control::ACK_BAD_PLAN),
        };
        if !addr_plan_matches_shape(shape, &plan) || !self.r2o_plan_valid(&plan) {
            return (false, control::ACK_BAD_PLAN);
        }
        let key = AddrPlanKey { address, shape };
        if !self.addr_plans.contains_key(&key) && !self.make_room_exact() {
            return (false, control::ACK_NO_ROOM);
        }
        if self.addr_plans.try_reserve(1).is_err() {
            return (false, control::ACK_NO_ROOM);
        }
        let generation = self.next_generation();
        let last_used = Cell::new(self.next_plan_clock());
        self.addr_plans.insert(
            key,
            InstalledPlan {
                plan,
                generation,
                last_used,
            },
        );
        (true, control::ACK_OK)
    }

    fn set_suffix(&mut self, body: &[u8]) -> (bool, u8) {
        let Some(name_len) = body.first().copied().map(usize::from) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let Some(fields_end) = 3_usize.checked_add(name_len) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if name_len == 0 || name_len > control::MAX_DNS_NAME_LEN || body.len() <= fields_end {
            return (false, control::ACK_BAD_ARGS);
        }
        let Some(suffix) = canonical_area_name(&body[1..1 + name_len]) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let shape = body[1 + name_len];
        let family = body[2 + name_len];
        if !matches!(family, 4 | 6)
            || !(matches!(
                shape,
                SHAPE_MODERN | SHAPE_LEGACY | SHAPE_QUIC | SHAPE_ECH_TCP
            ) || is_tcp_context_shape(shape))
        {
            return (false, control::ACK_BAD_ARGS);
        }
        let plan = match Plan::parse_wire(&body[fields_end..]) {
            Ok(plan) => plan,
            Err(_) => return (false, control::ACK_BAD_PLAN),
        };
        let compatible = match shape {
            SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP => plan.transport == 6 && plan.proto == 1,
            _ if is_tcp_context_shape(shape) => plan.transport == 6 && plan.proto == 1,
            SHAPE_QUIC => valid_quic_plan(&plan),
            _ => false,
        };
        if !compatible || !self.r2o_plan_valid(&plan) {
            return (false, control::ACK_BAD_PLAN);
        }
        let key = SuffixPlanKey {
            suffix,
            transport: plan.transport,
            family,
            shape,
        };
        if !self.suffix_plans.contains_key(&key) && self.suffix_plans.len() >= MAX_SUFFIX_PLANS {
            return (false, control::ACK_NO_ROOM);
        }
        if self.suffix_plans.try_reserve(1).is_err() {
            return (false, control::ACK_NO_ROOM);
        }
        let generation = self.next_generation();
        self.suffix_plans.insert(
            key,
            InstalledPlan {
                plan,
                generation,
                last_used: Cell::new(0),
            },
        );
        (true, control::ACK_OK)
    }

    fn set_domain_bypass(&mut self, body: &[u8]) -> (bool, u8) {
        let Some(name_len) = body.first().copied().map(usize::from) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if name_len == 0 || name_len > control::MAX_DNS_NAME_LEN || body.len() != name_len + 4 {
            return (false, control::ACK_BAD_ARGS);
        }
        let Some(name) = canonical_area_name(&body[1..1 + name_len]) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let transport = body[1 + name_len];
        let shape = body[2 + name_len];
        let family = body[3 + name_len];
        if !valid_domain_area_context(transport, shape, family) {
            return (false, control::ACK_BAD_ARGS);
        }
        let key = DomainBypassKey {
            name,
            transport,
            family,
            shape,
        };
        if !self.domain_bypasses.contains(&key) && self.domain_bypasses.len() >= MAX_DOMAIN_BYPASSES
        {
            return (false, control::ACK_NO_ROOM);
        }
        if self.domain_bypasses.try_reserve(1).is_err() {
            return (false, control::ACK_NO_ROOM);
        }
        self.domain_bypasses.insert(key);
        (true, control::ACK_OK)
    }

    fn delete_domain_area(&mut self, body: &[u8], suffix: bool) -> (bool, u8) {
        let Some(name_len) = body.first().copied().map(usize::from) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if name_len == 0 || name_len > control::MAX_DNS_NAME_LEN || body.len() != name_len + 4 {
            return (false, control::ACK_BAD_ARGS);
        }
        let Some(name) = canonical_area_name(&body[1..1 + name_len]) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let transport = body[1 + name_len];
        let shape = body[2 + name_len];
        let family = body[3 + name_len];
        if !valid_domain_area_context(transport, shape, family) {
            return (false, control::ACK_BAD_ARGS);
        }
        if suffix {
            self.suffix_plans.remove(&SuffixPlanKey {
                suffix: name,
                transport,
                family,
                shape,
            });
        } else {
            self.domain_bypasses.remove(&DomainBypassKey {
                name,
                transport,
                family,
                shape,
            });
        }
        (true, control::ACK_OK)
    }

    fn set_https(&mut self, body: &[u8]) -> (bool, u8) {
        self.set_https_at(body, Instant::now())
    }

    fn set_https_at(&mut self, body: &[u8], now: Instant) -> (bool, u8) {
        let Some(name_len) = body.first().copied().map(usize::from) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if name_len == 0 || body.len() != name_len + 5 {
            return (false, control::ACK_BAD_ARGS);
        }
        let Some(host) = canonical_https_name(&body[1..1 + name_len]) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let ttl = u32::from_be_bytes(
            body[1 + name_len..]
                .try_into()
                .expect("HTTPS TTL has a fixed width"),
        );
        // C-датапат не отвергает большой срок, а обрезает его до семи
        // суток (`ctlsrv.c:446`): иначе команда, которую C принял бы,
        // возвращала бы ACK_BAD_ARGS.
        let ttl = ttl.min(MAX_HTTPS_TTL_SECONDS);
        let existing = self
            .https_names
            .iter()
            .position(|slot| slot.matches(host.as_bytes()));
        if ttl == 0 {
            if let Some(index) = existing {
                self.https_names[index].clear();
            }
            return (true, control::ACK_OK);
        }
        let expires = now + Duration::from_secs(u64::from(ttl));
        if let Some(index) = existing {
            self.https_names[index].expires = Some(expires);
            return (true, control::ACK_OK);
        }
        // C `d2k_http80_set_https`: первый свободный слот, иначе слот с
        // минимальным `expires`; при равенстве — первый по порядку слотов.
        let pick = self
            .https_names
            .iter()
            .position(HttpsNameSlot::is_free)
            .or_else(|| {
                self.https_names
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, slot)| slot.expires)
                    .map(|(index, _)| index)
            });
        if let Some(index) = pick {
            self.https_names[index].assign(host.as_bytes(), expires);
        }
        (true, control::ACK_OK)
    }

    fn set_name_probe(&mut self, body: &[u8], trial_id: Option<[u8; 16]>) -> (bool, u8) {
        let Some(name_len) = body.first().copied().map(usize::from) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let Some(fields_end) = 5_usize.checked_add(name_len) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if name_len == 0
            || body.len() < fields_end
            || trial_id.is_none_or(|id| id.iter().all(|byte| *byte == 0))
        {
            return (false, control::ACK_BAD_ARGS);
        }
        let shape = body[1 + name_len];
        let Some(host) = canonical_plan_name(&body[1..1 + name_len], shape) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let family = body[2 + name_len];
        let source_port = u16::from_be_bytes([body[3 + name_len], body[4 + name_len]]);
        if !valid_tcp_probe_shape(shape) || !matches!(family, 4 | 6) || source_port == 0 {
            return (false, control::ACK_BAD_ARGS);
        }
        let key = NameProbeKey {
            name: NamePlanKey {
                host,
                family,
                shape,
            },
            source_port,
        };
        let plan = match Plan::parse_wire(&body[fields_end..]) {
            Ok(plan) => plan,
            Err(_) => return (false, control::ACK_BAD_PLAN),
        };
        let proto_matches = match shape {
            SHAPE_HTTP => plan.proto == PROTO_HTTP,
            SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP => plan.proto == 1,
            _ if is_tcp_context_shape(shape) => plan.proto == 1,
            _ => false,
        };
        if plan.transport != 6 || !proto_matches || !self.r2o_plan_valid(&plan) {
            return (false, control::ACK_BAD_PLAN);
        }
        // D2O `set_name_trial` снимает прежнюю пробную запись того же
        // (name, family, port) и того же транспорта (`probe_transport`).
        let transport = r2o_probe_transport(&plan, shape);
        self.probes.retain(|old, probe| {
            old.name.host != key.name.host
                || old.name.family != key.name.family
                || old.source_port != key.source_port
                || r2o_probe_transport(&probe.plan, old.name.shape) != transport
        });
        if !self.probes.contains_key(&key) && !self.make_room_exact() {
            return (false, control::ACK_NO_ROOM);
        }
        if self.probes.try_reserve(1).is_err() {
            return (false, control::ACK_NO_ROOM);
        }
        let generation = self.next_generation();
        let last_used = Cell::new(self.next_plan_clock());
        self.probes.insert(
            key,
            ProbePlan {
                plan,
                trial_id: trial_id.unwrap(),
                generation,
                last_used,
            },
        );
        (true, control::ACK_OK)
    }

    fn set_voice_addr(&mut self, body: &[u8]) -> (bool, u8) {
        if body.len() <= 4 {
            return (false, control::ACK_BAD_ARGS);
        }
        let r2o_server = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
        if r2o_server.is_unspecified() || r2o_server.is_multicast() {
            return (false, control::ACK_BAD_ARGS);
        }
        let r2o_plan = match Plan::parse_wire(&body[4..]) {
            Ok(r2o_plan) => r2o_plan,
            Err(_) => return (false, control::ACK_BAD_PLAN),
        };
        if r2o_plan.transport != 17
            || r2o_plan.proto != PROTO_VOICE
            || !self.r2o_plan_valid(&r2o_plan)
        {
            return (false, control::ACK_BAD_PLAN);
        }
        if !self.voice_addr_plans.contains_key(&r2o_server)
            && self.voice_addr_plans.len() >= MAX_VOICE_ADDR_PLANS
        {
            return (false, control::ACK_NO_ROOM);
        }
        if self.voice_addr_plans.try_reserve(1).is_err() {
            return (false, control::ACK_NO_ROOM);
        }
        let r2o_generation = self.next_generation();
        self.voice_addr_plans.insert(
            r2o_server,
            InstalledPlan {
                plan: r2o_plan,
                generation: r2o_generation,
                last_used: Cell::new(0),
            },
        );
        (true, control::ACK_OK)
    }

    fn set_voice_addr_probe(&mut self, body: &[u8], trial_id: Option<[u8; 16]>) -> (bool, u8) {
        if body.len() <= 14 || trial_id.is_none_or(|r2o_id| r2o_id.iter().all(|byte| *byte == 0)) {
            return (false, control::ACK_BAD_ARGS);
        }
        let r2o_key = VoiceProbeKey {
            client: Ipv4Addr::new(body[0], body[1], body[2], body[3]),
            server: Ipv4Addr::new(body[4], body[5], body[6], body[7]),
            server_port: u16::from_be_bytes([body[8], body[9]]),
        };
        let r2o_lease_ms = u32::from_be_bytes(
            body[10..14]
                .try_into()
                .expect("срок голосового опыта занимает четыре байта"),
        );
        if r2o_key.client.is_unspecified()
            || r2o_key.client.is_multicast()
            || r2o_key.server.is_unspecified()
            || r2o_key.server.is_multicast()
            || r2o_key.server_port == 0
            || r2o_lease_ms == 0
            || r2o_lease_ms > control::VOICE_ADDR_PROBE_LEASE_MAX_MS
        {
            return (false, control::ACK_BAD_ARGS);
        }
        let r2o_now = Instant::now();
        self.voice_addr_probes
            .retain(|_, r2o_probe| r2o_probe.expires > r2o_now);
        if let Some(r2o_existing) = self.voice_addr_probes.get(&r2o_key)
            && r2o_existing.trial_id != trial_id.unwrap()
        {
            return (false, control::ACK_BAD_ARGS);
        }
        let r2o_plan = match Plan::parse_wire(&body[14..]) {
            Ok(r2o_plan) => r2o_plan,
            Err(_) => return (false, control::ACK_BAD_PLAN),
        };
        if r2o_plan.transport != 17
            || r2o_plan.proto != PROTO_VOICE
            || !self.r2o_plan_valid(&r2o_plan)
        {
            return (false, control::ACK_BAD_PLAN);
        }
        if !self.voice_addr_probes.contains_key(&r2o_key)
            && self.flow_probe_count() >= MAX_FLOW_PROBES
        {
            return (false, control::ACK_NO_ROOM);
        }
        if self.voice_addr_probes.try_reserve(1).is_err() {
            return (false, control::ACK_NO_ROOM);
        }
        let r2o_generation = self.next_generation();
        self.voice_addr_probes.insert(
            r2o_key,
            VoiceProbePlan {
                plan: r2o_plan,
                trial_id: trial_id.unwrap(),
                generation: r2o_generation,
                expires: r2o_now + Duration::from_millis(u64::from(r2o_lease_ms)),
            },
        );
        (true, control::ACK_OK)
    }

    fn set_addr_probe(&mut self, body: &[u8]) -> (bool, u8) {
        let fixed = control::KEY_LEN + 20;
        if body.len() < fixed {
            return (false, control::ACK_BAD_ARGS);
        }
        let Some(key) = r2o_read_probe_flow(&body[..control::KEY_LEN]) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let trial_id: [u8; 16] = body[control::KEY_LEN..control::KEY_LEN + 16]
            .try_into()
            .expect("длина адресного опыта проверена выше");
        let lease_ms = u32::from_be_bytes(
            body[control::KEY_LEN + 16..fixed]
                .try_into()
                .expect("длина срока адресного опыта проверена выше"),
        );
        let source_port = u16::from_be_bytes([key[33], key[34]]);
        let voice_wildcard = source_port == 0;
        if voice_wildcard {
            // C `probe_flow_valid` допускает src_port=0 как голосовой
            // wildcard (`plans.c:857-874`); R2O хранит такие опыты в
            // `voice_addr_probes` без клиентского порта.
            if key[0] != 4
                || key[37] != 17
                || !key[5..17].iter().all(|byte| *byte == 0)
                || !key[21..33].iter().all(|byte| *byte == 0)
                || key[1..5].iter().all(|byte| *byte == 0)
                || key[17..21].iter().all(|byte| *byte == 0)
                || u16::from_be_bytes([key[35], key[36]]) == 0
            {
                return (false, control::ACK_BAD_ARGS);
            }
        } else if !control::valid_udp_addr_probe_flow(&key) {
            return (false, control::ACK_BAD_ARGS);
        }
        if trial_id.iter().all(|byte| *byte == 0)
            || lease_ms == 0
            || lease_ms > control::ADDR_PROBE_LEASE_MAX_MS
        {
            return (false, control::ACK_BAD_ARGS);
        }
        let plan = match Plan::parse_wire(&body[fixed..]) {
            Ok(plan) => plan,
            Err(_) => return (false, control::ACK_BAD_PLAN),
        };
        if voice_wildcard {
            // C принимает любой разобранный план: shape выводится из proto
            // (2→QUIC, 3→VOICE, иначе ANY), отказа по proto здесь нет.
            let voice_key = VoiceProbeKey {
                client: Ipv4Addr::new(key[1], key[2], key[3], key[4]),
                server: Ipv4Addr::new(key[17], key[18], key[19], key[20]),
                server_port: u16::from_be_bytes([key[35], key[36]]),
            };
            let now = Instant::now();
            self.voice_addr_probes
                .retain(|_, probe| probe.expires > now);
            if self
                .voice_addr_probes
                .get(&voice_key)
                .is_some_and(|existing| existing.trial_id != trial_id)
            {
                return (false, control::ACK_BAD_ARGS);
            }
            if !self.voice_addr_probes.contains_key(&voice_key)
                && self.flow_probe_count() >= MAX_FLOW_PROBES
            {
                return (false, control::ACK_NO_ROOM);
            }
            if self.voice_addr_probes.try_reserve(1).is_err() {
                return (false, control::ACK_NO_ROOM);
            }
            let generation = self.next_generation();
            self.voice_addr_probes.insert(
                voice_key,
                VoiceProbePlan {
                    plan,
                    trial_id,
                    generation,
                    expires: now + Duration::from_millis(u64::from(lease_ms)),
                },
            );
            return (true, control::ACK_OK);
        }
        // C не требует QUIC-плана: shape ANY допустим, прочие proto тоже.
        let now = Instant::now();
        self.addr_probes.retain(|_, probe| probe.expires > now);
        if self
            .addr_probes
            .get(&key)
            .is_some_and(|existing| existing.trial_id != trial_id)
        {
            return (false, control::ACK_BAD_ARGS);
        }
        if !self.addr_probes.contains_key(&key) && self.flow_probe_count() >= MAX_FLOW_PROBES {
            return (false, control::ACK_NO_ROOM);
        }
        if self.addr_probes.try_reserve(1).is_err() {
            return (false, control::ACK_NO_ROOM);
        }
        let generation = self.next_generation();
        self.addr_probes.insert(
            key,
            AddrProbePlan {
                plan,
                trial_id,
                generation,
                expires: now + Duration::from_millis(u64::from(lease_ms)),
            },
        );
        (true, control::ACK_OK)
    }

    fn delete_addr_probe(&mut self, body: &[u8], trial_id: Option<[u8; 16]>) -> (bool, u8) {
        if body.len() != control::KEY_LEN + 16 || trial_id.is_none() {
            return (false, control::ACK_BAD_ARGS);
        }
        let Some(key) = r2o_read_probe_flow(&body[..control::KEY_LEN]) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let body_trial_id: [u8; 16] = body[control::KEY_LEN..]
            .try_into()
            .expect("длина идентификатора адресного опыта проверена выше");
        if body_trial_id.iter().all(|byte| *byte == 0) || trial_id != Some(body_trial_id) {
            return (false, control::ACK_BAD_ARGS);
        }
        let source_port = u16::from_be_bytes([key[33], key[34]]);
        if source_port == 0 {
            // C generic DEL_ADDR_PROBE снимает и голосовой wildcard; при
            // несовпадении trial запись просто остаётся, ACK — OK.
            if key[0] != 4
                || key[37] != 17
                || !key[5..17].iter().all(|byte| *byte == 0)
                || !key[21..33].iter().all(|byte| *byte == 0)
                || key[1..5].iter().all(|byte| *byte == 0)
                || key[17..21].iter().all(|byte| *byte == 0)
                || u16::from_be_bytes([key[35], key[36]]) == 0
            {
                return (false, control::ACK_BAD_ARGS);
            }
            let voice_key = VoiceProbeKey {
                client: Ipv4Addr::new(key[1], key[2], key[3], key[4]),
                server: Ipv4Addr::new(key[17], key[18], key[19], key[20]),
                server_port: u16::from_be_bytes([key[35], key[36]]),
            };
            if self
                .voice_addr_probes
                .get(&voice_key)
                .is_some_and(|probe| probe.trial_id == body_trial_id)
            {
                self.voice_addr_probes.remove(&voice_key);
            }
            return (true, control::ACK_OK);
        }
        if !control::valid_udp_addr_probe_flow(&key) {
            return (false, control::ACK_BAD_ARGS);
        }
        if self
            .addr_probes
            .get(&key)
            .is_some_and(|probe| probe.trial_id == body_trial_id)
        {
            self.addr_probes.remove(&key);
        }
        (true, control::ACK_OK)
    }

    fn delete_voice_addr_probe(&mut self, body: &[u8], trial_id: Option<[u8; 16]>) -> (bool, u8) {
        if body.len() != 10 || trial_id.is_none() {
            return (false, control::ACK_BAD_ARGS);
        }
        let r2o_key = VoiceProbeKey {
            client: Ipv4Addr::new(body[0], body[1], body[2], body[3]),
            server: Ipv4Addr::new(body[4], body[5], body[6], body[7]),
            server_port: u16::from_be_bytes([body[8], body[9]]),
        };
        if let Some(r2o_probe) = self.voice_addr_probes.get(&r2o_key) {
            if r2o_probe.trial_id != trial_id.unwrap() {
                return (false, control::ACK_BAD_ARGS);
            }
            self.voice_addr_probes.remove(&r2o_key);
        }
        (true, control::ACK_OK)
    }

    fn delete_name_probe(&mut self, body: &[u8]) -> (bool, u8) {
        let Some(name_len) = body.first().copied().map(usize::from) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if name_len == 0 || body.len() != name_len + 5 {
            return (false, control::ACK_BAD_ARGS);
        }
        let shape = body[1 + name_len];
        let Some(host) = canonical_plan_name(&body[1..1 + name_len], shape) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let family = body[2 + name_len];
        let source_port = u16::from_be_bytes([body[3 + name_len], body[4 + name_len]]);
        // C `d2k_plantab_del_name_probe_family` форму не проверяет: чужая
        // форма просто не совпадает и ACK остаётся OK (`plans.c:808-828`).
        if !matches!(family, 4 | 6) || source_port == 0 {
            return (false, control::ACK_BAD_ARGS);
        }
        self.probes.remove(&NameProbeKey {
            name: NamePlanKey {
                host,
                family,
                shape,
            },
            source_port,
        });
        (true, control::ACK_OK)
    }

    fn delete_name(&mut self, body: &[u8]) -> (bool, u8) {
        let Some(name_len) = body.first().copied().map(usize::from) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if name_len == 0 || body.len() != name_len + 4 {
            return (false, control::ACK_BAD_ARGS);
        }
        let transport = body[1 + name_len];
        let shape = body[2 + name_len];
        let Some(host) = canonical_plan_name(&body[1..1 + name_len], shape) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let family = body[3 + name_len];
        if !matches!(family, 4 | 6)
            || !(transport == 6 && valid_tcp_shape(shape)
                || transport == 17 && matches!(shape, SHAPE_VOICE | SHAPE_QUIC))
        {
            return (false, control::ACK_BAD_ARGS);
        }
        self.plans.remove(&NamePlanKey {
            host,
            family,
            shape,
        });
        (true, control::ACK_OK)
    }

    fn delete_name_bound(&mut self, body: &[u8]) -> (bool, u8) {
        let Some(name_len) = body.first().copied().map(usize::from) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let Some(context_start) = 2_usize.checked_add(name_len) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if name_len == 0
            || body.len() != context_start + control::BINDING_CONTEXT_LEN
            || !body
                .get(1 + name_len)
                .is_some_and(|transport| matches!(transport, 6 | 17))
        {
            return (false, control::ACK_BAD_ARGS);
        }
        let Some(binding) = read_binding_context(&body[context_start..]) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let Some(host) = canonical_plan_name(&body[1..1 + name_len], binding.shape) else {
            return (true, control::ACK_OK);
        };
        if !binding.is_known()
            || binding.kind != 1
            || binding.temporary
            || !matches!(binding.family, 4 | 6)
        {
            return (true, control::ACK_OK);
        }
        let transport = body[1 + name_len];
        let key = NamePlanKey {
            host,
            family: binding.family,
            shape: binding.shape,
        };
        if self.epoch == binding.epoch
            && self.plans.get(&key).is_some_and(|installed| {
                let current = BindingContext {
                    generation: installed.generation,
                    kind: 1,
                    family: binding.family,
                    shape: binding.shape,
                    temporary: false,
                    epoch: self.epoch,
                };
                control::r2o_binding_equal(&current, &binding)
                    && installed.plan.transport == transport
            })
        {
            self.plans.remove(&key);
            self.revision = self.revision.wrapping_add(1);
        }
        (true, control::ACK_OK)
    }

    fn delete_addr(&mut self, body: &[u8]) -> (bool, u8) {
        if body.len() != 18 {
            return (false, control::ACK_BAD_ARGS);
        }
        let Some((address, shape)) = addr_plan_key(body) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if !valid_addr_shape(shape) {
            return (false, control::ACK_BAD_ARGS);
        }
        self.addr_plans.remove(&AddrPlanKey { address, shape });
        (true, control::ACK_OK)
    }

    fn is_ech_shape(shape: u8) -> bool {
        matches!(shape, SHAPE_ECH_TCP | SHAPE_ECH_NO_TS | SHAPE_ECH_TS)
    }

    /// C `d2k_plantab_has_ech_target`: есть ли ECH-привязка имени/адреса,
    /// пробы или суффикса с учётом BYPASS.
    pub fn has_ech_target(
        &self,
        name: Option<&[u8]>,
        addr: Option<Address>,
        family: u8,
        sport_be: u16,
    ) -> bool {
        if !matches!(family, 4 | 6) {
            return false;
        }
        let host = name.and_then(canonical_name);
        for key in self.plans.keys() {
            if key.family == family
                && Self::is_ech_shape(key.shape)
                && host.as_ref().is_some_and(|host| key.host == *host)
            {
                return true;
            }
        }
        for key in self.addr_plans.keys() {
            if key.address.family() != family || !Self::is_ech_shape(key.shape) {
                continue;
            }
            if addr.is_some_and(|addr| key.address == addr)
                && host.as_ref().is_none_or(|host| {
                    !self.name_is_bypassed(host.as_bytes(), family, key.shape, 6)
                })
            {
                return true;
            }
        }
        if sport_be != 0 {
            for key in self.probes.keys() {
                if key.name.family == family
                    && key.source_port == sport_be
                    && Self::is_ech_shape(key.name.shape)
                    && host.as_ref().is_some_and(|host| key.name.host == *host)
                {
                    return true;
                }
            }
        }
        if let Some(host) = host {
            for shape in [SHAPE_ECH_TCP, SHAPE_ECH_NO_TS, SHAPE_ECH_TS] {
                if !self.name_is_bypassed(host.as_bytes(), family, shape, 6)
                    && self
                        .find_in_domain(host.as_bytes(), family, shape, 6)
                        .is_some()
                {
                    return true;
                }
            }
        }
        false
    }

    /// C `find_name_skip`: первая постоянная запись имени любой формы;
    /// `skip_http` исключает HTTP-запись.
    fn find_name_skip(&self, host: &str, family: u8, skip_http: bool) -> Option<NamePlanKey> {
        self.plans
            .keys()
            .find(|key| {
                key.host == host && key.family == family && !(skip_http && key.shape == SHAPE_HTTP)
            })
            .cloned()
    }

    /// C `scan_name.h.any`: первая не-HTTP запись имени любой формы.
    fn find_any_name(&self, bytes: &[u8], family: u8) -> Option<&Plan> {
        let host = canonical_name(bytes)?;
        self.plans
            .iter()
            .find(|(key, _)| key.host == host && key.family == family && key.shape != SHAPE_HTTP)
            .map(|(_, entry)| &entry.plan)
    }

    /// C `scan_addr` + `shape_fits`: адресная запись, совместимая с
    /// наблюдённой формой (grandfather/ECH-перенос/точное равенство).
    fn find_addr_shape_fits(&self, address: Address, seen_shape: u8) -> Option<&Plan> {
        let entry = self
            .addr_plans
            .iter()
            .find(|(key, _)| key.address == address && r2o_shape_fits(key.shape, seen_shape))
            .map(|(_, entry)| entry)?;
        Self::touch(entry, self.next_plan_clock());
        Some(&entry.plan)
    }

    /// C `scan_name` + `shape_fits`: любая именная запись, совместимая с
    /// наблюдённой формой (grandfather/ECH-перенос/точное равенство).
    fn find_shape_fits(&self, bytes: &[u8], family: u8, seen_shape: u8) -> Option<&Plan> {
        let host = canonical_name(bytes)?;
        let entry = self
            .plans
            .iter()
            .find(|(key, _)| {
                key.host == host
                    && key.family == family
                    && key.shape != SHAPE_HTTP
                    && r2o_shape_fits(key.shape, seen_shape)
            })
            .map(|(_, entry)| entry)?;
        Self::touch(entry, self.next_plan_clock());
        Some(&entry.plan)
    }

    fn find_exact(&self, bytes: &[u8], family: u8, shape: u8) -> Option<&Plan> {
        let host = canonical_plan_name(bytes, shape)?;
        let entry = self.plans.get(&NamePlanKey {
            host,
            family,
            shape,
        })?;
        Self::touch(entry, self.next_plan_clock());
        Some(&entry.plan)
    }

    /// C `d2k_plantab_find`: IPv4, без порта.
    pub fn find(
        &self,
        name: Option<&[u8]>,
        address: Option<Address>,
        seen_shape: u8,
    ) -> Option<&Plan> {
        self.find_sport(name, address, seen_shape, 0)
    }

    /// C `d2k_plantab_find_sport`: IPv4, с портом.
    pub fn find_sport(
        &self,
        name: Option<&[u8]>,
        address: Option<Address>,
        seen_shape: u8,
        source_port: u16,
    ) -> Option<&Plan> {
        self.find_family(name, address, seen_shape, source_port, 4)
    }

    /// C `d2k_plantab_find_family`: IPv6 ищет без адреса.
    pub fn find_family(
        &self,
        name: Option<&[u8]>,
        address: Option<Address>,
        seen_shape: u8,
        source_port: u16,
        family: u8,
    ) -> Option<&Plan> {
        if !matches!(family, 4 | 6) {
            return None;
        }
        let address = if family == 4 { address } else { None };
        self.find_target(name, address, family, seen_shape, source_port)
    }

    /// C `d2k_plantab_find_target`: полный поиск без разбора пакета.
    pub fn find_target(
        &self,
        name: Option<&[u8]>,
        address: Option<Address>,
        family: u8,
        seen_shape: u8,
        source_port: u16,
    ) -> Option<&Plan> {
        if !matches!(family, 4 | 6) {
            return None;
        }
        let host = name.and_then(canonical_name);
        let no_name = name.is_none_or(|value| value.is_empty());

        // C: пустое имя + порт — уникальная портовая проба подходящей формы.
        if no_name && source_port != 0 {
            let mut found: Option<&ProbePlan> = None;
            for (key, probe) in &self.probes {
                if key.name.family == family
                    && key.source_port == source_port
                    && r2o_shape_fits(key.name.shape, seen_shape)
                {
                    if found.is_some() {
                        return None;
                    }
                    found = Some(probe);
                }
            }
            if let Some(probe) = found {
                Self::touch_probe(probe, self.next_plan_clock());
                return Some(&probe.plan);
            }
        }

        if let Some(host) = host.as_deref() {
            if source_port != 0 {
                let mut probe: Option<(&NameProbeKey, &ProbePlan)> = None;
                // Точная форма, затем ECH→MODERN, ANY→любая, grandfather.
                for (key, value) in &self.probes {
                    if key.name.host == host
                        && key.name.family == family
                        && key.source_port == source_port
                        && key.name.shape == seen_shape
                    {
                        probe = Some((key, value));
                        break;
                    }
                }
                if probe.is_none() && seen_shape == SHAPE_ECH_TCP {
                    for (key, value) in &self.probes {
                        if key.name.host == host
                            && key.name.family == family
                            && key.source_port == source_port
                            && key.name.shape == SHAPE_MODERN
                        {
                            probe = Some((key, value));
                            break;
                        }
                    }
                }
                if probe.is_none() && seen_shape == 0 {
                    for (key, value) in &self.probes {
                        if key.name.host == host
                            && key.name.family == family
                            && key.source_port == source_port
                        {
                            probe = Some((key, value));
                            break;
                        }
                    }
                }
                if probe.is_none() {
                    for (key, value) in &self.probes {
                        if key.name.host == host
                            && key.name.family == family
                            && key.source_port == source_port
                            && key.name.shape == SHAPE_GRANDFATHER
                        {
                            probe = Some((key, value));
                            break;
                        }
                    }
                }
                if let Some((key, value)) = probe {
                    Self::touch_probe(value, self.next_plan_clock());
                    if (seen_shape == 0 && key.source_port == source_port)
                        || r2o_shape_fits(key.name.shape, seen_shape)
                    {
                        return Some(&value.plan);
                    }
                    if r2o_shape_is_udp(seen_shape) && !r2o_shape_is_udp(key.name.shape) {
                        // C: goto check_addr — имя другого транспорта уступает адресу.
                    } else {
                        self.increment_shape_misses();
                        return None;
                    }
                }
            }

            let transport = if r2o_shape_is_udp(seen_shape) { 17 } else { 6 };
            let plan = self
                .find_exact(host.as_bytes(), family, seen_shape)
                .or_else(|| {
                    (seen_shape == SHAPE_ECH_TCP)
                        .then(|| self.find_exact(host.as_bytes(), family, SHAPE_MODERN))
                        .flatten()
                })
                .or_else(|| self.find_exact(host.as_bytes(), family, SHAPE_GRANDFATHER))
                .or_else(|| self.find_shape_fits(host.as_bytes(), family, seen_shape))
                .or_else(|| self.find_in_domain(host.as_bytes(), family, seen_shape, transport));
            if let Some(plan) = plan {
                return Some(plan);
            }
            if !r2o_shape_is_udp(seen_shape) {
                if self.name_has_any_binding(host.as_bytes(), family) {
                    self.increment_shape_misses();
                }
                return None;
            }
            if self.name_has_udp_binding(host.as_bytes(), family) {
                self.increment_shape_misses();
                return None;
            }
        }

        let Some(address) = address else {
            return None;
        };
        let plan = self
            .find_addr(address, seen_shape)
            .or_else(|| self.find_addr_shape_fits(address, seen_shape));
        if plan.is_none() && self.addr_plans.keys().any(|key| key.address == address) {
            self.increment_shape_misses();
        }
        plan
    }

    fn increment_shape_misses(&self) {
        self.shape_misses
            .set(self.shape_misses.get().saturating_add(1));
    }

    /// C `d2k_plantab_del_name_family`: снять все постоянные записи имени
    /// в семействе, не трогая пробы (`only_sport != 0`).
    pub fn delete_name_family_all(&mut self, host: &str, family: u8) -> bool {
        let Some(host) = canonical_name(host.as_bytes()) else {
            return false;
        };
        let before = self.plans.len();
        self.plans
            .retain(|key, _| !(key.host == host && key.family == family));
        let removed = before - self.plans.len();
        if removed != 0 {
            self.revision = self.revision.wrapping_add(removed as u64);
        }
        removed != 0
    }

    /// C `d2k_plantab_del_name` — вариант `delete_name_family_all` для IPv4.
    pub fn delete_name_all(&mut self, host: &str) -> bool {
        self.delete_name_family_all(host, 4)
    }

    /// C `d2k_plantab_del_addr_family`: снять адрес целиком, все формы.
    pub fn delete_addr_family_all(&mut self, address: Address) -> bool {
        let before = self.addr_plans.len();
        self.addr_plans.retain(|key, _| key.address != address);
        let removed = before - self.addr_plans.len();
        if removed != 0 {
            self.revision = self.revision.wrapping_add(removed as u64);
        }
        removed != 0
    }

    /// C `d2k_plantab_del_addr` — снятие всех форм адреса.
    pub fn delete_addr_all(&mut self, address: Address) -> bool {
        self.delete_addr_family_all(address)
    }

    /// C `find_addr(..., any_shape=1, 0)`: любая форма адреса.
    pub fn find_addr_any(&self, address: Address) -> Option<&Plan> {
        self.addr_plans
            .iter()
            .find(|(key, _)| key.address == address)
            .map(|(_, entry)| &entry.plan)
    }

    /// C `d2k_plantab_set_addr`: IPv4-адрес как grandfather-запись.
    pub fn set_addr_legacy(&mut self, address: Address, plan: Plan) -> bool {
        self.set_addr_family_legacy(address, 4, plan)
    }

    /// C `d2k_plantab_set_addr_family`: адрес без формы → grandfather.
    pub fn set_addr_family_legacy(&mut self, address: Address, family: u8, plan: Plan) -> bool {
        self.set_addr_shaped_legacy(address, family, SHAPE_GRANDFATHER, plan)
    }

    /// C `d2k_plantab_set_addr_shaped`: адрес ровно (address, family, shape);
    /// C отвергает только ANY/HTTP и HTTP-протокол плана.
    pub fn set_addr_shaped_legacy(
        &mut self,
        address: Address,
        family: u8,
        shape: u8,
        plan: Plan,
    ) -> bool {
        if !matches!(family, 4 | 6)
            || address.family() != family
            || shape == 0
            || shape == SHAPE_HTTP
            || plan.proto == PROTO_HTTP
            || !self.r2o_plan_valid(&plan)
        {
            return false;
        }
        let key = AddrPlanKey { address, shape };
        if !self.addr_plans.contains_key(&key) && !self.make_room_exact() {
            return false;
        }
        if self.addr_plans.try_reserve(1).is_err() {
            return false;
        }
        let generation = self.next_generation();
        let last_used = Cell::new(self.next_plan_clock());
        self.addr_plans.insert(
            key,
            InstalledPlan {
                plan,
                generation,
                last_used,
            },
        );
        self.revision = self.revision.wrapping_add(1);
        true
    }

    fn find_addr(&self, address: Address, shape: u8) -> Option<&Plan> {
        let entry = self
            .addr_plans
            .get(&AddrPlanKey { address, shape })
            .or_else(|| {
                // C `modern_shape_for_ech`: ECH_TCP→MODERN,
                // ECH_NO_TS→MODERN_NO_TS, ECH_TS→MODERN_TS.
                let fallback = match shape {
                    SHAPE_ECH_TCP => SHAPE_MODERN,
                    SHAPE_ECH_NO_TS => SHAPE_MODERN_NO_TS,
                    SHAPE_ECH_TS => SHAPE_MODERN_TS,
                    _ => return None,
                };
                self.addr_plans.get(&AddrPlanKey {
                    address,
                    shape: fallback,
                })
            })?;
        Self::touch(entry, self.next_plan_clock());
        Some(&entry.plan)
    }

    fn find_addr_fallback(
        &self,
        address: Address,
        name: Option<&[u8]>,
        family: u8,
        shape: u8,
        transport: u8,
    ) -> Option<&Plan> {
        if let Some(name) = name {
            if self.name_has_transport_binding(name, family, shape, transport)
                || self.name_is_bypassed(name, family, shape, transport)
                || shape == SHAPE_ECH_TCP
                    && self.name_is_bypassed(name, family, SHAPE_MODERN, transport)
            {
                return None;
            }
            // C `find_target`: имя названо, и его план не подошёл по форме.
            // Адресный fallback разрешён только при UDP-наблюдении; для TCP
            // запись соседа по CDN брать нельзя (`plans.c:1190-1200`).
            if !r2o_shape_is_udp(shape) && self.name_has_any_binding(name, family) {
                return None;
            }
        }
        self.find_addr(address, shape)
    }

    /// Есть ли у имени любая запись/суффикс в семействе (не только тот же
    /// транспорт). Нужно для одностороннего правила addr-fallback.
    fn name_has_any_binding(&self, bytes: &[u8], family: u8) -> bool {
        let Some(host) = canonical_name(bytes) else {
            return false;
        };
        self.plans
            .keys()
            .any(|key| key.host == host && key.family == family && key.shape != SHAPE_HTTP)
            || self
                .suffix_plans
                .keys()
                .any(|key| key.family == family && domain_suffix_member(&host, &key.suffix))
    }

    fn name_has_transport_binding(
        &self,
        bytes: &[u8],
        family: u8,
        shape: u8,
        transport: u8,
    ) -> bool {
        let Some(host) = canonical_plan_name(bytes, shape) else {
            return false;
        };
        self.plans.iter().any(|(key, entry)| {
            key.host == host && key.family == family && entry.plan.transport == transport
        })
    }

    fn name_is_bypassed(&self, bytes: &[u8], family: u8, shape: u8, transport: u8) -> bool {
        let Some(name) = canonical_name(bytes) else {
            return false;
        };
        self.domain_bypasses.contains(&DomainBypassKey {
            name,
            transport,
            family,
            shape,
        })
    }

    fn find_in_domain(&self, bytes: &[u8], family: u8, shape: u8, transport: u8) -> Option<&Plan> {
        let host = canonical_name(bytes)?;
        let bypass = DomainBypassKey {
            name: host.clone(),
            transport,
            family,
            shape,
        };
        if self.domain_bypasses.contains(&bypass) {
            return None;
        }
        self.suffix_plans
            .iter()
            .filter(|(key, _)| {
                key.transport == transport
                    && key.family == family
                    && key.shape == shape
                    && domain_suffix_member(&host, &key.suffix)
            })
            .max_by_key(|(key, _)| key.suffix.len())
            .map(|(_, entry)| &entry.plan)
    }

    fn next_generation(&self) -> u64 {
        // C `bind_context`: `generation = ++next_binding`, с пропуском нуля
        // при переполнении (`plans.c:94-102`).
        let next = self.binding_generation.get().wrapping_add(1);
        let next = if next == 0 { 1 } else { next };
        self.binding_generation.set(next);
        next
    }
}

/// C `shape_transport` (`plans.c:169-175`): QUIC → 17, TLS/ECH/контекст → 6,
/// остальные формы → 0.
/// C `read_probe_flow` (`ctlsrv.c:169-187`): family 4/6, канонический IPv4
/// (хвост нулевой), порты и transport как есть. Валидация транспорта/портов —
/// уже на уровне команды.
fn r2o_read_probe_flow(bytes: &[u8]) -> Option<[u8; control::KEY_LEN]> {
    if bytes.len() < control::KEY_LEN {
        return None;
    }
    let family = bytes[0];
    if !matches!(family, 4 | 6) {
        return None;
    }
    if family == 4
        && (bytes[5..17].iter().any(|byte| *byte != 0)
            || bytes[21..33].iter().any(|byte| *byte != 0))
    {
        return None;
    }
    let mut key = [0; control::KEY_LEN];
    key.copy_from_slice(&bytes[..control::KEY_LEN]);
    Some(key)
}

/// C `probe_flow_valid` (`plans.c:860-874`): UDP-транспорт, ненулевой
/// dst_port, family 0/4/6, ненулевые адреса; src_port=0 — голосовой wildcard.
fn r2o_probe_flow_valid(flow: &[u8; control::KEY_LEN]) -> bool {
    if flow[37] != 17 || u16::from_be_bytes([flow[35], flow[36]]) == 0 {
        return false;
    }
    let family = flow[0];
    if !matches!(family, 0 | 4 | 6) {
        return false;
    }
    let width = if family == 6 { 16 } else { 4 };
    flow[1..1 + width].iter().any(|byte| *byte != 0)
        && flow[17..17 + width].iter().any(|byte| *byte != 0)
}

/// C `probe_flow_equal`: равенство family/transport/портов/адресов.
fn r2o_probe_flow_equal(a: &[u8; control::KEY_LEN], b: &[u8; control::KEY_LEN]) -> bool {
    a == b
}

/// C `shape_is_udp`: QUIC/VOICE — UDP-формы.
fn r2o_shape_is_udp(shape: u8) -> bool {
    matches!(shape, SHAPE_QUIC | SHAPE_VOICE)
}

/// C `shape_fits` (`plans.c:1044-1052`): grandfather подходит любой форме;
/// MODERN/NO_TS/TS совместимы с соответствующей ECH-формой; иначе точное
/// равенство ненулевых форм.
/// C `name_same` (`session.c:369-382`): равная длина и ASCII A-Z→a-z,
/// без нормализации точки и без прочих преобразований.
pub fn r2o_name_same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(left, right)| left.to_ascii_lowercase() == right.to_ascii_lowercase())
}

fn r2o_shape_fits(entry_shape: u8, seen_shape: u8) -> bool {
    if entry_shape == SHAPE_GRANDFATHER {
        return true;
    }
    if entry_shape == SHAPE_MODERN && seen_shape == SHAPE_ECH_TCP {
        return true;
    }
    if entry_shape == SHAPE_MODERN_NO_TS && seen_shape == SHAPE_ECH_NO_TS {
        return true;
    }
    if entry_shape == SHAPE_MODERN_TS && seen_shape == SHAPE_ECH_TS {
        return true;
    }
    entry_shape != 0 && entry_shape == seen_shape
}

fn r2o_shape_transport(shape: u8) -> u8 {
    match shape {
        SHAPE_QUIC => 17,
        SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP => 6,
        _ if is_tcp_context_shape(shape) => 6,
        _ => 0,
    }
}

/// C `probe_transport` (`plans.c:584-588`): объявленный транспорт плана,
/// иначе QUIC/VOICE → 17, всё остальное → 6.
fn r2o_probe_transport(plan: &Plan, shape: u8) -> u8 {
    if plan.transport != 0 {
        plan.transport
    } else if matches!(shape, SHAPE_QUIC | SHAPE_VOICE) {
        17
    } else {
        6
    }
}

fn valid_domain_area_context(transport: u8, shape: u8, family: u8) -> bool {
    matches!(family, 4 | 6) && transport != 0 && transport == r2o_shape_transport(shape)
}

fn domain_suffix_member(name: &str, suffix: &str) -> bool {
    name == suffix
        || name
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn addr_plan_key(body: &[u8]) -> Option<(Address, u8)> {
    if body.len() != 18 {
        return None;
    }
    let address = match body[0] {
        4 if body[5..17].iter().all(|byte| *byte == 0) => Address::new(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(&body[1..5]).ok()?,
        ))),
        6 => Address::new(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&body[1..17]).ok()?,
        ))),
        _ => return None,
    };
    Some((address, body[17]))
}

fn valid_addr_shape(shape: u8) -> bool {
    matches!(
        shape,
        SHAPE_MODERN | SHAPE_LEGACY | SHAPE_QUIC | SHAPE_VOICE | SHAPE_ECH_TCP
    )
}

fn addr_plan_matches_shape(shape: u8, plan: &Plan) -> bool {
    match shape {
        SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP => plan.transport == 6 && plan.proto == 1,
        SHAPE_QUIC => valid_quic_plan(plan),
        SHAPE_VOICE => plan.transport == 17 && plan.proto == PROTO_VOICE,
        _ => false,
    }
}

fn r2o_udp_flow_wire_key(packet: &[u8]) -> Option<[u8; r2k_core::control::KEY_LEN]> {
    let view = PacketView::parse(packet)?;
    if view.protocol != 17 || view.fragment & 0x3fff != 0 {
        return None;
    }
    let r2o_udp = packet.get(view.l4_offset..view.total_len)?;
    if r2o_udp.len() < 8 {
        return None;
    }
    let r2o_source_port = u16::from_be_bytes([r2o_udp[0], r2o_udp[1]]);
    let r2o_destination_port = u16::from_be_bytes([r2o_udp[2], r2o_udp[3]]);
    if r2o_source_port == 0 || r2o_destination_port == 0 {
        return None;
    }
    let r2o_source_bytes = view.src.bytes();
    let r2o_destination_bytes = view.dst.bytes();
    let r2o_ip_length = if view.family == 4 { 4 } else { 16 };
    let (r2o_low, r2o_high) = if r2o_source_bytes[..r2o_ip_length]
        .cmp(&r2o_destination_bytes[..r2o_ip_length])
        .then_with(|| r2o_source_port.cmp(&r2o_destination_port))
        .is_le()
    {
        (
            (r2o_source_bytes, r2o_source_port),
            (r2o_destination_bytes, r2o_destination_port),
        )
    } else {
        (
            (r2o_destination_bytes, r2o_destination_port),
            (r2o_source_bytes, r2o_source_port),
        )
    };
    let mut r2o_key = [0; r2k_core::control::KEY_LEN];
    r2o_key[0] = view.family;
    r2o_key[1..17].copy_from_slice(&r2o_low.0);
    r2o_key[17..33].copy_from_slice(&r2o_high.0);
    r2o_key[33..35].copy_from_slice(&r2o_low.1.to_be_bytes());
    r2o_key[35..37].copy_from_slice(&r2o_high.1.to_be_bytes());
    r2o_key[37] = 17;
    Some(r2o_key)
}

pub fn flow_journal_key_for_packet(packet: &[u8]) -> Option<[u8; r2k_core::control::KEY_LEN]> {
    let view = PacketView::parse(packet)?;
    match view.protocol {
        6 => Some(crate::capture::TcpFlowKey::from_packet(packet)?.wire_key()),
        17 => r2o_udp_flow_wire_key(packet),
        _ => None,
    }
}

fn r2o_udp_addr_probe_flow_key(packet: &[u8]) -> Option<[u8; r2k_core::control::KEY_LEN]> {
    let view = PacketView::parse(packet)?;
    if view.protocol != 17 || view.fragment & 0x3fff != 0 {
        return None;
    }
    let udp = packet.get(view.l4_offset..view.total_len)?;
    if udp.len() < 8 {
        return None;
    }
    let source_port = u16::from_be_bytes([udp[0], udp[1]]);
    let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
    if source_port == 0 || destination_port == 0 {
        return None;
    }
    let mut key = [0; r2k_core::control::KEY_LEN];
    key[0] = view.family;
    let ip_length = if view.family == 4 { 4 } else { 16 };
    key[1..1 + ip_length].copy_from_slice(&view.src.bytes()[..ip_length]);
    key[17..17 + ip_length].copy_from_slice(&view.dst.bytes()[..ip_length]);
    key[33..35].copy_from_slice(&source_port.to_be_bytes());
    key[35..37].copy_from_slice(&destination_port.to_be_bytes());
    key[37] = 17;
    r2k_core::control::valid_udp_addr_probe_flow(&key).then_some(key)
}

fn canonical_plan_name(bytes: &[u8], shape: u8) -> Option<String> {
    if shape == SHAPE_VOICE && bytes == b"@discord-voice" {
        Some("@discord-voice".to_owned())
    } else {
        canonical_name(bytes)
    }
}

fn valid_tcp_shape(shape: u8) -> bool {
    is_tcp_plan_shape(shape) || shape == SHAPE_GRANDFATHER
}

/// C `d2k_ctl_binding_read` (`datapath/include/d2k_ctl.h:91-99`): ровно 28
/// байт; kind<=BIND_FLOW(4), family 0/4/6, shape<=TCP_SHAPE_MAX(13),
/// temporary 0/1. Известность привязки (generation/epoch) здесь не
/// проверяется — это делает удаление записи, а не чтение контекста.
fn read_binding_context(context: &[u8]) -> Option<BindingContext> {
    if context.len() != control::BINDING_CONTEXT_LEN {
        return None;
    }
    let binding = BindingContext {
        generation: u64::from_be_bytes(context[..8].try_into().ok()?),
        kind: context[8],
        family: context[9],
        shape: context[10],
        temporary: match context[11] {
            0 => false,
            1 => true,
            _ => return None,
        },
        epoch: context[12..28].try_into().ok()?,
    };
    if binding.kind > 4
        || !matches!(binding.family, 0 | 4 | 6)
        || binding.shape > control::SHAPE_ECH_TS
    {
        return None;
    }
    Some(binding)
}

fn valid_tcp_probe_shape(shape: u8) -> bool {
    is_tcp_plan_shape(shape)
}

fn valid_quic_plan(plan: &Plan) -> bool {
    plan.r2k_is_quic_address_plan() && validate_runtime_plan(plan).is_ok()
}

/// C `d2k_plantab_set_addr_probe`: shape из proto (2→QUIC, 3→VOICE, иначе ANY).
fn flow_probe_shape(plan: &Plan) -> u8 {
    match plan.proto {
        2 => SHAPE_QUIC,
        3 => SHAPE_VOICE,
        _ => 0,
    }
}

struct PendingWrite {
    bytes: Vec<u8>,
    offset: usize,
}

pub struct ControlServer {
    listener: UnixListener,
    path: PathBuf,
    socket_dev: u64,
    socket_ino: u64,
    send_maxlen: u32,
    wire_profile: control::WireProfile,
    release_id: String,
    peer: Option<UnixStream>,
    input: Vec<u8>,
    output: VecDeque<PendingWrite>,
    output_bytes: usize,
    dropped_events: u64,
    /// C `d2k_ctl.sent`: кадры, целиком поставленные в кольцо.
    sent_events: u64,
    /// C `disconnect_hook`: вызывается при разрыве живого пира.
    disconnect_hook: Option<Box<dyn FnMut() + Send>>,
    // D2O хранит снимки нескольких целей. Один последний снимок на семейство
    // терялся на занятом роутере: ARM_SHAPE приходил уже после того, как его
    // вытеснило приветствие другого клиента, и Discovery шёл без ClientHello.
    last_client_shapes: VecDeque<CachedClientShape>,
    /// C `shape_armed[shape_slot(transport, family)]`: 4 слота
    /// TCP/UDP × IPv4/IPv6.
    armed_shapes: [Option<Vec<u8>>; 4],
    /// QUIC-снимки C `last_hello[shape_slot(17, family)]`: QSN-пачка
    /// совместима с `d2k_qsnap_pack`, а событие для v22 — `EV_SHAPE`.
    last_quic_shapes: VecDeque<CachedQuicShape>,
    /// C `shape_opts[shape_slot(6,family)]`: TCP-опции клиента для формы TCP.
    shape_tcp_options: [Option<Vec<u8>>; 4],
}

const CLIENT_SHAPE_CACHE_MAX: usize = 512;

#[derive(Clone)]
struct CachedClientShape {
    host: Vec<u8>,
    family: u8,
    event_body: Vec<u8>,
}

#[derive(Clone)]
struct CachedQuicShape {
    host: Vec<u8>,
    family: u8,
    /// R2O-событие `EVENT_HELLO` с QSN-снимком.
    event_body: Vec<u8>,
    /// Голый QSN-снимок для C `EV_SHAPE` (v22).
    snapshot: Vec<u8>,
}

/// C `slot_of`: всё, кроме UDP, — слот TCP.
fn slot_of(transport: u8) -> usize {
    usize::from(transport == 17)
}

/// C `shape_slot`: TCP4=0, UDP4=1, TCP6=2, UDP6=3.
fn shape_slot(transport: u8, family: u8) -> usize {
    slot_of(transport) + usize::from(family == 6) * 2
}

/// События, формат которых в v22 совпадает с R2O. Остальные номера v22
/// либо транслируются, либо не отправляются C-контроллеру вовсе.
fn v22_event_frames(kind: u16, body: &[u8]) -> Vec<(u16, Vec<u8>)> {
    if kind == control::EVENT_R2O_JOURNAL_ENTRY {
        let frame = Frame {
            kind,
            body: body.to_vec(),
        };
        return crate::flow_journal::R2oFlowJournalEntry::from_event_frame(&frame)
            .map(|entry| entry.to_v22_frames())
            .unwrap_or_default();
    }
    match kind {
        control::EVENT_HELLO
        | control::EVENT_STATS
        | control::EVENT_REFUSED
        | control::EVENT_APPLIED
        | control::EVENT_PROTOCOL
        | control::EVENT_HTTP_PORTAL
        | control::EVENT_HTTP_RESPONSE
        | control::EVENT_LEGACY_SHAPE => vec![(kind, body.to_vec())],
        _ => control::translate_event_to_v22(kind, body),
    }
}

impl ControlServer {
    pub fn open(path: impl AsRef<Path>, send_maxlen: u32) -> io::Result<Self> {
        Self::open_with_profile(
            path,
            send_maxlen,
            control::WireProfile::V48,
            control::RELEASE_ID,
        )
    }

    pub fn open_with_profile(
        path: impl AsRef<Path>,
        send_maxlen: u32,
        wire_profile: control::WireProfile,
        release_id: &str,
    ) -> io::Result<Self> {
        if !control::valid_release_id(release_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                crate::error_text::error_text(96, "недопустимый release ID control-wire"),
            ));
        }
        let path = path.as_ref().to_owned();
        // C `d2k_ctl_open` (`ctl.c:109-112`): (void)unlink(path) перед bind —
        // снимается только свой путь из настройки, чтобы файл после SIGKILL
        // не мешал следующему запуску.
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        // C `listen(c->lfd, 1)`; std уже вызвал listen с большим backlog,
        // повторный вызов сужает очередь до эталонной.
        if unsafe { libc::listen(listener.as_raw_fd(), 1) } != 0 {
            let error = io::Error::last_os_error();
            drop(listener);
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        if let Err(error) = listener.set_nonblocking(true) {
            drop(listener);
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                drop(listener);
                let _ = std::fs::remove_file(&path);
                return Err(error);
            }
        };
        Ok(Self {
            listener,
            path,
            socket_dev: metadata.dev(),
            socket_ino: metadata.ino(),
            send_maxlen,
            wire_profile,
            release_id: release_id.to_owned(),
            peer: None,
            input: Vec::new(),
            output: VecDeque::new(),
            output_bytes: 0,
            dropped_events: 0,
            sent_events: 0,
            disconnect_hook: None,
            last_client_shapes: VecDeque::new(),
            armed_shapes: [None, None, None, None],
            last_quic_shapes: VecDeque::new(),
            shape_tcp_options: [None, None, None, None],
        })
    }

    pub fn poll(&mut self) -> io::Result<Vec<Frame>> {
        let mut frames = Vec::new();
        let peer_was_connected = self.peer.is_some();
        if peer_was_connected && !self.read_peer(&mut frames) {
            self.disconnect();
            return Ok(frames);
        }
        self.accept_peer();
        if !peer_was_connected && self.peer.is_some() && !self.read_peer(&mut frames) {
            self.disconnect();
        }
        self.flush()?;
        Ok(frames)
    }

    pub fn send_ack(&mut self, ack: Ack) -> io::Result<()> {
        let bytes = control::encode_ack_with_identifiers_profile(
            self.wire_profile,
            ack.command,
            ack.ok,
            ack.reason,
            ack.trial_id,
            ack.area_id,
            ack.binding_context,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.enqueue(bytes);
        self.flush()
    }

    /// C `d2k_session_shape_tcp_options_family`: опции TCP клиента для
    /// семейства. `None` — снимка формы нет; `Some(&[])` — снимок есть,
    /// но опций не было (C возвращает указатель с `len=0`).
    pub fn shape_tcp_options_family(&self, family: u8) -> Option<&[u8]> {
        if !matches!(family, 4 | 6) {
            return None;
        }
        if !self
            .last_client_shapes
            .iter()
            .any(|cached| cached.family == family)
        {
            return None;
        }
        Some(
            self.shape_tcp_options[shape_slot(6, family)]
                .as_deref()
                .unwrap_or(&[]),
        )
    }

    /// Запомнить набор TCP-опций наблюдённого ClientHello (C `shape_opts[k]`).
    pub fn record_shape_tcp_options(&mut self, family: u8, options: &[u8]) {
        if matches!(family, 4 | 6) {
            let slot = shape_slot(6, family);
            self.shape_tcp_options[slot] = Some(options[..options.len().min(40)].to_vec());
        }
    }

    fn v22_frames_with_shape_options(&self, kind: u16, body: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut frames = v22_event_frames(kind, body);
        if kind == control::EVENT_CLIENT_SHAPE
            && let Some(family) = body.first().copied()
            && let Some(options) = self.shape_tcp_options_family(family)
            && options.len() <= 40
            && let Some((_, tcp_body)) = frames
                .iter_mut()
                .find(|(kind, _)| *kind == control::EVENT_LEGACY_CLIENT_TCP)
        {
            // C отправляет CLIENT_TCP перед SHAPE с тем же ключом.
            tcp_body.extend_from_slice(options);
        }
        frames
    }

    pub fn send_event(&mut self, kind: u16, body: &[u8]) -> io::Result<()> {
        if self.peer.is_none() {
            self.dropped_events = self.dropped_events.saturating_add(1);
            return Ok(());
        }
        if self.wire_profile == control::WireProfile::V22 {
            for (legacy_kind, legacy_body) in self.v22_frames_with_shape_options(kind, body) {
                let bytes = control::encode_frame(legacy_kind, &legacy_body)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                self.enqueue(bytes);
            }
            return self.flush();
        }
        let bytes = control::encode_frame(kind, body)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.enqueue(bytes);
        self.flush()
    }

    /// Queue an event only when it can be retained for the connected controller.
    pub fn try_send_event(&mut self, kind: u16, body: &[u8]) -> io::Result<bool> {
        if self.peer.is_none() {
            self.dropped_events = self.dropped_events.saturating_add(1);
            return Ok(false);
        }
        let frames = if self.wire_profile == control::WireProfile::V22 {
            self.v22_frames_with_shape_options(kind, body)
        } else {
            vec![(kind, body.to_vec())]
        };
        if frames.is_empty() {
            return Ok(self.peer.is_some());
        }
        let mut bytes = Vec::new();
        for (frame_kind, frame_body) in frames {
            bytes.extend_from_slice(
                &control::encode_frame(frame_kind, &frame_body)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
            );
        }
        if !self.enqueue(bytes) {
            return Ok(false);
        }
        self.flush()?;
        Ok(self.peer.is_some())
    }

    /// Объявляет новый общий предел отправки уже подключённому контроллеру.
    pub fn r2o_set_send_maxlen(&mut self, send_maxlen: u32) -> io::Result<()> {
        if self.send_maxlen == send_maxlen {
            return Ok(());
        }
        self.send_maxlen = send_maxlen;
        if self.peer.is_some() {
            let greeting =
                control::encode_greeting_profile(self.wire_profile, &self.release_id, send_maxlen)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            self.enqueue(greeting);
            self.flush()?;
        }
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.peer.is_some()
    }

    /// C `d2k_ctl_set_disconnect_hook`: повесить обработчик разрыва.
    pub fn set_disconnect_hook(&mut self, hook: impl FnMut() + Send + 'static) {
        self.disconnect_hook = Some(Box::new(hook));
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// C `d2k_ctl_sent` (`datapath/ctl.c:316`).
    pub fn sent_events(&self) -> u64 {
        self.sent_events
    }

    /// C `d2k_ctl_listen_fd` (`datapath/ctl.c:143`).
    pub fn listen_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    /// C `d2k_ctl_peer_fd` (`datapath/ctl.c:144`): -1 без подключённого пира.
    pub fn peer_fd(&self) -> RawFd {
        self.peer.as_ref().map(AsRawFd::as_raw_fd).unwrap_or(-1)
    }

    fn arm_ack(ok: bool, reason: u8) -> Ack {
        Ack {
            command: COMMAND_ARM_SHAPE,
            ok,
            reason,
            trial_id: None,
            area_id: None,
            binding_context: None,
        }
    }

    /// ARM_SHAPE: serve a matching cached ClientHello immediately or arm one capture.
    ///
    /// C хранит снимки отдельно по транспорту и семейству (`shape_slot`);
    /// пустое имя — wildcard, подходящий любому сохранённому приветствию
    /// (`session.c:2931-2959`).
    pub fn arm_client_shape(&mut self, frame: &Frame) -> (Ack, Option<(u16, Vec<u8>)>) {
        let Ok(command) = decode_arm_shape(frame) else {
            return (Self::arm_ack(false, control::ACK_BAD_ARGS), None);
        };
        let slot = shape_slot(command.transport, command.family);
        match command.transport {
            6 => {
                if let Some(position) = self.last_client_shapes.iter().position(|cached| {
                    cached.family == command.family
                        && (command.name.is_empty() || r2o_name_same(&cached.host, &command.name))
                }) {
                    let cached = self
                        .last_client_shapes
                        .remove(position)
                        .expect("позиция кэша ClientHello только что найдена");
                    // Свежий запрос продлевает жизнь снимка в LRU.
                    let body = cached.event_body.clone();
                    self.last_client_shapes.push_back(cached);
                    return (
                        Self::arm_ack(true, control::ACK_OK),
                        Some((control::EVENT_CLIENT_SHAPE, body)),
                    );
                }
                self.armed_shapes[slot] = Some(command.name);
                (Self::arm_ack(true, control::ACK_OK), None)
            }
            17 => {
                if let Some(position) = self.last_quic_shapes.iter().position(|cached| {
                    cached.family == command.family
                        && (command.name.is_empty() || r2o_name_same(&cached.host, &command.name))
                }) {
                    let cached = self
                        .last_quic_shapes
                        .remove(position)
                        .expect("позиция кэша QUIC-снимка только что найдена");
                    let event = self.quic_shape_event(&cached);
                    self.last_quic_shapes.push_back(cached);
                    return (Self::arm_ack(true, control::ACK_OK), Some(event));
                }
                self.armed_shapes[slot] = Some(command.name);
                (Self::arm_ack(true, control::ACK_OK), None)
            }
            _ => (Self::arm_ack(false, control::ACK_BAD_ARGS), None),
        }
    }

    /// Событие снимка для контроллера: C `EV_SHAPE` в v22 или R2O
    /// `EVENT_HELLO` с QSN-пачкой в v48.
    fn quic_shape_event(&self, cached: &CachedQuicShape) -> (u16, Vec<u8>) {
        if self.wire_profile == control::WireProfile::V22 {
            let mut body = vec![0; control::KEY_LEN];
            body[0] = cached.family;
            body[control::KEY_LEN - 1] = 17;
            body.extend_from_slice(&cached.snapshot);
            (control::EVENT_LEGACY_SHAPE, body)
        } else {
            (control::EVENT_HELLO, cached.event_body.clone())
        }
    }

    /// Retain the latest TCP ClientHello per family and satisfy a matching one-shot arm.
    pub fn observe_client_shape(&mut self, body: &[u8]) -> Result<Option<Vec<u8>>, &'static str> {
        let event = decode_client_shape(&Frame {
            kind: control::EVENT_CLIENT_SHAPE,
            body: body.to_vec(),
        })?;
        let family = event.key[0];
        let slot = shape_slot(6, family);
        if let Some(position) = self
            .last_client_shapes
            .iter()
            .position(|cached| cached.family == family && r2o_name_same(&cached.host, &event.host))
        {
            self.last_client_shapes.remove(position);
        }
        self.last_client_shapes.push_back(CachedClientShape {
            host: event.host.clone(),
            family,
            event_body: body.to_vec(),
        });
        while self.last_client_shapes.len() > CLIENT_SHAPE_CACHE_MAX {
            self.last_client_shapes.pop_front();
        }
        if self.armed_shapes[slot]
            .as_ref()
            .is_some_and(|host| host.is_empty() || r2o_name_same(host, &event.host))
        {
            self.armed_shapes[slot] = None;
            Ok(Some(body.to_vec()))
        } else {
            Ok(None)
        }
    }

    /// Сохранить QUIC-снимок и, если он ждали, отдать событие немедленно.
    ///
    /// C `d2k_session_shape_family` возвращает QSN-пачку в `EV_SHAPE`
    /// (`session.c:2966-2980`); R2O `QSN`-формат побайтно совпадает с
    /// `d2k_qsnap_pack`. В v48 обычный `EVENT_HELLO` уже уходит вызывающим,
    /// поэтому дополнительное событие не дублируется.
    pub fn observe_quic_hello(
        &mut self,
        hello: &crate::capture::QuicHello,
    ) -> Option<(u16, Vec<u8>)> {
        if hello.key[37] != 17 {
            return None;
        }
        let snapshot = hello.snapshot.as_ref()?;
        let event_body = hello.event_body()?;
        let family = hello.key[0];
        if let Some(position) = self
            .last_quic_shapes
            .iter()
            .position(|cached| cached.family == family && r2o_name_same(&cached.host, &hello.host))
        {
            self.last_quic_shapes.remove(position);
        }
        self.last_quic_shapes.push_back(CachedQuicShape {
            host: hello.host.clone(),
            family,
            event_body,
            snapshot: snapshot.clone(),
        });
        while self.last_quic_shapes.len() > CLIENT_SHAPE_CACHE_MAX {
            self.last_quic_shapes.pop_front();
        }
        let slot = shape_slot(17, family);
        if self.armed_shapes[slot]
            .as_ref()
            .is_some_and(|host| host.is_empty() || r2o_name_same(host, &hello.host))
        {
            self.armed_shapes[slot] = None;
            if self.wire_profile == control::WireProfile::V22 {
                let cached = self
                    .last_quic_shapes
                    .back()
                    .expect("QUIC-снимок только что добавлен");
                return Some(self.quic_shape_event(cached));
            }
        }
        None
    }

    fn accept_peer(&mut self) {
        loop {
            match self.listener.accept() {
                Ok((peer, _)) if self.peer.is_none() => {
                    if peer.set_nonblocking(true).is_err() {
                        let _ = peer.shutdown(Shutdown::Both);
                        return;
                    }
                    self.peer = Some(peer);
                    if let Ok(greeting) = control::encode_greeting_profile(
                        self.wire_profile,
                        &self.release_id,
                        self.send_maxlen,
                    ) {
                        self.enqueue(greeting);
                    }
                }
                Ok((peer, _)) => {
                    let _ = peer.shutdown(Shutdown::Both);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => return,
            }
        }
    }

    fn read_peer(&mut self, frames: &mut Vec<Frame>) -> bool {
        let mut buffer = [0; 8192];
        loop {
            let result = match self.peer.as_mut() {
                Some(peer) => peer.read(&mut buffer),
                None => return true,
            };
            match result {
                Ok(0) => return false,
                Ok(length) => {
                    if self.input.len().saturating_add(length) > control::FRAME_MAX + 4 {
                        return false;
                    }
                    self.input.extend_from_slice(&buffer[..length]);
                    if !self.take_complete_frames(frames) {
                        return false;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return true,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return false,
            }
        }
    }

    fn take_complete_frames(&mut self, frames: &mut Vec<Frame>) -> bool {
        loop {
            if self.input.len() < 4 {
                return true;
            }
            let length =
                u32::from_be_bytes(self.input[..4].try_into().expect("four byte prefix")) as usize;
            if !(2..=control::FRAME_MAX).contains(&length) {
                return false;
            }
            let frame_len = length + 4;
            if self.input.len() < frame_len {
                return true;
            }
            let kind = u16::from_be_bytes([self.input[4], self.input[5]]);
            frames.push(Frame {
                kind,
                body: self.input[6..frame_len].to_vec(),
            });
            self.input.drain(..frame_len);
        }
    }

    /// Поставить кадр в кольцо целиком. `false` — кадр потерян.
    ///
    /// C `d2k_ctl_event` считает `sent++` только после успешной записи
    /// заголовка и тела в кольцо (`ctl.c:244-253`).
    fn enqueue(&mut self, bytes: Vec<u8>) -> bool {
        if self.peer.is_none() {
            return false;
        }
        if self.output_bytes.saturating_add(bytes.len()) > MAX_CONTROL_OUTPUT {
            self.dropped_events = self.dropped_events.saturating_add(1);
            return false;
        }
        self.output_bytes += bytes.len();
        self.output.push_back(PendingWrite { bytes, offset: 0 });
        self.sent_events = self.sent_events.saturating_add(1);
        true
    }

    fn flush(&mut self) -> io::Result<()> {
        let Some(peer) = self.peer.as_mut() else {
            return Ok(());
        };
        loop {
            let Some(pending) = self.output.front_mut() else {
                return Ok(());
            };
            match peer.write(&pending.bytes[pending.offset..]) {
                Ok(0) => {
                    self.disconnect();
                    return Ok(());
                }
                Ok(length) => {
                    pending.offset += length;
                    self.output_bytes -= length;
                    if pending.offset == pending.bytes.len() {
                        self.output.pop_front();
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.disconnect();
                    return if error.kind() == io::ErrorKind::BrokenPipe {
                        Ok(())
                    } else {
                        Err(error)
                    };
                }
            }
        }
    }

    fn disconnect(&mut self) {
        let peer = self.peer.take();
        let was_connected = peer.is_some();
        if let Some(peer) = peer {
            let _ = peer.shutdown(Shutdown::Both);
        }
        self.input.clear();
        self.output.clear();
        self.output_bytes = 0;
        if was_connected && let Some(hook) = self.disconnect_hook.as_mut() {
            hook();
        }
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        // C `d2k_ctl_close` закрывает pfd напрямую, без disconnect_hook.
        self.disconnect_hook = None;
        self.disconnect();
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.socket_dev
            && metadata.ino() == self.socket_ino
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// C `name_norm` (`datapath/http80.c:83-95`): имя HTTPS-подтверждения —
/// только `A-Za-z0-9-.`, один хвостовой точка снимается, длина до 253.
/// Это НЕ строгий валидатор планов: C допускает односложные, чисто цифровые
/// имена и пустые метки (`localhost`, `1.2.3.4`, `a..b`).
fn canonical_https_name(bytes: &[u8]) -> Option<String> {
    let bytes = bytes.strip_suffix(b".").unwrap_or(bytes);
    if bytes.is_empty() || bytes.len() >= HTTPS_NAME_BYTES || !bytes.is_ascii() {
        return None;
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return None;
    }
    String::from_utf8(bytes.to_ascii_lowercase()).ok()
}

fn canonical_name(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > 253 || !bytes.is_ascii() {
        return None;
    }
    let value = std::str::from_utf8(bytes).ok()?;
    let value = value.strip_suffix('.').unwrap_or(value);
    let mut has_non_digit = false;
    let labels: Vec<_> = value.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in labels {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return None;
        }
        has_non_digit |= label.bytes().any(|byte| !byte.is_ascii_digit());
    }
    if !has_non_digit {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

/// C `area_name_valid` (`plans.c:177-191`): суффикс/исключение допускает
/// односложные и чисто цифровые имена, но не пустые метки, крайние дефисы и
/// метки длиннее 63 байт. Точные имена проверяются отдельно `canonical_name`.
fn canonical_area_name(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > 253 || !bytes.is_ascii() {
        return None;
    }
    let mut label_len = 0usize;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == b'.' {
            if label_len == 0 || bytes[index - 1] == b'-' {
                return None;
            }
            label_len = 0;
        } else {
            if !(byte.is_ascii_alphanumeric() || byte == b'-') {
                return None;
            }
            if label_len == 0 && byte == b'-' {
                return None;
            }
            label_len += 1;
            if label_len > 63 {
                return None;
            }
        }
    }
    if label_len == 0 || bytes[bytes.len() - 1] == b'-' {
        return None;
    }
    Some(std::str::from_utf8(bytes).ok()?.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{
        AddrProbePlan, ControlServer, InstalledPlan, NamePlanKey, NamePlans, NameProbeKey,
        ProbePlan, VoiceProbeKey, VoiceProbePlan,
    };
    use r2k_core::control::BindingContext;
    use r2k_core::plan::Plan;
    use std::io::Write;
    use std::os::unix::fs::FileTypeExt;

    fn plan_header(minexec: u16, records: u16) -> Vec<u8> {
        let mut bytes = super::PLAN_MAGIC.to_vec();
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&minexec.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&records.to_be_bytes());
        bytes
    }
    fn tls_plan_records(id: [u8; 16]) -> Vec<u8> {
        let mut bytes = plan_header(0, 2);
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x01]);
        bytes
    }
    fn quic_plan_records(id: [u8; 16]) -> Vec<u8> {
        let mut bytes = plan_header(10, 3);
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x11, 0x02]);
        bytes.extend_from_slice(&[0x01, 0x0f, 0x00, 0x01, 0x01]);
        bytes
    }
    fn quic_deny_plan_records(id: [u8; 16]) -> Vec<u8> {
        let mut bytes = plan_header(11, 3);
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x11, 0x02]);
        bytes.extend_from_slice(&[0x01, 0x10, 0x00, 0x01, 0x01]);
        bytes
    }
    fn r2o_quic_clearance_plan_records(id: [u8; 16]) -> Vec<u8> {
        let mut bytes = plan_header(10, 4);
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x11, 0x02]);
        bytes.extend_from_slice(&[0x00, 0x10, 0x00, 0x12, 0x00, 0x01]);
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&[0x01, 0x01, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00]);
        bytes.extend_from_slice(&[0x01, 0x00, 0, 0, 0, 0]);
        bytes
    }

    fn r2o_quic_udp_length_plan_records(id: [u8; 16]) -> Vec<u8> {
        let mut bytes = plan_header(9, 3);
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x11, 0x02]);
        bytes.extend_from_slice(&[0x01, 0x0e, 0x00, 0x02, 0, 100]);
        bytes
    }
    use r2k_core::control::{
        self, Ack, COMMAND_ARM_SHAPE, COMMAND_CLEAR, COMMAND_DEL_ADDR, COMMAND_DEL_BYPASS,
        COMMAND_DEL_NAME, COMMAND_DEL_NAME_PROBE, COMMAND_DEL_SUFFIX, COMMAND_SET_ADDR,
        COMMAND_SET_BYPASS, COMMAND_SET_NAME, COMMAND_SET_NAME_BOUND, COMMAND_SET_NAME_PROBE,
        COMMAND_SET_SUFFIX, EVENT_CLIENT_SHAPE, EVENT_HELLO, EVENT_LEGACY_SHAPE, Frame,
        SHAPE_ECH_TCP, SHAPE_GRANDFATHER, SHAPE_HTTP, SHAPE_LEGACY, SHAPE_MODERN, SHAPE_QUIC,
        SHAPE_VOICE, encode_delete_addr, encode_set_addr, encode_set_voice_addr,
        encode_set_voice_addr_probe,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[test]
    fn control_socket_is_private_to_its_owner() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("r2o-control-perms-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let server = ControlServer::open(&path, u16::MAX as u32).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        drop(server);
        // C `d2k_ctl_open` не вызывает chmod: доступ задаёт umask. Проверяем
        // только, что владелец может пользоваться сокетом и это сокет.
        assert!(metadata.file_type().is_socket());
        assert_ne!(mode & 0o600, 0, "owner must be able to use the socket");
        assert!(!path.exists(), "server should remove its socket on drop");
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn control_open_unlinks_existing_regular_file_like_c() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("r2o-control-unlink-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        std::fs::write(&path, b"stale").unwrap();
        let server = ControlServer::open(&path, u16::MAX as u32).unwrap();
        assert!(std::fs::metadata(&path).unwrap().file_type().is_socket());
        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn control_server_accepts_reconnect_pending_after_previous_peer_closes() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "r2o-control-reconnect-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server = ControlServer::open(&path, u16::MAX as u32).unwrap();
        let mut previous = UnixStream::connect(&path).unwrap();
        previous
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(server.poll().unwrap().is_empty());
        assert_eq!(
            control::read_frame(&mut previous).unwrap().kind,
            control::EVENT_PROTOCOL
        );

        drop(previous);
        let mut reconnected = UnixStream::connect(&path).unwrap();
        reconnected
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(server.poll().unwrap().is_empty());
        assert!(
            !server.is_connected(),
            "the disconnect must be visible before accepting its reconnect"
        );

        assert!(server.poll().unwrap().is_empty());

        assert!(server.is_connected(), "the queued reconnect was discarded");
        assert_eq!(
            control::read_frame(&mut reconnected).unwrap().kind,
            control::EVENT_PROTOCOL
        );

        drop(reconnected);
        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn arm_shape_serves_cached_client_hello_of_older_target() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "r2o-control-shape-cache-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server = ControlServer::open(&path, u16::MAX as u32).unwrap();

        let first = crate::capture::tcp_hello_from_packet(&tcp_tls_packet("first.example"))
            .unwrap()
            .shape_event_body()
            .unwrap();
        let second = crate::capture::tcp_hello_from_packet(&tcp_tls_packet("second.example"))
            .unwrap()
            .shape_event_body()
            .unwrap();
        server.observe_client_shape(&first).unwrap();
        server.observe_client_shape(&second).unwrap();

        let name = b"first.example";
        let mut body = vec![name.len() as u8];
        body.extend_from_slice(name);
        body.extend_from_slice(&[6, 4]);
        let (ack, cached) = server.arm_client_shape(&Frame {
            kind: COMMAND_ARM_SHAPE,
            body,
        });
        assert!(ack.ok);
        assert_eq!(
            cached.as_ref().map(|(kind, body)| (*kind, body.as_slice())),
            Some((EVENT_CLIENT_SHAPE, first.as_slice())),
            "снимок старой цели должен отдаваться из кэша, а не теряться"
        );

        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn shape_slots_совпадают_с_c_и_независимы() {
        assert_eq!(super::slot_of(6), 0);
        assert_eq!(super::slot_of(17), 1);
        assert_eq!(super::slot_of(0), 0);
        assert_eq!(super::shape_slot(6, 4), 0);
        assert_eq!(super::shape_slot(17, 4), 1);
        assert_eq!(super::shape_slot(6, 6), 2);
        assert_eq!(super::shape_slot(17, 6), 3);

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "r2o-control-shape-slots-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server = ControlServer::open(&path, u16::MAX as u32).unwrap();

        for (transport, family, name) in [
            (6_u8, 4_u8, b"tcp4".as_slice()),
            (17, 4, b"udp4".as_slice()),
            (6, 6, b"tcp6".as_slice()),
            (17, 6, b"udp6".as_slice()),
        ] {
            let mut body = vec![name.len() as u8];
            body.extend_from_slice(name);
            body.extend_from_slice(&[transport, family]);
            let (ack, cached) = server.arm_client_shape(&Frame {
                kind: COMMAND_ARM_SHAPE,
                body,
            });
            assert!(ack.ok, "ARM_SHAPE {transport}/{family}");
            assert!(cached.is_none());
        }
        assert_eq!(server.armed_shapes[0].as_deref(), Some(b"tcp4".as_slice()));
        assert_eq!(server.armed_shapes[1].as_deref(), Some(b"udp4".as_slice()));
        assert_eq!(server.armed_shapes[2].as_deref(), Some(b"tcp6".as_slice()));
        assert_eq!(server.armed_shapes[3].as_deref(), Some(b"udp6".as_slice()));

        server.record_shape_tcp_options(4, &[2, 4, 1, 1]);
        server.record_shape_tcp_options(6, &[2, 4, 8, 10]);
        assert_eq!(
            server.shape_tcp_options[0].as_deref(),
            Some(&[2, 4, 1, 1][..])
        );
        assert!(server.shape_tcp_options[1].is_none());
        assert_eq!(
            server.shape_tcp_options[2].as_deref(),
            Some(&[2, 4, 8, 10][..])
        );
        assert!(server.shape_tcp_options[3].is_none());

        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn arm_shape_serves_quic_snapshot_and_empty_name_is_wildcard() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "r2o-control-quic-shape-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server = ControlServer::open(&path, u16::MAX as u32).unwrap();
        let packet = udp_packet(
            include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin"),
            443,
        );
        let hello = crate::capture::quic_hello_from_packet(&packet).unwrap();
        assert!(!hello.host.is_empty());
        assert!(hello.snapshot.is_some());

        // ARM_SHAPE 17 с точным именем: снимка ещё нет — только взвод.
        let mut arm = vec![hello.host.len() as u8];
        arm.extend_from_slice(&hello.host);
        arm.extend_from_slice(&[17, 4]);
        let (ack, cached) = server.arm_client_shape(&Frame {
            kind: COMMAND_ARM_SHAPE,
            body: arm,
        });
        assert!(ack.ok);
        assert!(cached.is_none());

        // v48: обычный EVENT_HELLO уже уходит вызывающим, дубля нет.
        assert!(server.observe_quic_hello(&hello).is_none());

        // Пустое имя — wildcard: снимок отдаётся из кэша сразу.
        let (ack, cached) = server.arm_client_shape(&Frame {
            kind: COMMAND_ARM_SHAPE,
            body: vec![0, 17, 4],
        });
        assert!(ack.ok);
        let (kind, body) = cached.expect("снимок QUIC должен быть в кэше");
        assert_eq!(kind, EVENT_HELLO);
        assert_eq!(Some(body), hello.event_body());

        // v22: C-контроллер ждёт EV_SHAPE с QSN-пачкой и ключом transport=17.
        let path22 = directory.join("control22.sock");
        let mut server22 = ControlServer::open_with_profile(
            &path22,
            u16::MAX as u32,
            control::WireProfile::V22,
            control::RELEASE_ID,
        )
        .unwrap();
        let (ack, cached) = server22.arm_client_shape(&Frame {
            kind: COMMAND_ARM_SHAPE,
            body: vec![0, 17, 4],
        });
        assert!(ack.ok);
        assert!(cached.is_none());
        let (kind, body) = server22
            .observe_quic_hello(&hello)
            .expect("взведённый ARM_SHAPE 17 должен отдать снимок");
        assert_eq!(kind, EVENT_LEGACY_SHAPE);
        let mut expected = vec![0; control::KEY_LEN];
        expected[0] = hello.key[0];
        expected[control::KEY_LEN - 1] = 17;
        expected.extend_from_slice(hello.snapshot.as_ref().unwrap());
        assert_eq!(body, expected);

        drop(server);
        drop(server22);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn control_server_counts_each_event_without_connected_peer_as_dropped_like_d2o() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "r2o-control-disconnected-event-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server = ControlServer::open(&path, u16::MAX as u32).unwrap();
        let body = [1, 2, 3, 4];

        server.send_event(EVENT_HELLO, &body).unwrap();
        assert!(!server.try_send_event(EVENT_HELLO, &body).unwrap());

        assert_eq!(server.dropped_events(), 2);
        if let Some(output) = std::env::var_os("R2O_CONTROL_DROPPED_DIFF_OUTPUT") {
            std::fs::write(output, "control_dropped=2\n").unwrap();
        }
        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn control_server_sends_a_tls_hello_event_to_connected_controller() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("r2o-control-event-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server = ControlServer::open(&path, u16::MAX as u32).unwrap();
        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(server.poll().unwrap().is_empty());
        assert!(server.is_connected());
        let greeting = control::read_frame(&mut client).unwrap();
        assert_eq!(greeting.kind, control::EVENT_PROTOCOL);

        let mut body = vec![0; control::KEY_LEN + 1 + b"example.test".len()];
        body[0] = 4;
        body[control::KEY_LEN] = b"example.test".len() as u8;
        body[control::KEY_LEN + 1..].copy_from_slice(b"example.test");
        server.send_event(EVENT_HELLO, &body).unwrap();
        let event = control::read_frame(&mut client).unwrap();
        assert_eq!(event.kind, EVENT_HELLO);
        assert_eq!(event.body, body);

        drop(client);
        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn v22_control_server_greets_with_profile_release_and_raw_bound_ack() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("r2o-control-v22-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server =
            ControlServer::open_with_profile(&path, 1500, control::WireProfile::V22, "dev")
                .unwrap();
        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(server.poll().unwrap().is_empty());
        let greeting =
            control::decode_greeting(&control::read_frame(&mut client).unwrap()).unwrap();
        assert_eq!(greeting.version, control::PROTOCOL_VERSION_V22);
        assert_eq!(greeting.release_id, "dev");
        assert_eq!(greeting.send_maxlen, 1500);

        let binding = control::BindingContext {
            generation: 0x0102_0304_0506_0708,
            kind: 1,
            family: 4,
            shape: SHAPE_HTTP,
            temporary: false,
            epoch: [0x11; 16],
        };
        server
            .send_ack(Ack {
                command: COMMAND_SET_NAME_BOUND,
                ok: true,
                reason: 0,
                trial_id: Some([0x22; 16]),
                area_id: None,
                binding_context: Some(binding),
            })
            .unwrap();
        let frame = control::read_frame(&mut client).unwrap();
        assert_eq!(frame.kind, control::EVENT_ACK);
        assert_eq!(frame.body.len(), control::KEY_LEN + 4 + 16 + 28);
        assert_ne!(
            &frame.body[control::KEY_LEN + 4 + 16..control::KEY_LEN + 4 + 20],
            b"R2BC"
        );
        assert_eq!(
            control::decode_ack(&frame).unwrap().binding_context,
            Some(binding)
        );
        drop(client);
        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn try_send_event_reports_when_the_control_outbox_cannot_retain_an_event() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("r2o-control-retry-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server = ControlServer::open(&path, u16::MAX as u32).unwrap();
        assert!(
            !server
                .try_send_event(control::EVENT_R2O_VOICE_RTP_PROOF, &[])
                .unwrap()
        );
        assert_eq!(server.dropped_events(), 1);

        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(server.poll().unwrap().is_empty());
        let _greeting = control::read_frame(&mut client).unwrap();
        server.output_bytes = super::MAX_CONTROL_OUTPUT;
        assert!(
            !server
                .try_send_event(control::EVENT_R2O_VOICE_RTP_PROOF, &[])
                .unwrap(),
            "полный outbox должен оставить доказательство на повтор"
        );
        assert_eq!(server.dropped_events(), 2);
        server.output_bytes = 0;
        assert!(
            server
                .try_send_event(control::EVENT_R2O_VOICE_RTP_PROOF, &[])
                .unwrap()
        );
        let event = control::read_frame(&mut client).unwrap();
        assert_eq!(event.kind, control::EVENT_R2O_VOICE_RTP_PROOF);

        drop(client);
        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn control_server_announces_updated_send_limit_to_connected_controller() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("r2o-control-limit-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server = ControlServer::open(&path, 1280).unwrap();
        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(server.poll().unwrap().is_empty());
        assert_eq!(
            control::decode_greeting(&control::read_frame(&mut client).unwrap())
                .unwrap()
                .send_maxlen,
            1280
        );

        server.r2o_set_send_maxlen(1500).unwrap();
        assert_eq!(
            control::decode_greeting(&control::read_frame(&mut client).unwrap())
                .unwrap()
                .send_maxlen,
            1500
        );
        drop(client);
        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn exact_name_addr_probe_tables_share_lru_capacity() {
        let address_b = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let address_c = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3));
        let mut plans = NamePlans::with_capacity(2);
        assert!(plans.handle(&set_name("a.example")).ok);
        let command =
            encode_set_addr(address_b, SHAPE_MODERN, &tls_plan_records([0x42; 16])).unwrap();
        let frame = control::read_frame(&mut std::io::Cursor::new(command)).unwrap();
        assert!(plans.handle(&frame).ok);
        assert_eq!(plans.r2o_plan_count(), 2);

        // Обращение к имени делает его свежим; старая адресная запись уходит.
        assert!(plans.select(&tcp_tls_packet("a.example")).is_some());
        let command =
            encode_set_addr(address_c, SHAPE_MODERN, &tls_plan_records([0x43; 16])).unwrap();
        let frame = control::read_frame(&mut std::io::Cursor::new(command)).unwrap();
        assert!(plans.handle(&frame).ok);
        assert_eq!(plans.r2o_plan_count(), 2);
        assert!(plans.select(&tcp_tls_packet("a.example")).is_some());
        assert!(!plans.addr_plans.contains_key(&super::AddrPlanKey {
            address: address_b.into(),
            shape: SHAPE_MODERN,
        }));
        assert!(plans.addr_plans.contains_key(&super::AddrPlanKey {
            address: address_c.into(),
            shape: SHAPE_MODERN,
        }));
    }

    #[test]
    fn name_plan_table_evicts_lru_and_delete_releases_a_slot() {
        let mut plans = NamePlans::with_capacity(2);
        assert!(plans.handle(&set_name("a.example")).ok);
        assert!(plans.handle(&set_name("b.example")).ok);
        assert!(plans.select(&tcp_tls_packet("a.example")).is_some());
        assert!(plans.handle(&set_name("c.example")).ok);
        assert_eq!(plans.r2o_plan_count(), 2);
        assert_eq!(plans.r2o_plan_capacity(), 2);
        assert!(plans.select(&tcp_tls_packet("a.example")).is_some());
        assert!(plans.select(&tcp_tls_packet("b.example")).is_none());
        assert!(plans.select(&tcp_tls_packet("c.example")).is_some());

        let mut delete = vec!["a.example".len() as u8];
        delete.extend_from_slice(b"a.example");
        delete.extend_from_slice(&[6, SHAPE_MODERN, 4]);
        assert!(
            plans
                .handle(&Frame {
                    kind: COMMAND_DEL_NAME,
                    body: delete,
                })
                .ok
        );
        assert!(plans.handle(&set_name("d.example")).ok);
        assert_eq!(plans.r2o_plan_count(), 2);
        assert!(plans.select(&tcp_tls_packet("d.example")).is_some());
        assert!(
            plans
                .handle(&Frame {
                    kind: COMMAND_CLEAR,
                    body: Vec::new(),
                })
                .ok
        );
    }

    #[test]
    fn bound_http_set_returns_its_trial_id_and_installed_binding() {
        let host = b"example.test";
        let trial_id = [0xabu8; 16];
        let mut plan = plan_header(11, 2);
        plan.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        plan.extend_from_slice(&[0x11; 16]);
        plan.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, r2k_core::plan::PROTO_HTTP]);
        let mut body = vec![host.len() as u8];
        body.extend_from_slice(host);
        body.extend_from_slice(&[SHAPE_HTTP, 4]);
        body.extend_from_slice(&plan);
        body.extend_from_slice(&trial_id);

        let mut plans = NamePlans::default();
        let ack = plans.handle(&Frame {
            kind: COMMAND_SET_NAME_BOUND,
            body,
        });
        assert!(ack.ok, "HTTP plan was rejected: {}", ack.reason);
        assert_eq!(ack.trial_id, Some(trial_id));
        let binding = ack
            .binding_context
            .expect("bound SET returns binding context");
        assert!(binding.is_known());
        assert_eq!(binding.family, 4);
        assert_eq!(binding.shape, SHAPE_HTTP);

        let wire = control::encode_ack_with_identifiers(
            ack.command,
            ack.ok,
            ack.reason,
            ack.trial_id,
            ack.area_id,
            ack.binding_context,
        )
        .unwrap();
        let decoded =
            control::decode_ack(&control::read_frame(&mut std::io::Cursor::new(wire)).unwrap())
                .unwrap();
        assert_eq!(decoded.trial_id, Some(trial_id));
        assert_eq!(decoded.binding_context, Some(binding));

        let failed = plans.handle(&Frame {
            kind: COMMAND_SET_NAME_BOUND,
            body: vec![0],
        });
        assert!(!failed.ok);
        assert_eq!(failed.trial_id, Some([0; 16]));
        assert_eq!(failed.binding_context, Some(Default::default()));
        let wire = control::encode_ack_with_identifiers(
            failed.command,
            failed.ok,
            failed.reason,
            failed.trial_id,
            failed.area_id,
            failed.binding_context,
        )
        .unwrap();
        let decoded =
            control::decode_ack(&control::read_frame(&mut std::io::Cursor::new(wire)).unwrap())
                .unwrap();
        assert_eq!(decoded.trial_id, Some([0; 16]));
        assert_eq!(decoded.binding_context, Some(Default::default()));
    }

    #[test]
    fn name_plan_отклоняется_если_максимальная_посылка_выше_mtu() {
        let mut plans = NamePlans::default();
        let mut frame = set_name("example.test");
        let prefix_len = 1 + "example.test".len() + 2;
        frame.body.truncate(prefix_len);
        frame.body.extend_from_slice(&plan_header(0, 4));
        frame.body.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        frame.body.extend_from_slice(&[0; 16]);
        frame
            .body
            .extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x01]);
        frame
            .body
            .extend_from_slice(&[0x00, 0x10, 0x00, 0x06, 0x00, 0x01, b'F', b'A', b'K', b'E']);
        frame
            .body
            .extend_from_slice(&[0x01, 0x01, 0x00, 0x0a, 0x00, 0x01, 0, 0, 1, 0, 0, 0, 0, 0]);
        let plan = Plan::parse_wire(&frame.body[prefix_len..]).unwrap();

        plans.r2o_set_send_maxlen(1);
        assert!(!plans.handle(&frame).ok);
        plans.r2o_set_send_maxlen(1500);
        let ack = plans.handle(&frame);
        assert!(ack.ok, "reason={} max_emit={}", ack.reason, plan.max_emit());
    }

    #[test]
    fn name_plan_rejects_ipid_zero_poison_like_plan_fits() {
        let host = "ipid-zero.test";
        let mut body = vec![host.len() as u8];
        body.extend_from_slice(host.as_bytes());
        body.extend_from_slice(&[SHAPE_MODERN, 4]);
        body.extend_from_slice(&plan_header(0, 3));
        body.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        body.extend_from_slice(&[0; 16]);
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x01]);
        // POISON: id=1, ttl=64, flags=POISON_IPID_ZERO, seq_shift=0.
        body.extend_from_slice(&[0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x40, 0x04]);
        body.extend_from_slice(&[0, 0, 0, 0]);

        let mut plans = NamePlans::default();
        let ack = plans.handle(&Frame {
            kind: COMMAND_SET_NAME,
            body,
        });
        assert_eq!(ack.reason, control::ACK_BAD_PLAN);
        assert!(!ack.ok);
        assert_eq!(plans.plans.len(), 0);
    }

    #[test]
    fn set_addr_accepts_measured_shapes_and_rejects_unmeasured() {
        let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let mut plans = NamePlans::default();
        let command = encode_set_addr(address, SHAPE_ECH_TCP, &tls_plan_records([0x66; 16]))
            .expect("ECH_TCP — измеренная форма адресной привязки");
        let frame = control::read_frame(&mut std::io::Cursor::new(command)).unwrap();
        assert!(plans.handle(&frame).ok);

        for shape in [0_u8, 4, 7] {
            let mut body = vec![4];
            body.extend_from_slice(&[198, 51, 100, 2]);
            body.extend_from_slice(&[0; 12]);
            body.push(shape);
            body.push(0); // заведомо негодный план: отказ должен прийти раньше разбора
            let ack = plans.handle(&Frame {
                kind: COMMAND_SET_ADDR,
                body,
            });
            assert!(!ack.ok, "shape {shape} не должен приниматься");
            assert_eq!(ack.reason, control::ACK_BAD_ARGS);
        }
    }

    #[test]
    fn адресные_планы_разделены_по_форме_и_удаляются_точечно() {
        let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let mut plans = NamePlans::default();
        for (shape, id) in [(SHAPE_MODERN, [0x31; 16]), (SHAPE_LEGACY, [0x42; 16])] {
            let command = encode_set_addr(address, shape, &tls_plan_records(id)).unwrap();
            let frame = control::read_frame(&mut std::io::Cursor::new(command)).unwrap();
            assert!(plans.handle(&frame).ok);
        }
        assert_eq!(plans.addr_plans.len(), 2);

        let delete = encode_delete_addr(address, SHAPE_MODERN).unwrap();
        let delete = control::read_frame(&mut std::io::Cursor::new(delete)).unwrap();
        assert_eq!(delete.kind, COMMAND_DEL_ADDR);
        assert!(plans.handle(&delete).ok);
        assert_eq!(plans.addr_plans.len(), 1);
        assert!(plans.addr_plans.contains_key(&super::AddrPlanKey {
            address: address.into(),
            shape: SHAPE_LEGACY,
        }));

        let mut malformed = delete;
        malformed.kind = COMMAND_SET_ADDR;
        malformed.body[5] = 1;
        malformed
            .body
            .extend_from_slice(&tls_plan_records([0x53; 16]));
        assert_eq!(plans.handle(&malformed).reason, control::ACK_BAD_ARGS);
    }

    #[test]
    fn адресный_tls_план_работает_без_sni_и_не_подменяет_форму_имени() {
        let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let mut plans = NamePlans::default();
        let command =
            encode_set_addr(address, SHAPE_MODERN, &tls_plan_records([0x61; 16])).unwrap();
        let frame = control::read_frame(&mut std::io::Cursor::new(command)).unwrap();
        assert!(plans.handle(&frame).ok);

        assert_eq!(
            plans.select(&tcp_tls_packet("")).map(|plan| plan.id),
            Some([0x61; 16])
        );

        let mut mismatched_name = set_name("example.test");
        mismatched_name.body[1 + b"example.test".len()] = SHAPE_LEGACY;
        assert!(plans.handle(&mismatched_name).ok);
        assert!(plans.select(&tcp_tls_packet("example.test")).is_none());
        assert!(plans.select(&tcp_tls_packet("other.test")).is_some());
    }

    #[test]
    fn дедушкина_именная_привязка_совпадает_с_любой_tls_формой() {
        let mut plans = NamePlans::default();
        let mut command = set_name("example.test");
        command.body[1 + b"example.test".len()] = SHAPE_GRANDFATHER;
        assert!(plans.handle(&command).ok);

        let modern = tcp_tls_packet("example.test");
        let mut legacy = modern.clone();
        let versions = [0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
        let versions_offset = legacy
            .windows(versions.len())
            .position(|window| window == versions)
            .unwrap();
        legacy[versions_offset + versions.len() - 1] = 0x03;
        for packet in [modern.clone(), legacy] {
            assert_eq!(plans.select(&packet).map(|plan| plan.id), Some([0; 16]));
        }
        let applied = plans.applied_event_for_packet(&modern, 57).unwrap();
        assert_eq!(applied.binding.shape, SHAPE_GRANDFATHER);

        let delete = control::read_frame(&mut std::io::Cursor::new(
            r2k_core::control::encode_delete_name("example.test", 6, SHAPE_GRANDFATHER, 4).unwrap(),
        ))
        .unwrap();
        assert!(plans.handle(&delete).ok);
        assert!(plans.select(&modern).is_none());
    }

    #[test]
    fn событие_применения_сохраняет_привязку_именного_tls_плана() {
        let mut plans = NamePlans::default();
        assert!(plans.handle(&set_name("example.test")).ok);
        let packet = tcp_tls_packet("example.test");

        let event = plans.applied_event_for_packet(&packet, 55).unwrap();

        assert_eq!(event.plan_id, [0; 16]);
        assert_eq!(event.execution_id, 55);
        assert_eq!(event.binding.kind, 1);
        assert_eq!(event.binding.family, 4);
        assert_eq!(event.binding.shape, SHAPE_MODERN);
        assert!(!event.binding.temporary);
    }

    #[test]
    fn событие_применения_сохраняет_привязку_именного_quic_плана() {
        let mut plans = NamePlans::default();
        assert!(plans.handle(&set_quic_name("example.com")).ok);
        let packet = udp_packet(
            include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin"),
            443,
        );

        let event = plans.applied_event_for_packet(&packet, 56).unwrap();

        assert_eq!(event.execution_id, 56);
        assert_eq!(event.binding.kind, 2);
        assert_eq!(event.binding.family, 4);
        assert_eq!(event.binding.shape, SHAPE_QUIC);
        assert!(!event.binding.temporary);
    }

    #[test]
    fn адресный_quic_план_проверяет_initial_и_возвращает_контекст() {
        use crate::netlink::R2O_NF_INET_POST_ROUTING;

        let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let name = "unlisted.example";
        let named = set_quic_name(name);
        let plan_records = named.body[3 + name.len()..].to_vec();
        let command = encode_set_addr(address, SHAPE_QUIC, &plan_records).unwrap();
        let frame = control::read_frame(&mut std::io::Cursor::new(command)).unwrap();
        let mut plans = NamePlans::default();
        assert!(plans.handle(&frame).ok);

        let initial = include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin");
        let packet = udp_packet(initial, 443);
        assert_eq!(plans.select(&packet).map(|plan| plan.qsplit), Some(1));
        let nonstandard_port = udp_packet(initial, 8443);
        assert_eq!(
            plans
                .select_with_quic_host_at_hook(
                    &nonstandard_port,
                    None,
                    Some(R2O_NF_INET_POST_ROUTING),
                )
                .map(|plan| plan.qsplit),
            Some(1)
        );
        assert!(
            plans
                .applied_event_for_packet_at_hook(
                    &nonstandard_port,
                    78,
                    Some(R2O_NF_INET_POST_ROUTING),
                )
                .is_some()
        );
        let applied = plans.applied_event_for_packet(&packet, 77).unwrap();
        assert_eq!(applied.execution_id, 77);
        assert_eq!(applied.binding.kind, 2);
        assert_eq!(applied.binding.shape, SHAPE_QUIC);
        assert_eq!(applied.binding.family, 4);
        assert!(!applied.binding.temporary);

        let mut invalid = packet;
        invalid[28] ^= 1;
        assert!(plans.select(&invalid).is_none());
    }

    #[test]
    fn план_суффикса_наследуется_поддоменом_и_не_совпадает_с_похожим_именем() {
        let suffix = "googlevideo.com";
        let mut body = vec![suffix.len() as u8];
        body.extend_from_slice(suffix.as_bytes());
        body.extend_from_slice(&[SHAPE_MODERN, 4]);
        body.extend_from_slice(&plan_header(0, 2));
        body.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        body.extend_from_slice(&[0x31; 16]);
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x01]);
        body.extend_from_slice(&[0xA1; 16]);

        let mut plans = NamePlans::default();
        let ack = plans.handle(&Frame {
            kind: COMMAND_SET_SUFFIX,
            body,
        });
        assert!(ack.ok, "SET_SUFFIX отвергнут: {}", ack.reason);
        assert_eq!(ack.area_id, Some([0xA1; 16]));

        assert_eq!(
            super::super::capture::tcp_hello_from_packet(&tcp_tls_packet("rr-new.googlevideo.com"))
                .unwrap()
                .host,
            Some(b"rr-new.googlevideo.com".to_vec())
        );
        assert_eq!(
            plans
                .select(&tcp_tls_packet("rr-new.googlevideo.com"))
                .map(|plan| plan.id),
            Some([0x31; 16])
        );
        assert!(
            plans
                .select(&tcp_tls_packet("evilgooglevideo.com"))
                .is_none()
        );

        let mut nested = vec![b"video.googlevideo.com".len() as u8];
        nested.extend_from_slice(b"video.googlevideo.com");
        nested.extend_from_slice(&[SHAPE_MODERN, 4]);
        nested.extend_from_slice(&plan_header(0, 2));
        nested.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        nested.extend_from_slice(&[0x42; 16]);
        nested.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x01]);
        nested.extend_from_slice(&[0xA2; 16]);
        assert!(
            plans
                .handle(&Frame {
                    kind: COMMAND_SET_SUFFIX,
                    body: nested
                })
                .ok
        );
        assert_eq!(
            plans
                .select(&tcp_tls_packet("rr-new.video.googlevideo.com"))
                .map(|plan| plan.id),
            Some([0x42; 16])
        );

        assert!(plans.handle(&set_name("rr-new.googlevideo.com")).ok);
        assert_eq!(
            plans
                .select(&tcp_tls_packet("rr-new.googlevideo.com"))
                .map(|plan| plan.id),
            Some([0; 16]),
            "точная привязка должна иметь приоритет над suffix-планом"
        );
    }

    #[test]
    fn shape_tcp_options_family_matches_c_and_v22_client_tcp_carries_them() {
        let options = [1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2];
        let hello = super::super::capture::tcp_hello_from_packet(&tcp_tls_packet_with_options(
            "opts.example",
            &options,
        ))
        .unwrap();
        assert_eq!(hello.tcp_options.as_deref(), Some(&options[..]));

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("r2o-control-opts-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server = ControlServer::open_with_profile(
            &path,
            u16::MAX as u32,
            control::WireProfile::V22,
            control::RELEASE_ID,
        )
        .unwrap();
        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(server.poll().unwrap().is_empty());
        assert_eq!(
            control::read_frame(&mut client).unwrap().kind,
            control::EVENT_PROTOCOL
        );

        // C: без снимка формы — NULL для обоих семейств и негодных семейств.
        assert!(server.shape_tcp_options_family(4).is_none());
        assert!(server.shape_tcp_options_family(6).is_none());
        assert!(server.shape_tcp_options_family(5).is_none());
        server.record_shape_tcp_options(4, &options);
        assert!(
            server.shape_tcp_options_family(4).is_none(),
            "опции без снимка формы не отдаются"
        );

        let shape_body = hello.shape_event_body().unwrap();
        assert!(server.observe_client_shape(&shape_body).unwrap().is_none());
        assert_eq!(server.shape_tcp_options_family(4), Some(&options[..]));
        assert!(server.shape_tcp_options_family(6).is_none());

        server
            .send_event(control::EVENT_CLIENT_SHAPE, &shape_body)
            .unwrap();
        let client_tcp = control::read_frame(&mut client).unwrap();
        assert_eq!(client_tcp.kind, control::EVENT_LEGACY_CLIENT_TCP);
        assert_eq!(
            &client_tcp.body[..control::KEY_LEN],
            &shape_body[..control::KEY_LEN]
        );
        assert_eq!(&client_tcp.body[control::KEY_LEN..], &options);
        let shape = control::read_frame(&mut client).unwrap();
        assert_eq!(shape.kind, control::EVENT_LEGACY_SHAPE);

        drop(client);
        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn tcp_timestamp_option_is_carried_with_captured_client_hello() {
        let no_timestamp =
            super::super::capture::tcp_hello_from_packet(&tcp_tls_packet("no-ts.example")).unwrap();
        assert_eq!(no_timestamp.tcp_has_timestamp, Some(false));
        let no_timestamp_frame = Frame {
            kind: control::EVENT_HELLO,
            body: no_timestamp.event_body(),
        };
        assert_eq!(
            control::decode_hello(&no_timestamp_frame)
                .unwrap()
                .tcp_has_timestamp,
            Some(false)
        );

        let mut with_timestamp = tcp_tls_packet("ts.example");
        let payload = with_timestamp[40..].to_vec();
        with_timestamp.truncate(40);
        with_timestamp.extend_from_slice(&[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2]);
        with_timestamp[32] = 8 << 4;
        let total_len = with_timestamp.len() + payload.len();
        with_timestamp[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        with_timestamp.extend_from_slice(&payload);

        let with_timestamp = super::super::capture::tcp_hello_from_packet(&with_timestamp).unwrap();
        assert_eq!(with_timestamp.tcp_has_timestamp, Some(true));
        let hello_frame = Frame {
            kind: control::EVENT_HELLO,
            body: with_timestamp.event_body(),
        };
        assert_eq!(
            control::decode_hello(&hello_frame)
                .unwrap()
                .tcp_has_timestamp,
            Some(true)
        );
        let shape_frame = Frame {
            kind: control::EVENT_CLIENT_SHAPE,
            body: with_timestamp.shape_event_body().unwrap(),
        };
        assert_eq!(
            control::decode_client_shape(&shape_frame)
                .unwrap()
                .tcp_has_timestamp,
            Some(true)
        );
    }

    #[test]
    fn исключение_снимает_suffix_только_для_точного_имени_и_удаляется() {
        let suffix = "googlevideo.com";
        let mut suffix_body = vec![suffix.len() as u8];
        suffix_body.extend_from_slice(suffix.as_bytes());
        suffix_body.extend_from_slice(&[SHAPE_MODERN, 4]);
        suffix_body.extend_from_slice(&plan_header(0, 2));
        suffix_body.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        suffix_body.extend_from_slice(&[0x31; 16]);
        suffix_body.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x01]);
        suffix_body.extend_from_slice(&[0xA3; 16]);

        let mut plans = NamePlans::default();
        assert!(
            plans
                .handle(&Frame {
                    kind: COMMAND_SET_SUFFIX,
                    body: suffix_body
                })
                .ok
        );
        let name = "failed.googlevideo.com";
        let mut bypass_body = vec![name.len() as u8];
        bypass_body.extend_from_slice(name.as_bytes());
        bypass_body.extend_from_slice(&[6, SHAPE_MODERN, 4]);
        bypass_body.extend_from_slice(&[0xA4; 16]);
        assert!(
            plans
                .handle(&Frame {
                    kind: COMMAND_SET_BYPASS,
                    body: bypass_body.clone()
                })
                .ok
        );

        assert!(plans.select(&tcp_tls_packet(name)).is_none());
        assert_eq!(
            plans
                .select(&tcp_tls_packet("other.googlevideo.com"))
                .map(|plan| plan.id),
            Some([0x31; 16])
        );

        assert!(
            plans
                .handle(&Frame {
                    kind: COMMAND_DEL_BYPASS,
                    body: bypass_body
                })
                .ok
        );
        assert_eq!(
            plans.select(&tcp_tls_packet(name)).map(|plan| plan.id),
            Some([0x31; 16])
        );

        let mut suffix_key = vec![suffix.len() as u8];
        suffix_key.extend_from_slice(suffix.as_bytes());
        suffix_key.extend_from_slice(&[6, SHAPE_MODERN, 4]);
        suffix_key.extend_from_slice(&[0xA5; 16]);
        assert!(
            plans
                .handle(&Frame {
                    kind: COMMAND_DEL_SUFFIX,
                    body: suffix_key
                })
                .ok
        );
        assert!(plans.select(&tcp_tls_packet(name)).is_none());
    }

    #[test]
    fn identified_area_command_requires_its_id_like_d2o() {
        let ack = NamePlans::default().handle(&Frame {
            kind: COMMAND_SET_BYPASS,
            body: Vec::new(),
        });
        assert!(!ack.ok);
        assert_eq!(ack.reason, control::ACK_BAD_ARGS);
        assert_eq!(ack.area_id, Some([0; 16]));
    }

    #[test]
    fn ctlsrv_command_differential_matches_c() {
        use std::fmt::Write as _;

        const TLS_PLAN: &[u8] = &[
            b'D', b'2', b'K', b'P', 0, 1, 0, 1, 0, 0, 0, 2, 0x00, 0x02, 0x00, 0x02, 6, 1, 0x01,
            0x00, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00,
        ];
        let host = b"RuTracker.org";
        let mut plans = NamePlans::with_capacity(16);
        let mut output = String::new();
        let mut run = |name: &str, kind: u16, body: Vec<u8>, output: &mut String| {
            let ack = plans.handle(&Frame { kind, body });
            writeln!(output, "{name} ok={}", u8::from(ack.ok)).unwrap();
        };

        let mut https = vec![host.len() as u8];
        https.extend_from_slice(host);
        https.extend_from_slice(&60_u32.to_be_bytes());
        run(
            "https",
            control::COMMAND_SET_HTTPS,
            https.clone(),
            &mut output,
        );
        run(
            "https_bad",
            control::COMMAND_SET_HTTPS,
            https[..https.len() - 1].to_vec(),
            &mut output,
        );
        let mut bad_name = https.clone();
        bad_name[1] = b' ';
        run(
            "https_bad_name",
            control::COMMAND_SET_HTTPS,
            bad_name,
            &mut output,
        );

        let mut set_name = vec![host.len() as u8];
        set_name.extend_from_slice(host);
        set_name.push(1);
        set_name.push(4);
        set_name.extend_from_slice(TLS_PLAN);
        run(
            "set_name",
            control::COMMAND_SET_NAME,
            set_name.clone(),
            &mut output,
        );
        run(
            "set_name_bad_plan",
            control::COMMAND_SET_NAME,
            set_name[..set_name.len() - 1].to_vec(),
            &mut output,
        );

        let mut delete_name = vec![host.len() as u8];
        delete_name.extend_from_slice(host);
        delete_name.extend_from_slice(&[6, 1, 4]);
        run(
            "delete_name",
            control::COMMAND_DEL_NAME,
            delete_name.clone(),
            &mut output,
        );
        run(
            "delete_name_again",
            control::COMMAND_DEL_NAME,
            delete_name,
            &mut output,
        );

        let mut bad_family = set_name;
        bad_family[1 + host.len() + 1] = 5;
        run(
            "set_name_bad_family",
            control::COMMAND_SET_NAME,
            bad_family,
            &mut output,
        );

        if let Ok(path) = std::env::var("R2O_CTLSRV_COMMAND_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert!(output.contains("set_name ok=1\n"));
        assert!(output.contains("set_name_bad_plan ok=0\n"));
        assert!(output.contains("set_name_bad_family ok=0\n"));
    }

    #[test]
    fn binding_control_differential_matches_c() {
        use r2k_core::control::{COMMAND_DEL_NAME_BOUND, COMMAND_SET_NAME};
        use std::fmt::Write as _;

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        fn send_case(
            output: &mut String,
            label: &str,
            name: &str,
            transport: u8,
            binding: BindingContext,
        ) {
            match r2k_core::control::encode_delete_name_bound(name, transport, binding) {
                Ok(frame) => {
                    writeln!(output, "send {label} rc=0 bytes={}", hex(&frame)).unwrap();
                }
                Err(_) => writeln!(output, "send {label} rc=-1").unwrap(),
            }
        }
        fn read_case(output: &mut String, label: &str, context: &[u8]) {
            match super::read_binding_context(context) {
                Some(binding) => {
                    writeln!(
                        output,
                        "read {label} rc=0 gen={:016x} kind={} family={} shape={} temp={} epoch={}",
                        binding.generation,
                        binding.kind,
                        binding.family,
                        binding.shape,
                        u8::from(binding.temporary),
                        hex(&binding.epoch)
                    )
                    .unwrap();
                }
                None => writeln!(output, "read {label} rc=-1").unwrap(),
            }
        }
        fn binding(
            generation: u64,
            kind: u8,
            family: u8,
            shape: u8,
            temporary: bool,
            epoch: [u8; 16],
        ) -> BindingContext {
            BindingContext {
                generation,
                kind,
                family,
                shape,
                temporary,
                epoch,
            }
        }
        fn delete_body(name: &[u8], transport: u8, binding: &BindingContext) -> Vec<u8> {
            let mut body = Vec::with_capacity(2 + name.len() + 28);
            body.push(name.len() as u8);
            body.extend_from_slice(name);
            body.push(transport);
            body.extend_from_slice(&binding.generation.to_be_bytes());
            body.extend_from_slice(&[
                binding.kind,
                binding.family,
                binding.shape,
                u8::from(binding.temporary),
            ]);
            body.extend_from_slice(&binding.epoch);
            body
        }
        fn install_http(plans: &mut NamePlans) -> BindingContext {
            let host = b"example.test";
            let mut records = plan_header(11, 2);
            records.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
            records.extend_from_slice(&[0x41; 16]);
            records.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x04]);
            let mut body = vec![host.len() as u8];
            body.extend_from_slice(host);
            body.extend_from_slice(&[SHAPE_HTTP, 4]);
            body.extend_from_slice(&records);
            let ack = plans.handle(&Frame {
                kind: COMMAND_SET_NAME,
                body,
            });
            assert!(ack.ok, "HTTP SET_NAME должен установиться");
            ack.binding_context.expect("HTTP SET_NAME ACK binding")
        }
        fn delete_context_case(
            output: &mut String,
            label: &str,
            name: &[u8],
            transport: u8,
            mutate: impl FnOnce(&mut [u8; 28]),
        ) {
            let mut plans = NamePlans::with_capacity(16);
            let installed = install_http(&mut plans);
            let mut body = delete_body(name, transport, &installed);
            let start = body.len() - 28;
            let mut context: [u8; 28] = body[start..].try_into().unwrap();
            mutate(&mut context);
            body[start..].copy_from_slice(&context);
            let ack = plans.handle(&Frame {
                kind: COMMAND_DEL_NAME_BOUND,
                body,
            });
            writeln!(
                output,
                "del {label} ok={} live={}",
                u8::from(ack.ok),
                plans.r2o_plan_count()
            )
            .unwrap();
        }
        fn delete_case(
            output: &mut String,
            label: &str,
            name: &[u8],
            transport: u8,
            mutate: impl FnOnce(&mut BindingContext),
            context_delta: i32,
        ) {
            let mut plans = NamePlans::with_capacity(16);
            let installed = install_http(&mut plans);
            assert_eq!(plans.r2o_plan_count(), 1);
            let mut binding = installed;
            mutate(&mut binding);
            let mut body = delete_body(name, transport, &binding);
            if context_delta < 0 {
                body.pop();
            } else if context_delta > 0 {
                body.push(0);
            }
            let ack = plans.handle(&Frame {
                kind: COMMAND_DEL_NAME_BOUND,
                body,
            });
            writeln!(
                output,
                "del {label} ok={} live={}",
                u8::from(ack.ok),
                plans.r2o_plan_count()
            )
            .unwrap();
        }

        let mut output = String::new();
        let epoch_a = [0xAB; 16];
        let epoch_seq: [u8; 16] = std::array::from_fn(|index| index as u8);
        let name255 = "n".repeat(255);
        let name256 = "n".repeat(256);

        // C `d2k_link_del_name_bound`: точные байты кадра и отказы отправителя.
        send_case(
            &mut output,
            "name1_tcp",
            "a",
            6,
            binding(1, 1, 4, 1, false, epoch_a),
        );
        send_case(
            &mut output,
            "name255_udp",
            &name255,
            17,
            binding(0x1122_3344_5566_7788, 1, 6, 13, false, epoch_seq),
        );
        send_case(
            &mut output,
            "name0",
            "",
            6,
            binding(1, 1, 4, 1, false, epoch_a),
        );
        send_case(
            &mut output,
            "name256",
            &name256,
            6,
            binding(1, 1, 4, 1, false, epoch_a),
        );
        send_case(
            &mut output,
            "transport0",
            "a",
            0,
            binding(1, 1, 4, 1, false, epoch_a),
        );
        send_case(
            &mut output,
            "transport5",
            "a",
            5,
            binding(1, 1, 4, 1, false, epoch_a),
        );
        send_case(
            &mut output,
            "generation0",
            "a",
            6,
            binding(0, 1, 4, 1, false, epoch_a),
        );
        send_case(
            &mut output,
            "epoch0",
            "a",
            6,
            binding(1, 1, 4, 1, false, [0; 16]),
        );
        send_case(
            &mut output,
            "kind0",
            "a",
            6,
            binding(1, 0, 4, 1, false, epoch_a),
        );
        send_case(
            &mut output,
            "kind2",
            "a",
            6,
            binding(1, 2, 4, 1, false, epoch_a),
        );
        send_case(
            &mut output,
            "temporary",
            "a",
            6,
            binding(1, 1, 4, 1, true, epoch_a),
        );
        send_case(
            &mut output,
            "family0_shape0",
            "a",
            6,
            binding(1, 1, 0, 0, false, epoch_a),
        );
        send_case(
            &mut output,
            "shape7",
            "a",
            6,
            binding(1, 1, 4, 7, false, epoch_a),
        );
        send_case(
            &mut output,
            "shape14",
            "a",
            6,
            binding(1, 1, 4, 14, false, epoch_a),
        );
        send_case(
            &mut output,
            "generation_max",
            "a",
            6,
            binding(u64::MAX, 1, 6, 13, false, epoch_seq),
        );

        // C `d2k_ctl_binding_read`: длина, поля и границы.
        let mut base = [0_u8; 28];
        base[..8].copy_from_slice(&0x1122_3344_5566_7788_u64.to_be_bytes());
        base[8] = 1;
        base[9] = 4;
        base[10] = 1;
        base[11] = 0;
        base[12..].copy_from_slice(&epoch_seq);
        read_case(&mut output, "len27", &base[..27]);
        read_case(&mut output, "len28_base", &base);
        let mut longer = base.to_vec();
        longer.push(0);
        read_case(&mut output, "len29", &longer);
        for (label, index, value) in [
            ("kind0", 8, 0_u8),
            ("kind4", 8, 4),
            ("kind5", 8, 5),
            ("family0", 9, 0),
            ("family4", 9, 4),
            ("family6", 9, 6),
            ("family5", 9, 5),
            ("family255", 9, 255),
            ("shape0", 10, 0),
            ("shape7", 10, 7),
            ("shape13", 10, 13),
            ("shape14", 10, 14),
            ("shape255", 10, 255),
            ("temp0", 11, 0),
            ("temp1", 11, 1),
            ("temp2", 11, 2),
            ("temp255", 11, 255),
        ] {
            let mut context = base;
            context[index] = value;
            read_case(&mut output, label, &context);
        }
        let mut unknown = base;
        unknown[..8].fill(0);
        read_case(&mut output, "generation0", &unknown);
        let mut no_epoch = base;
        no_epoch[12..].fill(0);
        read_case(&mut output, "epoch0", &no_epoch);

        // Приёмник DEL_NAME_BOUND: ACK и снятие/неснятие записи.
        delete_case(&mut output, "match", b"example.test", 6, |_| {}, 0);
        delete_case(
            &mut output,
            "generation_plus1",
            b"example.test",
            6,
            |binding| binding.generation += 1,
            0,
        );
        delete_case(
            &mut output,
            "generation0",
            b"example.test",
            6,
            |binding| binding.generation = 0,
            0,
        );
        delete_case(
            &mut output,
            "epoch_changed",
            b"example.test",
            6,
            |binding| binding.epoch[15] ^= 1,
            0,
        );
        delete_case(
            &mut output,
            "epoch0",
            b"example.test",
            6,
            |binding| binding.epoch = [0; 16],
            0,
        );
        delete_case(
            &mut output,
            "kind0",
            b"example.test",
            6,
            |binding| binding.kind = 0,
            0,
        );
        delete_case(
            &mut output,
            "kind2",
            b"example.test",
            6,
            |binding| binding.kind = 2,
            0,
        );
        delete_case(
            &mut output,
            "temporary",
            b"example.test",
            6,
            |binding| binding.temporary = true,
            0,
        );
        delete_case(
            &mut output,
            "family0",
            b"example.test",
            6,
            |binding| binding.family = 0,
            0,
        );
        delete_case(
            &mut output,
            "family6",
            b"example.test",
            6,
            |binding| binding.family = 6,
            0,
        );
        delete_case(
            &mut output,
            "shape0",
            b"example.test",
            6,
            |binding| binding.shape = 0,
            0,
        );
        delete_case(
            &mut output,
            "shape13",
            b"example.test",
            6,
            |binding| binding.shape = 13,
            0,
        );
        delete_case(&mut output, "transport17", b"example.test", 17, |_| {}, 0);
        delete_case(&mut output, "name_other", b"other.test", 6, |_| {}, 0);
        delete_case(&mut output, "name_upper", b"EXAMPLE.TEST", 6, |_| {}, 0);
        delete_case(
            &mut output,
            "invalid_kind5",
            b"example.test",
            6,
            |binding| binding.kind = 5,
            0,
        );
        delete_case(
            &mut output,
            "invalid_family5",
            b"example.test",
            6,
            |binding| binding.family = 5,
            0,
        );
        delete_case(
            &mut output,
            "invalid_shape14",
            b"example.test",
            6,
            |binding| binding.shape = 14,
            0,
        );
        delete_context_case(
            &mut output,
            "invalid_temp2",
            b"example.test",
            6,
            |context| context[11] = 2,
        );
        delete_case(
            &mut output,
            "invalid_transport0",
            b"example.test",
            0,
            |_| {},
            0,
        );
        delete_case(&mut output, "invalid_len27", b"example.test", 6, |_| {}, -1);
        delete_case(&mut output, "invalid_len29", b"example.test", 6, |_| {}, 1);
        delete_case(&mut output, "invalid_name0", b"", 6, |_| {}, 0);
        delete_case(
            &mut output,
            "invalid_name256",
            name256.as_bytes(),
            6,
            |_| {},
            0,
        );

        if let Ok(path) = std::env::var("R2O_BINDING_CONTROL_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert!(output.contains("send name1_tcp rc=0 bytes="));
        assert!(output.contains("read shape14 rc=-1\n"));
        assert!(output.contains("del match ok=1 live=0\n"));
        assert!(output.contains("del generation_plus1 ok=1 live=1\n"));
    }

    #[test]
    fn http80_https_differential_matches_c() {
        use std::fmt::Write as _;

        let now = Instant::now();
        let mut output = String::new();
        let mut plans = NamePlans::with_capacity(16);

        fn set_https(
            plans: &mut NamePlans,
            label: &str,
            name: &[u8],
            ttl: u32,
            now: Instant,
            output: &mut String,
        ) {
            let mut body = Vec::with_capacity(name.len() + 5);
            body.push(name.len() as u8);
            body.extend_from_slice(name);
            body.extend_from_slice(&ttl.to_be_bytes());
            let (ok, _) = plans.set_https_at(&body, now);
            if label != "filler" && label != "tie_filler" {
                writeln!(output, "set {label} rc={}", if ok { 0 } else { -1 }).unwrap();
            }
        }

        fn has(plans: &NamePlans, label: &str, name: &[u8], at: Instant, output: &mut String) {
            writeln!(
                output,
                "{label}={}",
                u8::from(plans.has_verified_https(name, at))
            )
            .unwrap();
        }

        set_https(
            &mut plans,
            "example",
            b"Example.COM.",
            7200,
            now,
            &mut output,
        );
        has(
            &plans,
            "example_now",
            b"example.com",
            now + Duration::from_nanos(1),
            &mut output,
        );
        has(
            &plans,
            "example_case",
            b"EXAMPLE.com.",
            now + Duration::from_nanos(1),
            &mut output,
        );
        has(
            &plans,
            "example_last",
            b"example.com",
            now + Duration::from_secs(7199),
            &mut output,
        );
        has(
            &plans,
            "example_expired",
            b"example.com",
            now + Duration::from_secs(7200),
            &mut output,
        );

        set_https(
            &mut plans,
            "single_label",
            b"localhost",
            100,
            now,
            &mut output,
        );
        has(
            &plans,
            "single_label",
            b"localhost",
            now + Duration::from_nanos(1),
            &mut output,
        );
        set_https(&mut plans, "numeric", b"1.2.3.4", 100, now, &mut output);
        has(
            &plans,
            "numeric",
            b"1.2.3.4",
            now + Duration::from_nanos(1),
            &mut output,
        );
        set_https(&mut plans, "dash", b"-bad", 100, now, &mut output);
        has(
            &plans,
            "dash",
            b"-bad",
            now + Duration::from_nanos(1),
            &mut output,
        );
        set_https(&mut plans, "empty_label", b"a..b", 100, now, &mut output);
        has(
            &plans,
            "empty_label",
            b"a..b",
            now + Duration::from_nanos(1),
            &mut output,
        );
        set_https(
            &mut plans,
            "invalid_char",
            b"bad_name",
            100,
            now,
            &mut output,
        );
        set_https(&mut plans, "empty", b"", 100, now, &mut output);

        set_https(&mut plans, "gone_first", b"gone", 100, now, &mut output);
        set_https(&mut plans, "gone_remove", b"gone", 0, now, &mut output);
        has(
            &plans,
            "removed",
            b"gone",
            now + Duration::from_nanos(1),
            &mut output,
        );
        set_https(&mut plans, "up_first", b"up", 100, now, &mut output);
        set_https(&mut plans, "up_second", b"up", 1000, now, &mut output);
        has(
            &plans,
            "updated",
            b"up",
            now + Duration::from_secs(500),
            &mut output,
        );

        set_https(
            &mut plans,
            "clamped",
            b"clamped",
            1_000_000_000,
            now,
            &mut output,
        );
        has(
            &plans,
            "clamped_last",
            b"clamped",
            now + Duration::from_secs(604_799),
            &mut output,
        );
        has(
            &plans,
            "clamped_expired",
            b"clamped",
            now + Duration::from_secs(604_800),
            &mut output,
        );

        let mut plans = NamePlans::with_capacity(16);
        for index in 0..256_u32 {
            let name = format!("n{index}");
            set_https(
                &mut plans,
                "filler",
                name.as_bytes(),
                100 + index,
                now,
                &mut output,
            );
        }
        set_https(&mut plans, "overflow", b"overflow", 500, now, &mut output);
        has(
            &plans,
            "n0",
            b"n0",
            now + Duration::from_nanos(1),
            &mut output,
        );
        has(
            &plans,
            "n1",
            b"n1",
            now + Duration::from_nanos(1),
            &mut output,
        );
        has(
            &plans,
            "overflow",
            b"overflow",
            now + Duration::from_nanos(1),
            &mut output,
        );

        set_https(&mut plans, "n5_remove", b"n5", 0, now, &mut output);
        set_https(&mut plans, "late", b"late", 50, now, &mut output);
        set_https(&mut plans, "overflow2", b"overflow2", 600, now, &mut output);
        has(
            &plans,
            "late",
            b"late",
            now + Duration::from_nanos(1),
            &mut output,
        );
        has(
            &plans,
            "overflow2",
            b"overflow2",
            now + Duration::from_nanos(1),
            &mut output,
        );
        has(
            &plans,
            "n1_after",
            b"n1",
            now + Duration::from_nanos(1),
            &mut output,
        );

        let mut plans = NamePlans::with_capacity(16);
        for index in 0..256_u32 {
            let name = format!("e{index}");
            set_https(
                &mut plans,
                "tie_filler",
                name.as_bytes(),
                100,
                now,
                &mut output,
            );
        }
        set_https(
            &mut plans,
            "tie_overflow",
            b"tie-overflow",
            100,
            now,
            &mut output,
        );
        has(
            &plans,
            "tie_e0",
            b"e0",
            now + Duration::from_nanos(1),
            &mut output,
        );
        has(
            &plans,
            "tie_e1",
            b"e1",
            now + Duration::from_nanos(1),
            &mut output,
        );
        has(
            &plans,
            "tie_overflow",
            b"tie-overflow",
            now + Duration::from_nanos(1),
            &mut output,
        );

        if let Ok(path) = std::env::var("R2O_HTTP80_HTTPS_DIFF_OUTPUT") {
            std::fs::write(path, &output).unwrap();
        }
        assert!(output.contains("single_label=1\n"));
        assert!(output.contains("n0=0\n"));
        assert!(output.contains("late=0\n"));
        assert!(output.contains("tie_e0=0\n"));
    }

    #[test]
    fn set_https_command_accepts_an_exact_name_with_a_bounded_ttl() {
        let mut plans = NamePlans::default();
        let mut body = vec![b"example.test".len() as u8];
        body.extend_from_slice(b"example.test");
        body.extend_from_slice(&21_600_u32.to_be_bytes());

        let ack = plans.handle(&Frame { kind: 0x0090, body });

        assert!(ack.ok, "HTTPS cache command was rejected: {}", ack.reason);
        let now = std::time::Instant::now();
        assert!(plans.has_verified_https(b"EXAMPLE.TEST", now));
        assert!(!plans.has_verified_https(b"sub.example.test", now));
        assert!(!plans.has_verified_https(b"example.test", now + Duration::from_secs(21_601)));

        let mut remove = vec![b"example.test".len() as u8];
        remove.extend_from_slice(b"example.test");
        remove.extend_from_slice(&0_u32.to_be_bytes());
        assert!(
            plans
                .handle(&Frame {
                    kind: control::COMMAND_SET_HTTPS,
                    body: remove,
                })
                .ok
        );
        assert!(!plans.has_verified_https(b"example.test", now));

        // TTL больше семи суток C-датапат обрезает, а не отвергает.
        let mut long = vec![b"long.example.test".len() as u8];
        long.extend_from_slice(b"long.example.test");
        long.extend_from_slice(&u32::MAX.to_be_bytes());
        let ack = plans.handle(&Frame {
            kind: control::COMMAND_SET_HTTPS,
            body: long,
        });
        assert!(ack.ok, "long HTTPS TTL was rejected: {}", ack.reason);
        let now = std::time::Instant::now();
        let bounded = u64::from(control::MAX_HTTPS_TTL_SECONDS);
        assert!(plans.has_verified_https(
            b"long.example.test",
            now + Duration::from_secs(bounded - 60)
        ));
        assert!(!plans.has_verified_https(
            b"long.example.test",
            now + Duration::from_secs(bounded + 60)
        ));
    }

    #[test]
    fn discord_voice_class_plan_matches_only_discord_voice_requests() {
        let mut plans = NamePlans::default();
        let mut body = vec![b"@discord-voice".len() as u8];
        body.extend_from_slice(b"@discord-voice");
        body.extend_from_slice(&[SHAPE_VOICE, 4]);
        body.extend_from_slice(&plan_header(1, 2));
        body.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        body.extend_from_slice(&[0; 16]);
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x11, 0x03]);
        let ack = plans.handle(&Frame {
            kind: COMMAND_SET_NAME,
            body,
        });
        assert!(ack.ok, "@discord-voice plan was rejected: {}", ack.reason);

        let mut discord_stun = vec![0; 20];
        discord_stun[..8].copy_from_slice(&[0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
        let mut discord_stun = udp_packet(&discord_stun, 50004);
        assert!(plans.select(&discord_stun).is_some());
        discord_stun[22..24].copy_from_slice(&3478_u16.to_be_bytes());
        assert!(plans.select(&discord_stun).is_none());
    }

    #[test]
    fn generic_addr_probe_accepts_voice_wildcard_like_d2o() {
        let mut plans = NamePlans::default();
        let mut key = [0u8; control::KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 1]);
        key[17..21].copy_from_slice(&[198, 51, 100, 2]);
        key[35..37].copy_from_slice(&3478_u16.to_be_bytes());
        key[37] = 17;
        let trial_id = [0x21; 16];
        let mut plan = plan_header(1, 2);
        plan.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        plan.extend_from_slice(&[0x31; 16]);
        plan.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 17, r2k_core::plan::PROTO_VOICE]);

        let mut body = key.to_vec();
        body.extend_from_slice(&trial_id);
        body.extend_from_slice(&1000_u32.to_be_bytes());
        body.extend_from_slice(&plan);
        let ack = plans.handle(&Frame {
            kind: control::COMMAND_SET_ADDR_PROBE,
            body,
        });
        assert!(ack.ok, "voice wildcard rejected: {}", ack.reason);
        assert_eq!(plans.voice_addr_probes.len(), 1);

        let request = r2k_core::stun::binding_request([7; 12]);
        let packet = udp_packet(&request, 3478);
        assert_eq!(
            plans.select(&packet).map(|selected| selected.id),
            Some([0x31; 16])
        );

        // Чужой trial не снимает запись, но DEL остаётся идемпотентным OK.
        let mut wrong_trial = key.to_vec();
        wrong_trial.extend_from_slice(&[0x22; 16]);
        let ack = plans.handle(&Frame {
            kind: control::COMMAND_DEL_ADDR_PROBE,
            body: wrong_trial,
        });
        assert!(ack.ok);
        assert_eq!(plans.voice_addr_probes.len(), 1);

        let mut delete = key.to_vec();
        delete.extend_from_slice(&trial_id);
        let ack = plans.handle(&Frame {
            kind: control::COMMAND_DEL_ADDR_PROBE,
            body: delete,
        });
        assert!(ack.ok);
        assert!(plans.voice_addr_probes.is_empty());
    }

    #[test]
    fn generic_addr_probe_accepts_any_plan_and_exact_voice() {
        fn key(source_port: u16) -> [u8; control::KEY_LEN] {
            let mut key = [0u8; control::KEY_LEN];
            key[0] = 4;
            key[1..5].copy_from_slice(&[192, 0, 2, 1]);
            key[17..21].copy_from_slice(&[198, 51, 100, 2]);
            key[33..35].copy_from_slice(&source_port.to_be_bytes());
            key[35..37].copy_from_slice(&3478_u16.to_be_bytes());
            key[37] = 17;
            key
        }
        fn plan(id: [u8; 16], proto: u8) -> Vec<u8> {
            let mut plan = plan_header(1, 2);
            plan.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
            plan.extend_from_slice(&id);
            plan.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 17, proto]);
            plan
        }
        let mut plans = NamePlans::default();
        let request = r2k_core::stun::binding_request([7; 12]);

        // Точный voice-порт generic-командой: C хранит его в probes[] и
        // находит как find_addr_probe, так и find_voice_probe.
        let voice_key = key(50_000);
        let voice_trial = [0x24; 16];
        let mut body = voice_key.to_vec();
        body.extend_from_slice(&voice_trial);
        body.extend_from_slice(&1000_u32.to_be_bytes());
        body.extend_from_slice(&plan([0x32; 16], r2k_core::plan::PROTO_VOICE));
        let ack = plans.handle(&Frame {
            kind: control::COMMAND_SET_ADDR_PROBE,
            body,
        });
        assert!(ack.ok, "exact voice rejected: {}", ack.reason);
        assert_eq!(plans.addr_probes.len(), 1);

        let mut packet = udp_packet(&request, 3478);
        packet[20..22].copy_from_slice(&50_000_u16.to_be_bytes());
        let selected = plans.select(&packet).expect("exact voice probe");
        assert_eq!(selected.id, [0x32; 16]);
        assert_eq!(plans.binding_for_plan(selected).unwrap().shape, SHAPE_VOICE);

        let mut other_port = packet.clone();
        other_port[20..22].copy_from_slice(&50_001_u16.to_be_bytes());
        assert!(plans.select(&other_port).is_none());

        // ANY-план (proto не 2/3) C принимает и отдаёт с shape=0.
        let any_key = key(50_002);
        let mut body = any_key.to_vec();
        body.extend_from_slice(&[0x25; 16]);
        body.extend_from_slice(&1000_u32.to_be_bytes());
        body.extend_from_slice(&plan([0x33; 16], 1));
        let ack = plans.handle(&Frame {
            kind: control::COMMAND_SET_ADDR_PROBE,
            body,
        });
        assert!(ack.ok, "ANY plan rejected: {}", ack.reason);
        assert_eq!(plans.addr_probes.len(), 2);

        let mut any_packet = udp_packet(&request, 3478);
        any_packet[20..22].copy_from_slice(&50_002_u16.to_be_bytes());
        let selected = plans.select(&any_packet).expect("ANY exact probe");
        assert_eq!(selected.id, [0x33; 16]);
        assert_eq!(plans.binding_for_plan(selected).unwrap().shape, 0);
        assert_eq!(super::MAX_FLOW_PROBES, 2048);
    }

    #[test]
    fn r2o_обычный_stun_получает_только_адресный_voice_план() {
        let r2o_server = Ipv4Addr::new(198, 51, 100, 2);
        let mut r2o_plan = plan_header(1, 2);
        r2o_plan.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        r2o_plan.extend_from_slice(&[0x25; 16]);
        r2o_plan.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 17, r2k_core::plan::PROTO_VOICE]);
        let command = encode_set_addr(IpAddr::V4(r2o_server), SHAPE_VOICE, &r2o_plan).unwrap();
        let command = control::read_frame(&mut std::io::Cursor::new(command)).unwrap();
        let mut plans = NamePlans::default();
        assert!(plans.handle(&command).ok);

        let request = r2k_core::stun::binding_request([7; 12]);
        let packet = udp_packet(&request, 3478);
        assert_eq!(plans.select(&packet).map(|plan| plan.id), Some([0x25; 16]));
        let applied = plans.applied_event_for_packet(&packet, 9).unwrap();
        assert_eq!(applied.plan_id, [0x25; 16]);
        assert_eq!(applied.binding.shape, SHAPE_VOICE);
        assert!(
            plans
                .select(&udp_packet("обычный UDP".as_bytes(), 3478))
                .is_none()
        );

        let mut other_server = packet;
        other_server[16..20].copy_from_slice(&[203, 0, 113, 5]);
        assert!(plans.select(&other_server).is_none());
    }

    #[test]
    fn временный_voice_план_совпадает_только_с_клиентом_и_точкой_сервера() {
        use std::net::{Ipv4Addr, SocketAddrV4};

        let r2o_client = Ipv4Addr::new(192, 0, 2, 1);
        let r2o_server = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 2), 50_004);
        let r2o_trial_id = [0x71; 16];
        let mut r2o_plan = plan_header(1, 2);
        r2o_plan.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        r2o_plan.extend_from_slice(&[0x23; 16]);
        r2o_plan.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 17, r2k_core::plan::PROTO_VOICE]);
        let r2o_command =
            encode_set_voice_addr_probe(r2o_client, r2o_server, 120_000, &r2o_plan, r2o_trial_id)
                .unwrap();
        let r2o_command = control::read_frame(&mut std::io::Cursor::new(r2o_command)).unwrap();
        let mut plans = NamePlans::default();
        let r2o_ack = plans.handle(&r2o_command);
        assert!(r2o_ack.ok);
        assert_eq!(r2o_ack.trial_id, Some(r2o_trial_id));

        let mut r2o_request = [0; 74];
        r2o_request[..4].copy_from_slice(&[0, 1, 0, 70]);
        r2o_request[4..8].copy_from_slice(&[1, 2, 3, 4]);
        let r2o_packet = udp_packet(&r2o_request, r2o_server.port());
        let r2o_selected = plans.select(&r2o_packet).unwrap();
        assert_eq!(r2o_selected.id, [0x23; 16]);
        let r2o_applied = plans.applied_event_for_packet(&r2o_packet, 7).unwrap();
        assert_eq!(r2o_applied.trial_id, r2o_trial_id);
        assert_eq!(r2o_applied.binding.kind, 2);
        assert_eq!(r2o_applied.binding.family, 4);
        assert_eq!(r2o_applied.binding.shape, SHAPE_VOICE);
        assert!(r2o_applied.binding.temporary);

        let mut r2o_other_client = r2o_packet.clone();
        r2o_other_client[12..16].copy_from_slice(&[192, 0, 2, 99]);
        assert!(plans.select(&r2o_other_client).is_none());
        assert!(plans.select(&udp_packet(&r2o_request, 50_005)).is_none());
    }

    #[test]
    fn обычный_stun_на_точной_voice_цели_получает_временный_план() {
        use std::net::{Ipv4Addr, SocketAddrV4};

        let client = Ipv4Addr::new(192, 0, 2, 1);
        let server = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 2), 3478);
        let trial_id = [0x72; 16];
        let mut plan = plan_header(1, 2);
        plan.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        plan.extend_from_slice(&[0x26; 16]);
        plan.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 17, r2k_core::plan::PROTO_VOICE]);
        let command =
            encode_set_voice_addr_probe(client, server, 120_000, &plan, trial_id).unwrap();
        let command = control::read_frame(&mut std::io::Cursor::new(command)).unwrap();
        let mut plans = NamePlans::default();
        assert!(plans.handle(&command).ok);

        let mut discovery = [0; 74];
        discovery[..4].copy_from_slice(&[0, 1, 0, 70]);
        let discovery_packet = udp_packet(&discovery, server.port());
        assert_eq!(plans.select(&discovery_packet).unwrap().id, [0x26; 16]);

        let request = r2k_core::stun::binding_request([0x19; 12]);
        let stun_packet = udp_packet(&request, server.port());
        let applied = plans.applied_event_for_packet(&stun_packet, 8).unwrap();
        assert_eq!(applied.plan_id, [0x26; 16]);
        assert_eq!(applied.trial_id, trial_id);
        assert!(applied.binding.temporary);
    }

    #[test]
    fn постоянный_voice_план_ограничен_адресом_сервера() {
        use std::net::Ipv4Addr;

        let r2o_server = Ipv4Addr::new(198, 51, 100, 2);
        let mut r2o_plan = plan_header(1, 2);
        r2o_plan.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        r2o_plan.extend_from_slice(&[0x24; 16]);
        r2o_plan.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 17, r2k_core::plan::PROTO_VOICE]);
        let r2o_command = encode_set_voice_addr(r2o_server, &r2o_plan).unwrap();
        let r2o_command = control::read_frame(&mut std::io::Cursor::new(r2o_command)).unwrap();
        let mut plans = NamePlans::default();
        assert!(plans.handle(&r2o_command).ok);

        let mut r2o_request = [0; 74];
        r2o_request[..4].copy_from_slice(&[0, 1, 0, 70]);
        r2o_request[4..8].copy_from_slice(&[1, 2, 3, 4]);
        let r2o_packet = udp_packet(&r2o_request, 50_004);
        assert_eq!(plans.select(&r2o_packet).unwrap().id, [0x24; 16]);
        let r2o_applied = plans.applied_event_for_packet(&r2o_packet, 8).unwrap();
        assert_eq!(r2o_applied.trial_id, [0; 16]);
        assert!(!r2o_applied.binding.temporary);

        let mut r2o_other_server = r2o_packet;
        r2o_other_server[16..20].copy_from_slice(&[203, 0, 113, 5]);
        assert!(plans.select(&r2o_other_server).is_none());
    }

    #[test]
    fn quic_name_plan_selects_only_its_authenticated_initial_sni() {
        let mut plans = NamePlans::default();
        let ack = plans.handle(&set_quic_name("example.com"));
        assert!(ack.ok, "QUIC plan was rejected: {}", ack.reason);

        let initial = include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin");
        let packet = udp_packet(initial, 443);
        assert_eq!(plans.select(&packet).map(|plan| plan.qsplit), Some(1));

        let mut corrupted = initial.to_vec();
        corrupted[600] ^= 1;
        assert!(plans.select(&udp_packet(&corrupted, 443)).is_none());
        assert!(plans.select(&udp_packet(initial, 8443)).is_none());
    }

    #[test]
    fn именной_quic_план_на_нестандартном_порту_требует_исходящий_hook() {
        use crate::netlink::{R2O_NF_INET_LOCAL_IN, R2O_NF_INET_POST_ROUTING};

        let mut plans = NamePlans::default();
        let ack = plans.handle(&set_quic_name("example.com"));
        assert!(ack.ok, "QUIC-план отклонён: {}", ack.reason);

        let initial = include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin");
        let packet = udp_packet(initial, 8443);
        assert_eq!(
            plans
                .select_with_quic_host_at_hook(
                    &packet,
                    Some(b"example.com"),
                    Some(R2O_NF_INET_POST_ROUTING),
                )
                .map(|plan| plan.qsplit),
            Some(1)
        );
        let applied = plans
            .applied_event_for_packet_at_hook(&packet, 88, Some(R2O_NF_INET_POST_ROUTING))
            .unwrap();
        assert_eq!(applied.execution_id, 88);
        assert_eq!(applied.binding.shape, SHAPE_QUIC);
        assert!(
            plans
                .select_with_quic_host_at_hook(
                    &packet,
                    Some(b"example.com"),
                    Some(R2O_NF_INET_LOCAL_IN),
                )
                .is_none()
        );
        assert!(
            plans
                .select_with_quic_host_at_hook(&packet, Some(b"example.com"), None)
                .is_none()
        );
    }

    #[test]
    fn временная_quic_привязка_проверяет_полный_поток_и_поколение() {
        use std::net::SocketAddr;

        let source: SocketAddr = "192.0.2.1:12345".parse().unwrap();
        let destination: SocketAddr = "198.51.100.2:443".parse().unwrap();
        let first_trial = [0x61; 16];
        let next_trial = [0x62; 16];
        let plan_id = [0x63; 16];
        let plan = quic_plan_records(plan_id);
        let command =
            control::encode_set_addr_probe(source, destination, 120_000, &plan, first_trial)
                .unwrap();
        let command = control::read_frame(&mut std::io::Cursor::new(command)).unwrap();
        let mut plans = NamePlans::default();
        let ack = plans.handle(&command);
        assert!(ack.ok);
        assert_eq!(ack.trial_id, Some(first_trial));

        let initial = include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin");
        let packet = udp_packet(initial, 443);
        assert_eq!(plans.select(&packet).map(|plan| plan.id), Some(plan_id));
        let applied = plans.applied_event_for_packet(&packet, 7).unwrap();
        assert_eq!(applied.trial_id, first_trial);
        assert_eq!(applied.plan_id, plan_id);
        assert_eq!(applied.binding.shape, SHAPE_QUIC);
        assert_eq!(applied.binding.kind, 2);
        assert!(applied.binding.temporary);

        let mut other_source_port = packet.clone();
        other_source_port[20..22].copy_from_slice(&12346_u16.to_be_bytes());
        assert!(plans.select(&other_source_port).is_none());
        let mut other_source = packet.clone();
        other_source[12..16].copy_from_slice(&[192, 0, 2, 9]);
        assert!(plans.select(&other_source).is_none());

        let next_plan_id = [0x64; 16];
        let second_command = control::encode_set_addr_probe(
            source,
            destination,
            120_000,
            &quic_plan_records(next_plan_id),
            next_trial,
        )
        .unwrap();
        let second_command =
            control::read_frame(&mut std::io::Cursor::new(second_command)).unwrap();
        assert!(!plans.handle(&second_command).ok);

        let delete = control::encode_delete_addr_probe(source, destination, first_trial).unwrap();
        let delete = control::read_frame(&mut std::io::Cursor::new(delete)).unwrap();
        assert!(plans.handle(&delete).ok);

        assert!(plans.handle(&second_command).ok);
        let stale_delete =
            control::encode_delete_addr_probe(source, destination, first_trial).unwrap();
        let stale_delete = control::read_frame(&mut std::io::Cursor::new(stale_delete)).unwrap();
        assert!(plans.handle(&stale_delete).ok);
        assert_eq!(
            plans.select(&packet).map(|plan| plan.id),
            Some(next_plan_id)
        );

        let delete = control::encode_delete_addr_probe(source, destination, next_trial).unwrap();
        let delete = control::read_frame(&mut std::io::Cursor::new(delete)).unwrap();
        assert!(plans.handle(&delete).ok);
        assert!(plans.select(&packet).is_none());
    }

    #[test]
    fn r2o_временная_quic_привязка_принимает_clearance_и_udplen() {
        use std::net::SocketAddr;

        let source: SocketAddr = "192.0.2.1:12345".parse().unwrap();
        let destination: SocketAddr = "198.51.100.2:443".parse().unwrap();
        let packet = udp_packet(
            include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin"),
            443,
        );
        let plans = [
            r2o_quic_clearance_plan_records([0x71; 16]),
            r2o_quic_udp_length_plan_records([0x72; 16]),
        ];
        for (index, records) in plans.iter().enumerate() {
            let trial_id = [0x73 + index as u8; 16];
            let command =
                control::encode_set_addr_probe(source, destination, 120_000, records, trial_id)
                    .unwrap();
            let command = control::read_frame(&mut std::io::Cursor::new(command)).unwrap();
            let mut active = NamePlans::default();
            let ack = active.handle(&command);
            assert!(ack.ok, "QUIC plan rejected: {}", ack.reason);
            assert!(active.select(&packet).is_some());
        }
    }

    #[test]
    fn http_probe_plan_matches_only_its_source_port_and_acknowledges_trial_id() {
        let host = b"example.test";
        let source_port = 40_123_u16;
        let trial_id = [0xabu8; 16];
        let mut plan = plan_header(11, 2);
        plan.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        plan.extend_from_slice(&[0x11; 16]);
        plan.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, r2k_core::plan::PROTO_HTTP]);
        let mut body = vec![host.len() as u8];
        body.extend_from_slice(host);
        body.extend_from_slice(&[SHAPE_HTTP, 4]);
        body.extend_from_slice(&source_port.to_be_bytes());
        body.extend_from_slice(&plan);
        body.extend_from_slice(&trial_id);

        let mut plans = NamePlans::default();
        let ack = plans.handle(&Frame {
            kind: COMMAND_SET_NAME_PROBE,
            body,
        });
        assert!(ack.ok, "HTTP probe plan was rejected: {}", ack.reason);
        assert_eq!(ack.trial_id, Some(trial_id));

        let packet = http_tcp_packet(host, source_port);
        assert_eq!(
            plans.select(&packet).map(|selected| selected.id),
            Some([0x11; 16])
        );
        let post = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 70000\r\n\r\n";
        let mut post_packet = packet[..40].to_vec();
        post_packet.extend_from_slice(post);
        let post_packet_len = post_packet.len() as u16;
        post_packet[2..4].copy_from_slice(&post_packet_len.to_be_bytes());
        assert_eq!(
            plans.select(&post_packet).map(|selected| selected.id),
            Some([0x11; 16]),
            "HTTP-план выбирается для POST с объявленным телом",
        );
        let applied = plans.applied_event_for_packet(&packet, 42).unwrap();
        assert_eq!(applied.plan_id, [0x11; 16]);
        assert_eq!(applied.trial_id, trial_id);
        assert_eq!(applied.execution_id, 42);
        assert!(applied.binding.temporary);
        assert!(applied.binding.is_known());
        assert_eq!(applied.binding.shape, SHAPE_HTTP);
        assert_eq!(
            u16::from_be_bytes([applied.key[33], applied.key[34]]),
            source_port
        );
        assert_eq!(u16::from_be_bytes([applied.key[35], applied.key[36]]), 80);
        assert!(
            plans
                .select(&http_tcp_packet(host, source_port + 1))
                .is_none()
        );
        assert!(
            plans
                .applied_event_for_packet(&http_tcp_packet(host, source_port + 1), 43)
                .is_none()
        );
    }

    #[test]
    fn permanent_http_set_ack_reports_exact_runtime_generation_and_epoch() {
        let host = b"example.test";
        let plan_id = [0x41; 16];
        let mut records = plan_header(11, 2);
        records.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        records.extend_from_slice(&plan_id);
        records.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, r2k_core::plan::PROTO_HTTP]);
        let mut body = vec![host.len() as u8];
        body.extend_from_slice(host);
        body.extend_from_slice(&[SHAPE_HTTP, 4]);
        body.extend_from_slice(&records);

        let mut plans = NamePlans::default();
        let first = plans.handle(&Frame {
            kind: COMMAND_SET_NAME,
            body: body.clone(),
        });
        assert!(first.ok);
        let first_binding = first.binding_context.expect("HTTP SET_NAME ACK context");
        assert!(first_binding.is_known());
        assert_eq!(first_binding.kind, 1);
        assert_eq!(first_binding.family, 4);
        assert_eq!(first_binding.shape, SHAPE_HTTP);
        assert!(!first_binding.temporary);

        let second = plans.handle(&Frame {
            kind: COMMAND_SET_NAME,
            body,
        });
        let second_binding = second.binding_context.expect("reinstalled ACK context");
        assert!(second_binding.generation > first_binding.generation);
        assert_eq!(second_binding.epoch, first_binding.epoch);
    }

    #[test]
    fn conditional_http_delete_preserves_replacements_and_removes_only_its_binding() {
        let host = "example.test";
        let plan_id = [0x41; 16];
        let mut records = plan_header(11, 2);
        records.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        records.extend_from_slice(&plan_id);
        records.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, r2k_core::plan::PROTO_HTTP]);
        let mut body = vec![host.len() as u8];
        body.extend_from_slice(host.as_bytes());
        body.extend_from_slice(&[SHAPE_HTTP, 4]);
        body.extend_from_slice(&records);

        let mut plans = NamePlans::default();
        let set_ack = plans.handle(&Frame {
            kind: COMMAND_SET_NAME,
            body,
        });
        let binding = set_ack.binding_context.expect("HTTP binding context");
        let installed_revision = plans.revision();
        let key = NamePlanKey {
            host: host.to_owned(),
            family: 4,
            shape: SHAPE_HTTP,
        };
        assert!(plans.plans.contains_key(&key));

        let stale = BindingContext {
            generation: binding.generation + 1,
            ..binding
        };
        let stale_delete = control::read_frame(&mut std::io::Cursor::new(
            control::encode_delete_name_bound(host, 6, stale).unwrap(),
        ))
        .unwrap();
        let stale_ack = plans.handle(&stale_delete);
        assert!(stale_ack.ok);
        assert_eq!(plans.revision(), installed_revision);
        assert!(plans.plans.contains_key(&key));

        let current_delete = control::read_frame(&mut std::io::Cursor::new(
            control::encode_delete_name_bound(host, 6, binding).unwrap(),
        ))
        .unwrap();
        let current_ack = plans.handle(&current_delete);
        assert!(current_ack.ok);
        assert_eq!(plans.revision(), installed_revision + 1);
        assert!(!plans.plans.contains_key(&key));
    }

    #[test]
    fn tls_probe_plan_matches_only_its_source_port_and_reports_temporary_applied() {
        let host = "example.test";
        let source_port = 50_000_u16;
        let trial_id = [0xabu8; 16];
        let probe_id = [0x33; 16];
        let mut plan = plan_header(11, 2);
        plan.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        plan.extend_from_slice(&probe_id);
        plan.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 1]);
        let mut body = vec![host.len() as u8];
        body.extend_from_slice(host.as_bytes());
        body.extend_from_slice(&[SHAPE_MODERN, 4]);
        body.extend_from_slice(&source_port.to_be_bytes());
        body.extend_from_slice(&plan);
        body.extend_from_slice(&trial_id);

        let mut plans = NamePlans::default();
        assert!(plans.handle(&set_name(host)).ok);
        let ack = plans.handle(&Frame {
            kind: COMMAND_SET_NAME_PROBE,
            body,
        });
        assert!(ack.ok, "TLS probe plan was rejected: {}", ack.reason);
        assert_eq!(ack.trial_id, Some(trial_id));

        let packet = tcp_tls_packet(host);
        assert_eq!(
            plans.select(&packet).map(|selected| selected.id),
            Some(probe_id)
        );
        let applied = plans.applied_event_for_packet(&packet, 44).unwrap();
        assert_eq!(applied.plan_id, probe_id);
        assert_eq!(applied.trial_id, trial_id);
        assert!(applied.binding.temporary);
        assert_eq!(applied.binding.shape, SHAPE_MODERN);

        let mut other_port = packet.clone();
        other_port[20..22].copy_from_slice(&(source_port + 1).to_be_bytes());
        assert_eq!(
            plans.select(&other_port).map(|selected| selected.id),
            Some([0; 16])
        );
        let applied = plans.applied_event_for_packet(&other_port, 45).unwrap();
        assert_eq!(applied.plan_id, [0; 16]);
        assert_eq!(applied.trial_id, [0; 16]);
        assert!(!applied.binding.temporary);

        let mut delete_body = vec![host.len() as u8];
        delete_body.extend_from_slice(host.as_bytes());
        delete_body.extend_from_slice(&[SHAPE_MODERN, 4]);
        delete_body.extend_from_slice(&source_port.to_be_bytes());
        assert!(
            plans
                .handle(&Frame {
                    kind: COMMAND_DEL_NAME_PROBE,
                    body: delete_body,
                })
                .ok
        );
        assert_eq!(
            plans.select(&packet).map(|selected| selected.id),
            Some([0; 16])
        );
    }

    #[test]
    fn clearing_disconnected_http_probes_keeps_the_permanent_plan() {
        let host = b"example.test";
        let source_port = 40_123_u16;
        let permanent_id = [0x22; 16];
        let probe_id = [0x33; 16];
        let mut permanent = plan_header(11, 2);
        permanent.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        permanent.extend_from_slice(&permanent_id);
        permanent.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, r2k_core::plan::PROTO_HTTP]);

        let mut permanent_body = vec![host.len() as u8];
        permanent_body.extend_from_slice(host);
        permanent_body.extend_from_slice(&[SHAPE_HTTP, 4]);
        permanent_body.extend_from_slice(&permanent);

        let mut probe_body = vec![host.len() as u8];
        probe_body.extend_from_slice(host);
        probe_body.extend_from_slice(&[SHAPE_HTTP, 4]);
        probe_body.extend_from_slice(&source_port.to_be_bytes());
        let mut probe = permanent.clone();
        probe[16..32].copy_from_slice(&probe_id);
        probe_body.extend_from_slice(&probe);
        probe_body.extend_from_slice(&[0xabu8; 16]);

        let mut plans = NamePlans::default();
        assert!(
            plans
                .handle(&Frame {
                    kind: COMMAND_SET_NAME,
                    body: permanent_body
                })
                .ok
        );
        assert!(
            plans
                .handle(&Frame {
                    kind: COMMAND_SET_NAME_PROBE,
                    body: probe_body
                })
                .ok
        );

        let packet = http_tcp_packet(host, source_port);
        assert_eq!(
            plans.select(&packet).map(|selected| selected.id),
            Some(probe_id)
        );
        plans.clear_probes();
        assert_eq!(
            plans.select(&packet).map(|selected| selected.id),
            Some(permanent_id)
        );
    }

    #[test]
    fn http_candidate_respects_source_port_like_d2o() {
        let mut plans = NamePlans::default();
        plans.plans.insert(
            NamePlanKey {
                host: "permanent.example".into(),
                family: 4,
                shape: SHAPE_HTTP,
            },
            InstalledPlan {
                plan: Plan::default(),
                generation: 1,
                last_used: std::cell::Cell::new(0),
            },
        );
        assert!(plans.has_http_candidate(4, 0));
        assert!(!plans.has_http_candidate(4, 40_000));

        plans.probes.insert(
            NameProbeKey {
                name: NamePlanKey {
                    host: "probe.example".into(),
                    family: 4,
                    shape: SHAPE_HTTP,
                },
                source_port: 40_000,
            },
            ProbePlan {
                plan: Plan::default(),
                trial_id: [0x44; 16],
                generation: 2,
                last_used: std::cell::Cell::new(0),
            },
        );
        assert!(plans.has_http_candidate(4, 40_000));
        assert!(!plans.has_http_candidate(6, 40_000));
    }

    #[test]
    fn shape_misses_count_known_name_with_wrong_tcp_shape() {
        let mut plans = NamePlans::default();
        assert!(
            plans
                .handle(&set_name_shape("example.test", SHAPE_LEGACY, [0x77; 16]))
                .ok
        );
        let packet = tcp_tls_packet("example.test");
        assert!(plans.select(&packet).is_none());
        assert_eq!(plans.r2o_shape_misses(), 1);
    }

    #[test]
    fn delete_name_probe_accepts_unknown_shape_like_d2o() {
        let mut plans = NamePlans::default();
        let mut body = vec![b"example.test".len() as u8];
        body.extend_from_slice(b"example.test");
        body.extend_from_slice(&[0, 4]);
        body.extend_from_slice(&40_000_u16.to_be_bytes());
        let ack = plans.handle(&Frame {
            kind: COMMAND_DEL_NAME_PROBE,
            body,
        });
        assert!(ack.ok);
        assert_eq!(ack.reason, control::ACK_OK);
    }

    #[test]
    fn plan_count_excludes_name_probes_like_d2o() {
        let mut plans = NamePlans::default();
        plans.probes.insert(
            NameProbeKey {
                name: NamePlanKey {
                    host: "probe.example".into(),
                    family: 4,
                    shape: SHAPE_MODERN,
                },
                source_port: 40_000,
            },
            ProbePlan {
                plan: Plan::default(),
                trial_id: [0x33; 16],
                generation: 1,
                last_used: std::cell::Cell::new(0),
            },
        );
        assert_eq!(plans.r2o_plan_count(), 0);
        assert_eq!(plans.exact_usage(), 1);
    }

    #[test]
    fn prune_expired_probes_matches_lazy_probe_drop() {
        let now = Instant::now();
        let mut plans = NamePlans::default();
        plans.addr_probes.insert(
            [0x11; control::KEY_LEN],
            AddrProbePlan {
                plan: Plan::default(),
                trial_id: [0x21; 16],
                generation: 1,
                expires: now - Duration::from_millis(1),
            },
        );
        plans.addr_probes.insert(
            [0x12; control::KEY_LEN],
            AddrProbePlan {
                plan: Plan::default(),
                trial_id: [0x22; 16],
                generation: 2,
                expires: now + Duration::from_secs(1),
            },
        );
        plans.voice_addr_probes.insert(
            VoiceProbeKey {
                client: Ipv4Addr::new(192, 0, 2, 1),
                server: Ipv4Addr::new(198, 51, 100, 2),
                server_port: 443,
            },
            VoiceProbePlan {
                plan: Plan::default(),
                trial_id: [0x23; 16],
                generation: 3,
                expires: now - Duration::from_millis(1),
            },
        );
        let revision = plans.revision();
        plans.prune_expired_probes(now);
        assert_eq!(plans.addr_probes.len(), 1);
        assert_eq!(plans.voice_addr_probes.len(), 0);
        assert_eq!(plans.revision(), revision.wrapping_add(1));
    }

    #[test]
    fn probe_count_counts_addr_and_voice_probes_like_d2o() {
        let now = std::time::Instant::now();
        let mut plans = NamePlans::default();
        plans.addr_probes.insert(
            [0x11; control::KEY_LEN],
            AddrProbePlan {
                plan: Plan::default(),
                trial_id: [0x21; 16],
                generation: 1,
                expires: now,
            },
        );
        plans.voice_addr_probes.insert(
            VoiceProbeKey {
                client: Ipv4Addr::new(192, 0, 2, 1),
                server: Ipv4Addr::new(198, 51, 100, 2),
                server_port: 443,
            },
            VoiceProbePlan {
                plan: Plan::default(),
                trial_id: [0x22; 16],
                generation: 2,
                expires: now,
            },
        );
        assert_eq!(plans.r2o_probe_count(now), 2);
        plans.clear_probes();
        assert_eq!(plans.r2o_probe_count(now), 0);
    }

    #[test]
    fn clearing_probes_removes_quic_deny_name_plans_like_d2o() {
        let mut plans = NamePlans::default();
        let mut deny_body = vec![b"deny.test".len() as u8];
        deny_body.extend_from_slice(b"deny.test");
        deny_body.extend_from_slice(&[SHAPE_QUIC, 4]);
        deny_body.extend_from_slice(&quic_deny_plan_records([0x44; 16]));
        assert!(
            plans
                .handle(&Frame {
                    kind: COMMAND_SET_NAME,
                    body: deny_body,
                })
                .ok
        );
        assert!(
            plans
                .handle(&set_name_shape("keep.test", SHAPE_MODERN, [0x55; 16]))
                .ok
        );
        assert_eq!(plans.r2o_plan_count(), 2);

        plans.clear_probes();

        assert_eq!(plans.r2o_plan_count(), 1);
        assert!(plans.find_exact(b"keep.test", 4, SHAPE_MODERN).is_some());
        assert!(plans.find_exact(b"deny.test", 4, SHAPE_QUIC).is_none());
    }

    fn http_tcp_packet(host: &[u8], source_port: u16) -> Vec<u8> {
        let request = [b"GET / HTTP/1.1\r\nHost: ".as_slice(), host, b"\r\n\r\n"].concat();
        let mut packet = vec![0; 40 + request.len()];
        packet[0] = 0x45;
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&80_u16.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = 0x18;
        packet[40..].copy_from_slice(&request);
        packet
    }

    fn udp_packet(payload: &[u8], destination_port: u16) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut packet = vec![0; 20 + udp_len];
        packet[0] = 0x45;
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&12345_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        packet
    }

    fn set_name(host: &str) -> Frame {
        let mut body = vec![host.len() as u8];
        body.extend_from_slice(host.as_bytes());
        body.extend_from_slice(&[SHAPE_MODERN, 4]);
        body.extend_from_slice(&plan_header(0, 2));
        body.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        body.extend_from_slice(&[0; 16]);
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x01]);
        Frame {
            kind: COMMAND_SET_NAME,
            body,
        }
    }

    fn set_quic_name(host: &str) -> Frame {
        let mut body = vec![host.len() as u8];
        body.extend_from_slice(host.as_bytes());
        body.extend_from_slice(&[SHAPE_QUIC, 4]);
        body.extend_from_slice(&plan_header(10, 3));
        body.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        body.extend_from_slice(&[0; 16]);
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x11, 0x02]);
        body.extend_from_slice(&[0x01, 0x0f, 0x00, 0x01, 0x01]);
        Frame {
            kind: COMMAND_SET_NAME,
            body,
        }
    }

    fn tcp_tls_packet(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut server_name = Vec::with_capacity(host.len() + 5);
        server_name.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        server_name.push(0);
        server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
        server_name.extend_from_slice(host);

        let mut extensions = vec![0x00, 0x00];
        extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&server_name);
        extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[0x42; 32]);
        hello.extend_from_slice(&[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&[
            ((hello.len() >> 16) & 0xff) as u8,
            ((hello.len() >> 8) & 0xff) as u8,
            (hello.len() & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&hello);

        let mut payload = vec![0x16, 0x03, 0x01];
        payload.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        payload.extend_from_slice(&handshake);

        let mut packet = vec![0; 40 + payload.len()];
        packet[0] = 0x45;
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&50_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = 0x18;
        packet[40..].copy_from_slice(&payload);
        packet
    }

    fn set_name_shape(host: &str, shape: u8, id: [u8; 16]) -> Frame {
        let mut body = vec![host.len() as u8];
        body.extend_from_slice(host.as_bytes());
        body.extend_from_slice(&[shape, 4]);
        body.extend_from_slice(&plan_header(0, 2));
        body.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        body.extend_from_slice(&id);
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x01]);
        Frame {
            kind: COMMAND_SET_NAME,
            body,
        }
    }

    fn tcp_tls_packet_with_options(host: &str, options: &[u8]) -> Vec<u8> {
        assert_eq!(options.len() % 4, 0);
        let mut base = tcp_tls_packet(host);
        let payload = base.split_off(40);
        let mut packet = base;
        packet[32] = (((20 + options.len()) / 4) as u8) << 4;
        packet.extend_from_slice(options);
        packet.extend_from_slice(&payload);
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet
    }

    #[test]
    fn tcp_shape_context_8_13_selects_by_timestamp_profile() {
        let mut plans = NamePlans::default();
        assert!(
            plans
                .handle(&set_name_shape(
                    "example.test",
                    r2k_core::control::SHAPE_MODERN_NO_TS,
                    [0xA1; 16],
                ))
                .ok
        );
        assert!(
            plans
                .handle(&set_name_shape(
                    "example.test",
                    r2k_core::control::SHAPE_MODERN_TS,
                    [0xB2; 16],
                ))
                .ok
        );

        let no_ts = tcp_tls_packet("example.test");
        assert_eq!(plans.select(&no_ts).map(|plan| plan.id), Some([0xA1; 16]));

        let with_ts =
            tcp_tls_packet_with_options("example.test", &[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(plans.select(&with_ts).map(|plan| plan.id), Some([0xB2; 16]));

        // Точный контекст имеет приоритет над базовой формой.
        let mut both = NamePlans::default();
        assert!(
            both.handle(&set_name_shape(
                "example.test",
                r2k_core::control::SHAPE_MODERN,
                [0xC3; 16],
            ))
            .ok
        );
        assert!(
            both.handle(&set_name_shape(
                "example.test",
                r2k_core::control::SHAPE_MODERN_TS,
                [0xB2; 16],
            ))
            .ok
        );
        assert_eq!(both.select(&with_ts).map(|plan| plan.id), Some([0xB2; 16]));
        assert_eq!(both.select(&no_ts).map(|plan| plan.id), Some([0xC3; 16]));

        // Базовая форма остаётся совместимым мостом, пока R2O-контроллер
        // ставит планы без контекста 8–13.
        let mut base_only = NamePlans::default();
        assert!(
            base_only
                .handle(&set_name_shape(
                    "example.test",
                    r2k_core::control::SHAPE_MODERN,
                    [0xC3; 16],
                ))
                .ok
        );
        assert_eq!(
            base_only.select(&with_ts).map(|plan| plan.id),
            Some([0xC3; 16])
        );
        assert_eq!(
            base_only.select(&no_ts).map(|plan| plan.id),
            Some([0xC3; 16])
        );
    }

    #[test]
    fn control_server_exposes_listen_and_peer_fds_like_d2o() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("r2o-control-fds-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server = ControlServer::open(&path, u16::MAX as u32).unwrap();
        assert!(server.listen_fd() >= 0);
        assert_eq!(server.peer_fd(), -1);

        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(server.poll().unwrap().is_empty());
        assert!(server.peer_fd() >= 0);
        assert_eq!(
            control::read_frame(&mut client).unwrap().kind,
            control::EVENT_PROTOCOL
        );

        drop(client);
        assert!(server.poll().unwrap().is_empty());
        assert_eq!(server.peer_fd(), -1);

        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn control_sent_counts_only_frames_queued_into_the_ring_like_d2o() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("r2o-control-sent-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server = ControlServer::open(&path, u16::MAX as u32).unwrap();
        assert_eq!(server.sent_events(), 0);
        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(server.poll().unwrap().is_empty());
        // Приветствие — первый кадр, целиком попавший в кольцо.
        assert_eq!(server.sent_events(), 1);
        assert_eq!(
            control::read_frame(&mut client).unwrap().kind,
            control::EVENT_PROTOCOL
        );

        server.send_event(EVENT_HELLO, &[1, 2, 3]).unwrap();
        assert_eq!(server.sent_events(), 2);
        assert_eq!(control::read_frame(&mut client).unwrap().kind, EVENT_HELLO);

        // C `d2k_ctl_event` при нехватке места теряет кадр целиком и
        // увеличивает dropped, но не sent.
        server.output_bytes = super::MAX_CONTROL_OUTPUT;
        server.send_event(EVENT_HELLO, &[4]).unwrap();
        assert_eq!(server.sent_events(), 2);
        assert_eq!(server.dropped_events(), 1);
        server.output_bytes = 0;

        server.send_event(EVENT_HELLO, &[5]).unwrap();
        assert_eq!(server.sent_events(), 3);

        drop(client);
        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn control_poll_processes_all_complete_frames_not_just_256() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("r2o-control-many-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server = ControlServer::open(&path, u16::MAX as u32).unwrap();
        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let mut wire = Vec::new();
        for index in 0..300u16 {
            wire.extend_from_slice(
                &control::encode_frame(COMMAND_ARM_SHAPE, &index.to_be_bytes()).unwrap(),
            );
        }
        client.write_all(&wire).unwrap();

        let frames = server.poll().unwrap();
        assert_eq!(frames.len(), 300);
        assert_eq!(frames[0].body, 0u16.to_be_bytes());
        assert_eq!(frames[299].body, 299u16.to_be_bytes());

        drop(client);
        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn disconnect_hook_fires_once_on_live_peer_disconnect() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("r2o-control-hook-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("control.sock");
        let mut server = ControlServer::open(&path, u16::MAX as u32).unwrap();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hook_calls = std::sync::Arc::clone(&calls);
        server.set_disconnect_hook(move || {
            hook_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });
        let mut client = UnixStream::connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(server.poll().unwrap().is_empty());
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(
            control::read_frame(&mut client).unwrap().kind,
            control::EVENT_PROTOCOL
        );
        drop(client);
        assert!(server.poll().unwrap().is_empty());
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(server.poll().unwrap().is_empty());
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        drop(server);
        std::fs::remove_dir(&directory).unwrap();
    }

    #[test]
    fn read_probe_flow_matches_canonical_layout() {
        let mut body = [0_u8; control::KEY_LEN];
        body[0] = 4;
        body[1..5].copy_from_slice(&[192, 0, 2, 1]);
        body[17..21].copy_from_slice(&[198, 51, 100, 2]);
        body[35..37].copy_from_slice(&443_u16.to_be_bytes());
        body[37] = 17;
        let key = super::r2o_read_probe_flow(&body).unwrap();
        assert_eq!(key[0], 4);
        assert_eq!(key[37], 17);

        let mut noncanonical = body;
        noncanonical[5] = 1;
        assert!(super::r2o_read_probe_flow(&noncanonical).is_none());

        let mut v6 = [0_u8; control::KEY_LEN];
        v6[0] = 6;
        v6[1..17].fill(0x20);
        v6[17..33].fill(0x30);
        v6[35..37].copy_from_slice(&443_u16.to_be_bytes());
        v6[37] = 17;
        assert!(super::r2o_read_probe_flow(&v6).is_some());

        let mut bad_family = body;
        bad_family[0] = 5;
        assert!(super::r2o_read_probe_flow(&bad_family).is_none());
    }

    #[test]
    fn control_out_ring_matches_c_65536_bytes() {
        assert_eq!(super::MAX_CONTROL_OUTPUT, 65536);
    }

    #[test]
    fn area_names_allow_single_label_and_numeric_like_d2o() {
        let records = tls_plan_records([0x31; 16]);
        for name in ["localhost", "12345", "a"] {
            let bytes = r2k_core::control::encode_set_suffix(
                name,
                r2k_core::control::SHAPE_MODERN,
                4,
                &records,
            )
            .unwrap();
            let mut frame =
                r2k_core::control::read_frame(&mut std::io::Cursor::new(bytes)).unwrap();
            // R2O-контроллер оборачивает area-команды `control_frame_with_area_id`.
            frame.body.extend_from_slice(&[0; 16]);
            let ack = NamePlans::default().handle(&frame);
            assert!(ack.ok, "suffix {name}: reason={}", ack.reason);
        }
        for name in ["-bad", "bad-", "a..b", "a_b", "a."] {
            let bytes = r2k_core::control::encode_set_suffix(
                name,
                r2k_core::control::SHAPE_MODERN,
                4,
                &records,
            )
            .unwrap();
            let mut frame =
                r2k_core::control::read_frame(&mut std::io::Cursor::new(bytes)).unwrap();
            frame.body.extend_from_slice(&[0; 16]);
            assert!(
                !NamePlans::default().handle(&frame).ok,
                "suffix {name} должен быть отвергнут"
            );
        }

        let bytes =
            r2k_core::control::encode_set_bypass("12345", 6, r2k_core::control::SHAPE_MODERN, 4)
                .unwrap();
        let mut frame = r2k_core::control::read_frame(&mut std::io::Cursor::new(bytes)).unwrap();
        frame.body.extend_from_slice(&[0; 16]);
        assert!(NamePlans::default().handle(&frame).ok);
    }

    #[test]
    fn exact_names_match_case_insensitively_like_name_eq() {
        let mut plans = NamePlans::default();
        assert!(plans.handle(&set_name("Example.Test")).ok);
        assert!(plans.select(&tcp_tls_packet("example.test")).is_some());
        assert!(plans.select(&tcp_tls_packet("EXAMPLE.TEST")).is_some());
    }

    #[test]
    fn name_probe_rejects_all_zero_trial_id_like_c() {
        let records = tls_plan_records([0x51; 16]);
        let frame = |trial_id: [u8; 16]| {
            let bytes = r2k_core::control::encode_set_name_probe(
                "probe.example",
                r2k_core::control::SHAPE_MODERN,
                4,
                40000,
                &records,
                trial_id,
            )
            .unwrap();
            r2k_core::control::read_frame(&mut std::io::Cursor::new(bytes)).unwrap()
        };
        assert!(!NamePlans::default().handle(&frame([0; 16])).ok);
        assert!(NamePlans::default().handle(&frame([0x51; 16])).ok);
    }

    #[test]
    fn broad_name_and_addr_deletion_removes_all_shapes_like_c() {
        let mut plans = NamePlans::default();
        assert!(
            plans
                .handle(&set_name_shape(
                    "wide.example",
                    r2k_core::control::SHAPE_MODERN,
                    [0x61; 16],
                ))
                .ok
        );
        assert!(
            plans
                .handle(&set_name_shape(
                    "wide.example",
                    r2k_core::control::SHAPE_LEGACY,
                    [0x62; 16],
                ))
                .ok
        );
        assert_eq!(plans.plans.len(), 2);
        assert!(plans.delete_name_family_all("wide.example", 4));
        assert!(plans.plans.is_empty());
        assert!(!plans.delete_name_family_all("wide.example", 4));

        let address = super::Address::new(super::IpAddr::V4(super::Ipv4Addr::new(198, 51, 100, 9)));
        for shape in [
            r2k_core::control::SHAPE_MODERN,
            r2k_core::control::SHAPE_LEGACY,
        ] {
            plans.addr_plans.insert(
                super::AddrPlanKey { address, shape },
                InstalledPlan {
                    plan: Plan::default(),
                    generation: 1,
                    last_used: std::cell::Cell::new(0),
                },
            );
        }
        assert!(plans.find_addr_any(address).is_some());
        assert!(plans.delete_addr_all(address));
        assert!(plans.addr_plans.is_empty());
        assert!(plans.find_addr_any(address).is_none());
    }

    #[test]
    fn binding_generation_is_monotonic_independent_of_revision() {
        let mut plans = NamePlans::default();
        assert!(plans.handle(&set_name("a.example")).ok);
        assert!(plans.handle(&set_name("b.example")).ok);
        let generations: Vec<u64> = plans.plans.values().map(|plan| plan.generation).collect();
        assert_eq!(generations.len(), 2);
        assert!(generations.iter().all(|generation| *generation >= 1));
        assert_ne!(generations[0], generations[1]);
    }

    #[test]
    fn find_addr_modern_shape_for_ech_covers_no_ts_and_ts() {
        let address = super::Address::new(super::IpAddr::V4(super::Ipv4Addr::new(198, 51, 100, 2)));
        let mut plans = NamePlans::default();
        for shape in [
            r2k_core::control::SHAPE_MODERN_NO_TS,
            r2k_core::control::SHAPE_MODERN_TS,
        ] {
            plans.addr_plans.insert(
                super::AddrPlanKey { address, shape },
                InstalledPlan {
                    plan: Plan::default(),
                    generation: 1,
                    last_used: std::cell::Cell::new(0),
                },
            );
        }
        assert!(
            plans
                .find_addr(address, r2k_core::control::SHAPE_ECH_NO_TS)
                .is_some()
        );
        assert!(
            plans
                .find_addr(address, r2k_core::control::SHAPE_ECH_TS)
                .is_some()
        );
        assert!(
            plans
                .find_addr(address, r2k_core::control::SHAPE_ECH_TCP)
                .is_none()
        );
    }

    #[test]
    fn set_suffix_accepts_exactly_c_shape_transports() {
        let name = "area.example";
        let tcp = tls_plan_records([0x41; 16]);
        let quic = quic_plan_records([0x42; 16]);
        let frame = |shape: u8, records: &[u8]| {
            let mut body = vec![name.len() as u8];
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(&[shape, 4]);
            body.extend_from_slice(records);
            body.extend_from_slice(&[0; 16]);
            Frame {
                kind: COMMAND_SET_SUFFIX,
                body,
            }
        };

        for shape in [1_u8, 2, 6, 8, 9, 10, 11, 12, 13] {
            let ack = NamePlans::default().handle(&frame(shape, &tcp));
            assert!(ack.ok, "shape {shape}: reason={}", ack.reason);
        }
        let ack = NamePlans::default().handle(&frame(r2k_core::control::SHAPE_QUIC, &quic));
        assert!(ack.ok, "QUIC: reason={}", ack.reason);

        for shape in [0_u8, 4, 5, 7, 14] {
            let ack = NamePlans::default().handle(&frame(shape, &tcp));
            assert!(!ack.ok, "shape {shape} должен быть отвергнут");
        }
        let ack = NamePlans::default().handle(&frame(r2k_core::control::SHAPE_MODERN, &quic));
        assert!(!ack.ok, "чужой транспорт плана должен быть отвергнут");
    }

    fn stream_input_tls_plan() -> Plan {
        let mut bytes = plan_header(5, 4);
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x01]);
        bytes.extend_from_slice(&[
            0x01, 0x09, 0x00, 0x01, 0x01, // wire detect-tcp-v1
            0x01, 0x06, 0x00, 0x0c, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        Plan::parse_wire(&bytes).unwrap()
    }

    #[test]
    fn tls_candidate_target_filters_name_suffix_bypass_and_addr() {
        let plan = stream_input_tls_plan();
        let mut plans = NamePlans::default();
        plans.plans.insert(
            NamePlanKey {
                host: "hold.example".into(),
                family: 4,
                shape: r2k_core::control::SHAPE_MODERN,
            },
            InstalledPlan {
                plan: plan.clone(),
                generation: 1,
                last_used: std::cell::Cell::new(0),
            },
        );
        assert!(plans.has_tls_candidate_target(Some(b"hold.example"), None, 4, 0));
        assert!(!plans.has_tls_candidate_target(Some(b"other.example"), None, 4, 0));

        plans.suffix_plans.insert(
            super::SuffixPlanKey {
                suffix: "hold.example".into(),
                transport: 6,
                family: 4,
                shape: r2k_core::control::SHAPE_MODERN,
            },
            InstalledPlan {
                plan: plan.clone(),
                generation: 2,
                last_used: std::cell::Cell::new(0),
            },
        );
        assert!(plans.has_tls_candidate_target(Some(b"sub.hold.example"), None, 4, 0));
        plans.domain_bypasses.insert(super::DomainBypassKey {
            name: "sub.hold.example".into(),
            transport: 6,
            family: 4,
            shape: r2k_core::control::SHAPE_MODERN,
        });
        assert!(!plans.has_tls_candidate_target(Some(b"sub.hold.example"), None, 4, 0));

        let address =
            super::Address::new(super::IpAddr::V4(super::Ipv4Addr::new(198, 51, 100, 24)));
        plans.addr_plans.insert(
            super::AddrPlanKey {
                address,
                shape: r2k_core::control::SHAPE_MODERN,
            },
            InstalledPlan {
                plan,
                generation: 3,
                last_used: std::cell::Cell::new(0),
            },
        );
        assert!(plans.has_tls_candidate_target(None, Some(address), 4, 0));
    }

    #[test]
    fn probe_flow_valid_and_equal_match_c() {
        let mut key = [0; control::KEY_LEN];
        key[0] = 4;
        key[1..5].copy_from_slice(&[192, 0, 2, 1]);
        key[17..21].copy_from_slice(&[198, 51, 100, 2]);
        key[35..37].copy_from_slice(&443_u16.to_be_bytes());
        key[37] = 17;
        assert!(super::r2o_probe_flow_valid(&key));
        assert!(super::r2o_probe_flow_equal(&key, &key));

        let mut foreign = key;
        key[35..37].copy_from_slice(&444_u16.to_be_bytes());
        assert!(!super::r2o_probe_flow_equal(&key, &foreign));
        foreign = key;
        foreign[37] = 6;
        assert!(!super::r2o_probe_flow_valid(&foreign));
        foreign = key;
        foreign[0] = 5;
        assert!(!super::r2o_probe_flow_valid(&foreign));
        foreign = key;
        foreign[35..37].fill(0);
        assert!(!super::r2o_probe_flow_valid(&foreign));
        foreign = key;
        foreign[1..5].fill(0);
        assert!(!super::r2o_probe_flow_valid(&foreign));
    }

    #[test]
    fn any_shape_name_counts_shape_miss_like_c() {
        let mut plans = NamePlans::default();
        plans.plans.insert(
            NamePlanKey {
                host: "any.example".into(),
                family: 4,
                shape: 0,
            },
            InstalledPlan {
                plan: Plan::default(),
                generation: 1,
                last_used: std::cell::Cell::new(0),
            },
        );
        assert!(plans.find_any_name(b"any.example", 4).is_some());
        let address =
            super::Address::new(super::IpAddr::V4(super::Ipv4Addr::new(198, 51, 100, 22)));
        let before = plans.shape_misses.get();
        plans.note_shape_miss(
            Some(b"any.example"),
            address,
            4,
            r2k_core::control::SHAPE_MODERN,
        );
        assert_eq!(plans.shape_misses.get(), before + 1);
    }

    #[test]
    fn explicit_find_wrappers_match_c_entry_points() {
        let mut plans = NamePlans::default();
        plans.plans.insert(
            NamePlanKey {
                host: "entry.example".into(),
                family: 4,
                shape: SHAPE_LEGACY,
            },
            InstalledPlan {
                plan: Plan {
                    id: [0xE1; 16],
                    ..Plan::default()
                },
                generation: 1,
                last_used: std::cell::Cell::new(0),
            },
        );
        assert_eq!(
            plans
                .find(Some(b"entry.example"), None, SHAPE_LEGACY)
                .map(|plan| plan.id),
            Some([0xE1; 16])
        );
        assert!(
            plans
                .find(Some(b"entry.example"), None, SHAPE_MODERN)
                .is_none()
        );

        plans.probes.insert(
            NameProbeKey {
                name: NamePlanKey {
                    host: "probe.example".into(),
                    family: 4,
                    shape: SHAPE_MODERN,
                },
                source_port: 40_000,
            },
            ProbePlan {
                plan: Plan {
                    id: [0xE2; 16],
                    ..Plan::default()
                },
                trial_id: [1; 16],
                generation: 2,
                last_used: std::cell::Cell::new(0),
            },
        );
        assert_eq!(
            plans
                .find_sport(Some(b"probe.example"), None, SHAPE_MODERN, 40_000)
                .map(|plan| plan.id),
            Some([0xE2; 16])
        );
        assert!(
            plans
                .find_sport(Some(b"probe.example"), None, SHAPE_MODERN, 40_001)
                .is_none()
        );
        // Пустое имя + уникальная портовая проба.
        assert_eq!(
            plans
                .find_target(None, None, 4, SHAPE_MODERN, 40_000)
                .map(|plan| plan.id),
            Some([0xE2; 16])
        );

        plans.plans.insert(
            NamePlanKey {
                host: "v6.example".into(),
                family: 6,
                shape: SHAPE_QUIC,
            },
            InstalledPlan {
                plan: Plan {
                    id: [0xE3; 16],
                    ..Plan::default()
                },
                generation: 3,
                last_used: std::cell::Cell::new(0),
            },
        );
        let v6 = super::Address::new(super::IpAddr::V6(super::Ipv6Addr::LOCALHOST));
        assert_eq!(
            plans
                .find_family(Some(b"v6.example"), Some(v6), SHAPE_QUIC, 0, 6)
                .map(|plan| plan.id),
            Some([0xE3; 16])
        );

        let address =
            super::Address::new(super::IpAddr::V4(super::Ipv4Addr::new(198, 51, 100, 30)));
        plans.plans.insert(
            NamePlanKey {
                host: "cross.example".into(),
                family: 4,
                shape: SHAPE_MODERN,
            },
            InstalledPlan {
                plan: Plan {
                    id: [0xE4; 16],
                    ..Plan::default()
                },
                generation: 4,
                last_used: std::cell::Cell::new(0),
            },
        );
        plans.addr_plans.insert(
            super::AddrPlanKey {
                address,
                shape: SHAPE_QUIC,
            },
            InstalledPlan {
                plan: Plan {
                    id: [0xE5; 16],
                    ..Plan::default()
                },
                generation: 5,
                last_used: std::cell::Cell::new(0),
            },
        );
        // UDP-наблюдение: TCP-запись имени уступает адресу.
        assert_eq!(
            plans
                .find_target(Some(b"cross.example"), Some(address), 4, SHAPE_QUIC, 0)
                .map(|plan| plan.id),
            Some([0xE5; 16])
        );
        // TCP-наблюдение: имя названо, адресный план не берётся, промах учтён.
        let before = plans.shape_misses.get();
        assert!(
            plans
                .find_target(Some(b"cross.example"), Some(address), 4, SHAPE_LEGACY, 0)
                .is_none()
        );
        assert_eq!(plans.shape_misses.get(), before + 1);
    }

    #[test]
    fn shape_misses_match_c_for_udp_and_addr_branches() {
        let address =
            super::Address::new(super::IpAddr::V4(super::Ipv4Addr::new(198, 51, 100, 25)));

        // UDP + только TCP-запись имени + нет адресной записи: не промах.
        let mut plans = NamePlans::default();
        plans.plans.insert(
            NamePlanKey {
                host: "voice.example".into(),
                family: 4,
                shape: r2k_core::control::SHAPE_MODERN,
            },
            InstalledPlan {
                plan: Plan::default(),
                generation: 1,
                last_used: std::cell::Cell::new(0),
            },
        );
        let before = plans.shape_misses.get();
        plans.note_shape_miss(
            Some(b"voice.example"),
            address,
            4,
            r2k_core::control::SHAPE_QUIC,
        );
        assert_eq!(plans.shape_misses.get(), before);

        // Та же UDP-цель, но у адреса есть любая запись: промах.
        plans.addr_plans.insert(
            super::AddrPlanKey {
                address,
                shape: r2k_core::control::SHAPE_MODERN,
            },
            InstalledPlan {
                plan: Plan::default(),
                generation: 2,
                last_used: std::cell::Cell::new(0),
            },
        );
        plans.note_shape_miss(
            Some(b"voice.example"),
            address,
            4,
            r2k_core::control::SHAPE_QUIC,
        );
        assert_eq!(plans.shape_misses.get(), before + 1);

        // Своя UDP-запись имени не подошла — промах без адреса.
        let mut udp_name = NamePlans::default();
        udp_name.plans.insert(
            NamePlanKey {
                host: "voice.example".into(),
                family: 4,
                shape: r2k_core::control::SHAPE_VOICE,
            },
            InstalledPlan {
                plan: Plan::default(),
                generation: 3,
                last_used: std::cell::Cell::new(0),
            },
        );
        udp_name.note_shape_miss(
            Some(b"voice.example"),
            address,
            4,
            r2k_core::control::SHAPE_QUIC,
        );
        assert_eq!(udp_name.shape_misses.get(), 1);

        // TCP-наблюдение с известным именем — промах даже без адреса.
        let mut tcp_name = NamePlans::default();
        tcp_name.plans.insert(
            NamePlanKey {
                host: "voice.example".into(),
                family: 4,
                shape: r2k_core::control::SHAPE_LEGACY,
            },
            InstalledPlan {
                plan: Plan::default(),
                generation: 4,
                last_used: std::cell::Cell::new(0),
            },
        );
        tcp_name.note_shape_miss(
            Some(b"voice.example"),
            address,
            4,
            r2k_core::control::SHAPE_MODERN,
        );
        assert_eq!(tcp_name.shape_misses.get(), 1);

        // Без имени, но с адресной записью другой формы — промах.
        let mut addr_only = NamePlans::default();
        addr_only.addr_plans.insert(
            super::AddrPlanKey {
                address,
                shape: r2k_core::control::SHAPE_QUIC,
            },
            InstalledPlan {
                plan: Plan::default(),
                generation: 5,
                last_used: std::cell::Cell::new(0),
            },
        );
        addr_only.note_shape_miss(None, address, 4, r2k_core::control::SHAPE_VOICE);
        assert_eq!(addr_only.shape_misses.get(), 1);
    }

    #[test]
    fn addr_shape_fits_finds_grandfather_and_ech_contexts() {
        let address =
            super::Address::new(super::IpAddr::V4(super::Ipv4Addr::new(198, 51, 100, 23)));
        let mut plans = NamePlans::default();
        plans.addr_plans.insert(
            super::AddrPlanKey {
                address,
                shape: r2k_core::control::SHAPE_MODERN,
            },
            InstalledPlan {
                plan: Plan::default(),
                generation: 1,
                last_used: std::cell::Cell::new(0),
            },
        );
        assert!(
            plans
                .find_addr_shape_fits(address, r2k_core::control::SHAPE_MODERN)
                .is_some()
        );
        assert!(
            plans
                .find_addr_shape_fits(address, r2k_core::control::SHAPE_ECH_NO_TS)
                .is_none()
        );
        plans.addr_plans.insert(
            super::AddrPlanKey {
                address,
                shape: r2k_core::control::SHAPE_GRANDFATHER,
            },
            InstalledPlan {
                plan: Plan::default(),
                generation: 2,
                last_used: std::cell::Cell::new(0),
            },
        );
        assert!(
            plans
                .find_addr_shape_fits(address, r2k_core::control::SHAPE_ECH_NO_TS)
                .is_some()
        );
    }

    #[test]
    fn has_ech_target_matches_c_entries_addr_and_bypass() {
        let mut plans = NamePlans::default();
        assert!(
            plans
                .handle(&set_name_shape(
                    "ech.example",
                    r2k_core::control::SHAPE_ECH_TCP,
                    [0x91; 16],
                ))
                .ok
        );
        assert!(plans.has_ech_target(Some(b"ech.example"), None, 4, 0));
        assert!(!plans.has_ech_target(None, None, 4, 0));

        let address =
            super::Address::new(super::IpAddr::V4(super::Ipv4Addr::new(198, 51, 100, 21)));
        let tcp = Plan::parse_wire(&tls_plan_records([0x92; 16])).unwrap();
        assert!(plans.set_addr_shaped_legacy(address, 4, r2k_core::control::SHAPE_ECH_NO_TS, tcp,));
        assert!(plans.has_ech_target(None, Some(address), 4, 0));

        plans.suffix_plans.insert(
            super::SuffixPlanKey {
                suffix: "bypass.example".into(),
                transport: 6,
                family: 4,
                shape: r2k_core::control::SHAPE_ECH_TS,
            },
            InstalledPlan {
                plan: Plan::default(),
                generation: 4,
                last_used: std::cell::Cell::new(0),
            },
        );
        assert!(plans.has_ech_target(Some(b"bypass.example"), None, 4, 0));
        plans.domain_bypasses.insert(super::DomainBypassKey {
            name: "bypass.example".into(),
            transport: 6,
            family: 4,
            shape: r2k_core::control::SHAPE_ECH_TS,
        });
        assert!(!plans.has_ech_target(Some(b"bypass.example"), None, 4, 0));
    }

    #[test]
    fn grandfather_updates_measured_name_and_find_name_skip_matches_c() {
        let mut plans = NamePlans::default();
        assert!(
            plans
                .handle(&set_name_shape(
                    "grand.example",
                    r2k_core::control::SHAPE_MODERN,
                    [0x81; 16],
                ))
                .ok
        );
        assert!(
            plans
                .handle(&set_name_shape(
                    "grand.example",
                    r2k_core::control::SHAPE_GRANDFATHER,
                    [0x82; 16],
                ))
                .ok
        );
        assert_eq!(plans.plans.len(), 1);
        assert_eq!(
            plans.plans[&NamePlanKey {
                host: "grand.example".into(),
                family: 4,
                shape: r2k_core::control::SHAPE_MODERN,
            }]
                .plan
                .id,
            [0x82; 16]
        );
        assert!(!plans.plans.contains_key(&NamePlanKey {
            host: "grand.example".into(),
            family: 4,
            shape: r2k_core::control::SHAPE_GRANDFATHER,
        }));

        plans.plans.insert(
            NamePlanKey {
                host: "http.example".into(),
                family: 4,
                shape: r2k_core::control::SHAPE_HTTP,
            },
            InstalledPlan {
                plan: Plan::default(),
                generation: 3,
                last_used: std::cell::Cell::new(0),
            },
        );
        assert!(plans.find_name_skip("http.example", 4, true).is_none());
        assert!(plans.find_name_skip("http.example", 4, false).is_some());
    }

    #[test]
    fn legacy_addr_setters_and_shape_fits_match_c() {
        let address = super::Address::new(super::IpAddr::V4(super::Ipv4Addr::new(198, 51, 100, 7)));
        let tcp = Plan::parse_wire(&tls_plan_records([0x71; 16])).unwrap();
        let mut plans = NamePlans::default();
        assert!(plans.set_addr_legacy(address, tcp.clone()));
        assert!(plans.addr_plans.contains_key(&super::AddrPlanKey {
            address,
            shape: r2k_core::control::SHAPE_GRANDFATHER,
        }));
        assert!(plans.set_addr_family_legacy(address, 4, tcp.clone()));
        assert!(plans.set_addr_shaped_legacy(
            address,
            4,
            r2k_core::control::SHAPE_MODERN,
            tcp.clone(),
        ));
        assert!(plans.addr_plans.contains_key(&super::AddrPlanKey {
            address,
            shape: r2k_core::control::SHAPE_MODERN,
        }));
        let http = Plan {
            proto: r2k_core::plan::PROTO_HTTP,
            ..Plan::default()
        };
        assert!(!plans.set_addr_shaped_legacy(address, 4, r2k_core::control::SHAPE_MODERN, http,));

        use r2k_core::control::{
            SHAPE_ECH_NO_TS, SHAPE_ECH_TCP, SHAPE_ECH_TS, SHAPE_GRANDFATHER, SHAPE_LEGACY,
            SHAPE_MODERN, SHAPE_MODERN_NO_TS, SHAPE_MODERN_TS, SHAPE_VOICE,
        };
        assert!(super::r2o_shape_fits(SHAPE_GRANDFATHER, SHAPE_VOICE));
        assert!(super::r2o_shape_fits(SHAPE_MODERN, SHAPE_ECH_TCP));
        assert!(super::r2o_shape_fits(SHAPE_MODERN_NO_TS, SHAPE_ECH_NO_TS));
        assert!(super::r2o_shape_fits(SHAPE_MODERN_TS, SHAPE_ECH_TS));
        assert!(super::r2o_shape_fits(SHAPE_LEGACY, SHAPE_LEGACY));
        assert!(!super::r2o_shape_fits(0, SHAPE_MODERN));
        assert!(!super::r2o_shape_fits(SHAPE_MODERN, SHAPE_ECH_NO_TS));
    }

    #[test]
    fn tcp_name_does_not_fall_back_to_addr_plan_but_udp_does() {
        let address = super::Address::new(super::IpAddr::V4(super::Ipv4Addr::new(198, 51, 100, 2)));
        let host = "fallback.example";
        let mut plans = NamePlans::default();
        plans.addr_plans.insert(
            super::AddrPlanKey {
                address,
                shape: r2k_core::control::SHAPE_QUIC,
            },
            InstalledPlan {
                plan: Plan::default(),
                generation: 1,
                last_used: std::cell::Cell::new(0),
            },
        );
        plans.plans.insert(
            NamePlanKey {
                host: host.into(),
                family: 4,
                shape: r2k_core::control::SHAPE_MODERN,
            },
            InstalledPlan {
                plan: Plan::default(),
                generation: 2,
                last_used: std::cell::Cell::new(0),
            },
        );

        // TCP-наблюдение: имя названо, его план не подошёл — адресный
        // план соседа по CDN не берём.
        assert!(
            plans
                .find_addr_fallback(
                    address,
                    Some(host.as_bytes()),
                    4,
                    r2k_core::control::SHAPE_LEGACY,
                    6,
                )
                .is_none()
        );
        // UDP-наблюдение: C разрешает `goto check_addr`.
        assert!(
            plans
                .find_addr_fallback(
                    address,
                    Some(host.as_bytes()),
                    4,
                    r2k_core::control::SHAPE_QUIC,
                    17,
                )
                .is_some()
        );
    }

    #[test]
    fn shape_transport_and_probe_transport_match_c() {
        use r2k_core::control::{
            SHAPE_ECH_NO_TS, SHAPE_ECH_TCP, SHAPE_ECH_TS, SHAPE_LEGACY, SHAPE_LEGACY_NO_TS,
            SHAPE_LEGACY_TS, SHAPE_MODERN, SHAPE_MODERN_NO_TS, SHAPE_MODERN_TS, SHAPE_QUIC,
            SHAPE_VOICE,
        };
        for shape in [
            SHAPE_MODERN,
            SHAPE_LEGACY,
            SHAPE_ECH_TCP,
            SHAPE_MODERN_NO_TS,
            SHAPE_LEGACY_NO_TS,
            SHAPE_ECH_NO_TS,
            SHAPE_MODERN_TS,
            SHAPE_LEGACY_TS,
            SHAPE_ECH_TS,
        ] {
            assert_eq!(super::r2o_shape_transport(shape), 6, "shape {shape}");
        }
        assert_eq!(super::r2o_shape_transport(SHAPE_QUIC), 17);
        assert_eq!(super::r2o_shape_transport(SHAPE_VOICE), 0);
        assert_eq!(super::r2o_shape_transport(0), 0);

        let mut plan = Plan::default();
        assert_eq!(super::r2o_probe_transport(&plan, SHAPE_QUIC), 17);
        assert_eq!(super::r2o_probe_transport(&plan, SHAPE_VOICE), 17);
        assert_eq!(super::r2o_probe_transport(&plan, SHAPE_MODERN), 6);
        plan.transport = 6;
        assert_eq!(super::r2o_probe_transport(&plan, SHAPE_QUIC), 6);
    }
    /// Оборванный TLS 1.3 ClientHello с SNI: объявленные длины больше
    /// пришедшего, supported_versions прочитан целиком.
    fn r2o_truncated_tls13_hello(complete: bool) -> Vec<u8> {
        fn put16(out: &mut Vec<u8>, value: u16) {
            out.extend_from_slice(&value.to_be_bytes());
        }
        let host = b"example.com";
        let mut out = Vec::new();
        out.extend_from_slice(&[0x16, 0x03, 0x03]);
        put16(&mut out, if complete { 74 } else { 400 });
        out.push(0x01);
        let hs_len: u32 = if complete { 70 } else { 390 };
        out.push((hs_len >> 16) as u8);
        out.push((hs_len >> 8) as u8);
        out.push(hs_len as u8);
        put16(&mut out, 0x0303);
        out.extend((0x20_u8..0x40).take(32));
        out.push(0);
        put16(&mut out, 2);
        out.extend_from_slice(&[0x13, 0x01]);
        out.extend_from_slice(&[1, 0]);
        put16(&mut out, if complete { 27 } else { 300 });
        put16(&mut out, 0x0000);
        put16(&mut out, 2 + 1 + 2 + host.len() as u16);
        put16(&mut out, 1 + 2 + host.len() as u16);
        out.push(0);
        put16(&mut out, host.len() as u16);
        out.extend_from_slice(host);
        put16(&mut out, 0x002b);
        put16(&mut out, 3);
        out.push(2);
        put16(&mut out, 0x0304);
        if complete {
            assert_eq!(out.len(), 79);
        }
        out
    }

    fn r2o_hello_packet(payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 40 + payload.len()];
        let total = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 20]);
        packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = 0x18;
        packet[34..36].copy_from_slice(&50240_u16.to_be_bytes());
        packet[40..].copy_from_slice(payload);
        packet
    }

    fn r2o_set_name(plans: &mut NamePlans, host: &str, shape: u8, id: [u8; 16]) {
        let mut body = vec![host.len() as u8];
        body.extend_from_slice(host.as_bytes());
        body.extend_from_slice(&[shape, 4]);
        body.extend_from_slice(&tls_plan_records(id));
        let ack = plans.handle(&Frame {
            kind: COMMAND_SET_NAME,
            body,
        });
        assert!(ack.ok, "SET_NAME shape {shape} reason {}", ack.reason);
    }

    #[test]
    fn truncated_tls13_uses_any_shape_only_with_an_ech_binding() {
        // C `session.c:2325-2334`: при обрыве и живом ECH-таргете форма ANY,
        // иначе сохраняется прежний быстрый путь MODERN.
        let hello = r2o_hello_packet(&r2o_truncated_tls13_hello(false));
        let complete = r2o_hello_packet(&r2o_truncated_tls13_hello(true));
        let modern = [0x11; 16];
        let ech = [0x22; 16];

        let mut plans = NamePlans::with_capacity(64);
        r2o_set_name(&mut plans, "example.com", SHAPE_MODERN, modern);
        r2o_set_name(&mut plans, "example.com", SHAPE_ECH_TCP, ech);
        assert!(
            plans.select(&hello).is_none(),
            "ECH-привязка при обрыве не даёт объявлять MODERN"
        );
        assert_eq!(
            plans.r2o_observed_tcp_shape(&hello, false),
            Some(0),
            "форма отказа при обрыве и ECH-таргете — ANY"
        );
        assert_eq!(plans.select(&complete).map(|plan| plan.id), Some(modern));
        assert_eq!(
            plans.r2o_observed_tcp_shape(&complete, false),
            Some(r2k_core::control::SHAPE_MODERN_NO_TS),
            "полный hello без TCP timestamp — MODERN_NO_TS"
        );

        let mut without_ech = NamePlans::with_capacity(64);
        r2o_set_name(&mut without_ech, "example.com", SHAPE_MODERN, modern);
        assert_eq!(without_ech.select(&hello).map(|plan| plan.id), Some(modern));
        assert_eq!(
            without_ech.r2o_observed_tcp_shape(&hello, false),
            Some(r2k_core::control::SHAPE_MODERN_NO_TS)
        );

        // Без признака TLS 1.3 оборванный блок тоже не объявляет LEGACY.
        let legacy = r2o_hello_packet(&{
            let mut packet = r2o_truncated_tls13_hello(false);
            packet.truncate(72);
            packet
        });
        let mut legacy_plans = NamePlans::with_capacity(64);
        r2o_set_name(&mut legacy_plans, "example.com", SHAPE_LEGACY, [0x33; 16]);
        assert!(legacy_plans.select(&legacy).is_none());
        assert_eq!(legacy_plans.r2o_observed_tcp_shape(&legacy, false), Some(0));
    }
}
