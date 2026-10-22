use crate::engine::validate_runtime_plan;
use r2k_core::addr::Address;
use r2k_core::control::{
    self, Ack, AppliedEvent, BindingContext, COMMAND_CLEAR, COMMAND_DEL_ADDR,
    COMMAND_DEL_ADDR_PROBE, COMMAND_DEL_BYPASS, COMMAND_DEL_NAME, COMMAND_DEL_NAME_PROBE,
    COMMAND_DEL_SUFFIX, COMMAND_DEL_VOICE_ADDR_PROBE, COMMAND_SET_ADDR, COMMAND_SET_ADDR_PROBE,
    COMMAND_SET_BYPASS, COMMAND_SET_HTTPS, COMMAND_SET_NAME, COMMAND_SET_NAME_PROBE,
    COMMAND_SET_SUFFIX, COMMAND_SET_VOICE_ADDR, COMMAND_SET_VOICE_ADDR_PROBE, Frame,
    MAX_HTTPS_TTL_SECONDS, SHAPE_ECH_TCP, SHAPE_HTTP, SHAPE_LEGACY, SHAPE_MODERN, SHAPE_QUIC,
    SHAPE_VOICE,
};
use r2k_core::packet::PacketView;
#[cfg(test)]
use r2k_core::plan::PLAN_MAGIC;
use r2k_core::plan::{PROTO_HTTP, PROTO_VOICE, Plan};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_CONTROL_OUTPUT: usize = 128 * 1024;
const MAX_COMMANDS_PER_POLL: usize = 256;
pub const MAX_NAME_PLANS: usize = 128;
const MAX_ADDR_PLANS: usize = 128;
const MAX_ADDR_PROBES: usize = 64;
const MAX_HTTPS_NAMES: usize = 256;
const MAX_VOICE_ADDR_PLANS: usize = 128;
const MAX_VOICE_ADDR_PROBES: usize = 64;
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
    https_names: HashMap<String, Instant>,
    send_maxlen: usize,
    revision: u64,
    epoch: [u8; 16],
}

struct InstalledPlan {
    plan: Plan,
    generation: u64,
}

struct ProbePlan {
    plan: Plan,
    trial_id: [u8; 16],
    generation: u64,
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

#[derive(Clone, Copy)]
struct PlanBinding {
    trial_id: [u8; 16],
    generation: u64,
    shape: u8,
    temporary: bool,
}

impl Default for NamePlans {
    fn default() -> Self {
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
            https_names: HashMap::new(),
            send_maxlen: 0,
            revision: 0,
            epoch,
        }
    }
}

impl NamePlans {
    /// Задаёт предел одной raw-посылки, чтобы отклонять неподходящие планы до установки.
    pub fn r2o_set_send_maxlen(&mut self, maxlen: usize) {
        self.send_maxlen = maxlen;
    }

    fn r2o_plan_valid(&self, plan: &Plan) -> bool {
        validate_runtime_plan(plan).is_ok()
            && (self.send_maxlen == 0 || plan.max_emit() <= self.send_maxlen)
    }

    pub fn handle(&mut self, frame: &Frame) -> Ack {
        let addr_probe = matches!(frame.kind, COMMAND_SET_ADDR_PROBE | COMMAND_DEL_ADDR_PROBE);
        let trial_id = if addr_probe {
            frame
                .body
                .get(control::KEY_LEN..control::KEY_LEN + 16)
                .and_then(|bytes| bytes.try_into().ok())
        } else if matches!(
            frame.kind,
            COMMAND_SET_NAME_PROBE | COMMAND_SET_VOICE_ADDR_PROBE | COMMAND_DEL_VOICE_ADDR_PROBE
        ) && frame.body.len() >= 16
        {
            frame.body[frame.body.len() - 16..].try_into().ok()
        } else {
            None
        };
        let body = if addr_probe {
            &frame.body
        } else if trial_id.is_some() {
            &frame.body[..frame.body.len() - 16]
        } else {
            &frame.body
        };
        let (ok, reason) = match frame.kind {
            COMMAND_SET_NAME => self.set_name(body),
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
                self.https_names.clear();
                (true, control::ACK_OK)
            }
            COMMAND_CLEAR => (false, control::ACK_BAD_ARGS),
            _ => (false, control::ACK_BAD_ARGS),
        };
        if ok {
            self.revision = self.revision.wrapping_add(1);
        }
        Ack {
            command: frame.kind,
            ok,
            reason,
            trial_id,
        }
    }

    pub fn select(&self, packet: &[u8]) -> Option<&Plan> {
        self.select_with_quic_host_at_hook(packet, None, None)
    }

    /// Выбирает план по QUIC SNI, уже извлечённому циклом обработки пакетов.
    pub fn select_with_quic_host(&self, packet: &[u8], quic_host: Option<&[u8]>) -> Option<&Plan> {
        self.select_with_quic_host_at_hook(packet, quic_host, None)
    }

    pub fn select_with_quic_host_at_hook(
        &self,
        packet: &[u8],
        quic_host: Option<&[u8]>,
        hook: Option<u8>,
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
                return self
                    .find(b"@discord-voice", view.family, SHAPE_VOICE)
                    .or_else(|| {
                        self.find_addr_fallback(
                            view.dst,
                            Some(b"@discord-voice"),
                            view.family,
                            SHAPE_VOICE,
                            17,
                        )
                    });
            }
            if r2k_core::stun::is_binding_request(payload) {
                return self.find_addr(view.dst, SHAPE_VOICE);
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
                self.find(quic_host, view.family, SHAPE_QUIC)
                    .or_else(|| self.find_in_domain(quic_host, view.family, SHAPE_QUIC, 17))
                    .or_else(|| {
                        self.find_addr_fallback(
                            view.dst,
                            Some(quic_host),
                            view.family,
                            SHAPE_QUIC,
                            17,
                        )
                    })
            } else {
                r2k_core::quic::is_authenticated_initial(payload)
                    .then(|| self.find_addr(view.dst, SHAPE_QUIC))
                    .flatten()
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
                return Some(&probe.plan);
            }
            return self.find(payload.get(host_range)?, view.family, SHAPE_HTTP);
        }
        let tls = r2k_core::tls::parse(payload);
        let sni = tls
            .sni_range
            .filter(|range| range.end <= payload.len())
            .and_then(|range| payload.get(range));
        let shape = if tls.ech_offer {
            SHAPE_ECH_TCP
        } else if tls.is_tls13 {
            SHAPE_MODERN
        } else {
            SHAPE_LEGACY
        };
        let Some(sni) = sni else {
            if !tls.is_client_hello || tls.extensions_truncated {
                return None;
            }
            return self.find_addr(view.dst, shape);
        };
        if let Some(probe) = self.probes.get(&NameProbeKey {
            name: NamePlanKey {
                host: canonical_plan_name(sni, shape)?,
                family: view.family,
                shape,
            },
            source_port: tcp.source_port,
        }) {
            return Some(&probe.plan);
        }
        self.find(sni, view.family, shape)
            .or_else(|| {
                (shape == SHAPE_ECH_TCP)
                    .then(|| self.find(sni, view.family, SHAPE_MODERN))
                    .flatten()
            })
            .or_else(|| self.find_in_domain(sni, view.family, shape, 6))
            .or_else(|| {
                (shape == SHAPE_ECH_TCP)
                    .then(|| self.find_in_domain(sni, view.family, SHAPE_MODERN, 6))
                    .flatten()
            })
            .or_else(|| self.find_addr_fallback(view.dst, Some(sni), view.family, shape, 6))
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn has_verified_https(&self, host: &[u8], now: Instant) -> bool {
        let Some(host) = canonical_name(host) else {
            return false;
        };
        self.https_names
            .get(&host)
            .is_some_and(|expires| *expires > now)
    }

    /// Удаляет временные испытания после отключения контроллера.
    pub fn clear_probes(&mut self) {
        if !self.probes.is_empty()
            || !self.voice_addr_probes.is_empty()
            || !self.addr_probes.is_empty()
        {
            self.probes.clear();
            self.voice_addr_probes.clear();
            self.addr_probes.clear();
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

    pub fn has_http_candidate(&self, family: u8) -> bool {
        self.plans
            .keys()
            .any(|key| key.family == family && key.shape == SHAPE_HTTP)
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
                    shape: SHAPE_VOICE,
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
                    shape: SHAPE_QUIC,
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
        if !r2k_core::stun::is_discord_voice_request(r2o_payload, r2o_destination_port) {
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
        let plan = match Plan::parse(&body[fields_end..]) {
            Ok(plan) => plan,
            Err(_) => return (false, control::ACK_BAD_PLAN),
        };
        let compatible = match shape {
            SHAPE_HTTP => plan.transport == 6 && plan.proto == PROTO_HTTP,
            SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP => plan.transport == 6 && plan.proto == 1,
            SHAPE_QUIC => valid_quic_plan(&plan),
            SHAPE_VOICE => plan.transport == 17 && plan.proto == PROTO_VOICE,
            _ => false,
        };
        if !compatible || !self.r2o_plan_valid(&plan) {
            return (false, control::ACK_BAD_PLAN);
        }
        if !self.plans.contains_key(&key) && self.plans.len() >= MAX_NAME_PLANS {
            return (false, control::ACK_NO_ROOM);
        }
        if self.plans.try_reserve(1).is_err() {
            return (false, control::ACK_NO_ROOM);
        }
        let generation = self.next_generation();
        self.plans.insert(key, InstalledPlan { plan, generation });
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
        let plan = match Plan::parse(&body[18..]) {
            Ok(plan) => plan,
            Err(_) => return (false, control::ACK_BAD_PLAN),
        };
        if !addr_plan_matches_shape(shape, &plan) || !self.r2o_plan_valid(&plan) {
            return (false, control::ACK_BAD_PLAN);
        }
        let key = AddrPlanKey { address, shape };
        if !self.addr_plans.contains_key(&key) && self.addr_plans.len() >= MAX_ADDR_PLANS {
            return (false, control::ACK_NO_ROOM);
        }
        if self.addr_plans.try_reserve(1).is_err() {
            return (false, control::ACK_NO_ROOM);
        }
        let generation = self.next_generation();
        self.addr_plans
            .insert(key, InstalledPlan { plan, generation });
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
        let Some(suffix) = canonical_name(&body[1..1 + name_len]) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let shape = body[1 + name_len];
        let family = body[2 + name_len];
        if !matches!(family, 4 | 6)
            || !matches!(
                shape,
                SHAPE_MODERN | SHAPE_LEGACY | SHAPE_QUIC | SHAPE_ECH_TCP
            )
        {
            return (false, control::ACK_BAD_ARGS);
        }
        let plan = match Plan::parse(&body[fields_end..]) {
            Ok(plan) => plan,
            Err(_) => return (false, control::ACK_BAD_PLAN),
        };
        let compatible = match shape {
            SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP => plan.transport == 6 && plan.proto == 1,
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
        self.suffix_plans
            .insert(key, InstalledPlan { plan, generation });
        (true, control::ACK_OK)
    }

    fn set_domain_bypass(&mut self, body: &[u8]) -> (bool, u8) {
        let Some(name_len) = body.first().copied().map(usize::from) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if name_len == 0 || name_len > control::MAX_DNS_NAME_LEN || body.len() != name_len + 4 {
            return (false, control::ACK_BAD_ARGS);
        }
        let Some(name) = canonical_name(&body[1..1 + name_len]) else {
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
        let Some(name) = canonical_name(&body[1..1 + name_len]) else {
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
        let Some(name_len) = body.first().copied().map(usize::from) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if name_len == 0 || body.len() != name_len + 5 {
            return (false, control::ACK_BAD_ARGS);
        }
        let Some(host) = canonical_name(&body[1..1 + name_len]) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let ttl = u32::from_be_bytes(
            body[1 + name_len..]
                .try_into()
                .expect("HTTPS TTL has a fixed width"),
        );
        if ttl > MAX_HTTPS_TTL_SECONDS {
            return (false, control::ACK_BAD_ARGS);
        }
        if ttl == 0 {
            self.https_names.remove(&host);
            return (true, control::ACK_OK);
        }
        if !self.https_names.contains_key(&host)
            && self.https_names.len() >= MAX_HTTPS_NAMES
            && let Some(oldest) = self
                .https_names
                .iter()
                .min_by_key(|(_, expires)| **expires)
                .map(|(host, _)| host.clone())
        {
            self.https_names.remove(&oldest);
        }
        self.https_names
            .insert(host, Instant::now() + Duration::from_secs(u64::from(ttl)));
        (true, control::ACK_OK)
    }

    fn set_name_probe(&mut self, body: &[u8], trial_id: Option<[u8; 16]>) -> (bool, u8) {
        let Some(name_len) = body.first().copied().map(usize::from) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let Some(fields_end) = 5_usize.checked_add(name_len) else {
            return (false, control::ACK_BAD_ARGS);
        };
        if name_len == 0 || body.len() < fields_end || trial_id.is_none() {
            return (false, control::ACK_BAD_ARGS);
        }
        let shape = body[1 + name_len];
        let Some(host) = canonical_plan_name(&body[1..1 + name_len], shape) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let family = body[2 + name_len];
        let source_port = u16::from_be_bytes([body[3 + name_len], body[4 + name_len]]);
        if !valid_tcp_shape(shape) || !matches!(family, 4 | 6) || source_port == 0 {
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
        let plan = match Plan::parse(&body[fields_end..]) {
            Ok(plan) => plan,
            Err(_) => return (false, control::ACK_BAD_PLAN),
        };
        let proto_matches = match shape {
            SHAPE_HTTP => plan.proto == PROTO_HTTP,
            SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP => plan.proto == 1,
            _ => false,
        };
        if plan.transport != 6 || !proto_matches || !self.r2o_plan_valid(&plan) {
            return (false, control::ACK_BAD_PLAN);
        }
        if !self.probes.contains_key(&key) && self.probes.len() >= MAX_NAME_PLANS {
            return (false, control::ACK_NO_ROOM);
        }
        if self.probes.try_reserve(1).is_err() {
            return (false, control::ACK_NO_ROOM);
        }
        let generation = self.next_generation();
        self.probes.insert(
            key,
            ProbePlan {
                plan,
                trial_id: trial_id.unwrap(),
                generation,
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
        let r2o_plan = match Plan::parse(&body[4..]) {
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
        let r2o_plan = match Plan::parse(&body[14..]) {
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
            && self.voice_addr_probes.len() >= MAX_VOICE_ADDR_PROBES
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
        let Ok(key) = <[u8; control::KEY_LEN]>::try_from(&body[..control::KEY_LEN]) else {
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
        if !control::valid_udp_addr_probe_flow(&key)
            || trial_id.iter().all(|byte| *byte == 0)
            || lease_ms == 0
            || lease_ms > control::ADDR_PROBE_LEASE_MAX_MS
        {
            return (false, control::ACK_BAD_ARGS);
        }
        let plan = match Plan::parse(&body[fixed..]) {
            Ok(plan) => plan,
            Err(_) => return (false, control::ACK_BAD_PLAN),
        };
        if !valid_quic_plan(&plan) {
            return (false, control::ACK_BAD_PLAN);
        }
        let now = Instant::now();
        self.addr_probes.retain(|_, probe| probe.expires > now);
        if self
            .addr_probes
            .get(&key)
            .is_some_and(|existing| existing.trial_id != trial_id)
        {
            return (false, control::ACK_BAD_ARGS);
        }
        if !self.addr_probes.contains_key(&key) && self.addr_probes.len() >= MAX_ADDR_PROBES {
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
        let Ok(key) = <[u8; control::KEY_LEN]>::try_from(&body[..control::KEY_LEN]) else {
            return (false, control::ACK_BAD_ARGS);
        };
        let body_trial_id: [u8; 16] = body[control::KEY_LEN..]
            .try_into()
            .expect("длина идентификатора адресного опыта проверена выше");
        if !control::valid_udp_addr_probe_flow(&key)
            || body_trial_id.iter().all(|byte| *byte == 0)
            || trial_id != Some(body_trial_id)
        {
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
        if !valid_tcp_shape(shape) || !matches!(family, 4 | 6) || source_port == 0 {
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

    fn find(&self, bytes: &[u8], family: u8, shape: u8) -> Option<&Plan> {
        let host = canonical_plan_name(bytes, shape)?;
        self.plans
            .get(&NamePlanKey {
                host,
                family,
                shape,
            })
            .map(|entry| &entry.plan)
    }

    fn find_addr(&self, address: Address, shape: u8) -> Option<&Plan> {
        self.addr_plans
            .get(&AddrPlanKey { address, shape })
            .or_else(|| {
                if shape == SHAPE_ECH_TCP {
                    self.addr_plans.get(&AddrPlanKey {
                        address,
                        shape: SHAPE_MODERN,
                    })
                } else {
                    None
                }
            })
            .map(|entry| &entry.plan)
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
        }
        self.find_addr(address, shape)
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
        self.revision.wrapping_add(1).max(1)
    }
}

fn valid_domain_area_context(transport: u8, shape: u8, family: u8) -> bool {
    matches!(family, 4 | 6)
        && ((transport == 6 && matches!(shape, SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP))
            || (transport == 17 && shape == SHAPE_QUIC))
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
    matches!(
        shape,
        SHAPE_MODERN | SHAPE_LEGACY | SHAPE_ECH_TCP | SHAPE_HTTP
    )
}

fn valid_quic_plan(plan: &Plan) -> bool {
    plan.r2k_is_quic_address_plan() && validate_runtime_plan(plan).is_ok()
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
    peer: Option<UnixStream>,
    input: Vec<u8>,
    output: VecDeque<PendingWrite>,
    output_bytes: usize,
    dropped_events: u64,
}

impl ControlServer {
    pub fn open(path: impl AsRef<Path>, send_maxlen: u32) -> io::Result<Self> {
        let path = path.as_ref().to_owned();
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            if !metadata.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "control path уже занят не Unix-сокетом",
                ));
            }
            match UnixStream::connect(&path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "control socket уже обслуживается",
                    ));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) =>
                {
                    std::fs::remove_file(&path)?;
                }
                Err(error) => return Err(error),
            }
        }
        let listener = UnixListener::bind(&path)?;
        if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        {
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
            peer: None,
            input: Vec::new(),
            output: VecDeque::new(),
            output_bytes: 0,
            dropped_events: 0,
        })
    }

    pub fn poll(&mut self) -> io::Result<Vec<Frame>> {
        self.accept_peer();
        let mut frames = Vec::new();
        if self.peer.is_some() && !self.read_peer(&mut frames) {
            self.disconnect();
        }
        self.flush()?;
        Ok(frames)
    }

    pub fn send_ack(&mut self, ack: Ack) -> io::Result<()> {
        let bytes = control::encode_ack_for_trial(ack.command, ack.ok, ack.reason, ack.trial_id)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.enqueue(bytes);
        self.flush()
    }

    pub fn send_event(&mut self, kind: u16, body: &[u8]) -> io::Result<()> {
        let bytes = control::encode_frame(kind, body)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.enqueue(bytes);
        self.flush()
    }

    pub fn is_connected(&self) -> bool {
        self.peer.is_some()
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
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
                    if let Ok(greeting) = control::encode_greeting(self.send_maxlen) {
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
            if frames.len() >= MAX_COMMANDS_PER_POLL {
                return true;
            }
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
            if frames.len() >= MAX_COMMANDS_PER_POLL {
                return true;
            }
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

    fn enqueue(&mut self, bytes: Vec<u8>) {
        if self.peer.is_none() {
            return;
        }
        if self.output_bytes.saturating_add(bytes.len()) > MAX_CONTROL_OUTPUT {
            self.dropped_events = self.dropped_events.saturating_add(1);
            return;
        }
        self.output_bytes += bytes.len();
        self.output.push_back(PendingWrite { bytes, offset: 0 });
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
        if let Some(peer) = self.peer.take() {
            let _ = peer.shutdown(Shutdown::Both);
        }
        self.input.clear();
        self.output.clear();
        self.output_bytes = 0;
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
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

#[cfg(test)]
mod tests {
    use super::{ControlServer, MAX_NAME_PLANS, NamePlans};
    use r2k_core::plan::Plan;

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
        self, COMMAND_CLEAR, COMMAND_DEL_ADDR, COMMAND_DEL_BYPASS, COMMAND_DEL_NAME,
        COMMAND_DEL_NAME_PROBE, COMMAND_DEL_SUFFIX, COMMAND_SET_ADDR, COMMAND_SET_BYPASS,
        COMMAND_SET_NAME, COMMAND_SET_NAME_PROBE, COMMAND_SET_SUFFIX, EVENT_HELLO, Frame,
        SHAPE_HTTP, SHAPE_LEGACY, SHAPE_MODERN, SHAPE_QUIC, SHAPE_VOICE, encode_delete_addr,
        encode_set_addr, encode_set_voice_addr, encode_set_voice_addr_probe,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        drop(server);
        assert_eq!(mode, 0o600, "control socket grants group/other access");
        assert!(!path.exists(), "server should remove its socket on drop");
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
    fn name_plan_table_is_bounded_and_delete_releases_a_slot() {
        let mut plans = NamePlans::default();
        for index in 0..MAX_NAME_PLANS {
            let host = format!("host-{index}.example");
            let ack = plans.handle(&set_name(&host));
            assert!(ack.ok, "{host}: {}", ack.reason);
        }

        let overflow = plans.handle(&set_name("overflow.example"));
        assert!(!overflow.ok);
        assert_eq!(overflow.reason, control::ACK_NO_ROOM);

        let mut delete = vec!["host-0.example".len() as u8];
        delete.extend_from_slice(b"host-0.example");
        delete.extend_from_slice(&[6, SHAPE_MODERN, 4]);
        let ack = plans.handle(&Frame {
            kind: COMMAND_DEL_NAME,
            body: delete,
        });
        assert!(ack.ok);
        assert!(plans.handle(&set_name("overflow.example")).ok);
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
        let plan = Plan::parse(&frame.body[prefix_len..]).unwrap();

        plans.r2o_set_send_maxlen(1);
        assert!(!plans.handle(&frame).ok);
        plans.r2o_set_send_maxlen(1500);
        let ack = plans.handle(&frame);
        assert!(ack.ok, "reason={} max_emit={}", ack.reason, plan.max_emit());
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

        let mut plans = NamePlans::default();
        let ack = plans.handle(&Frame {
            kind: COMMAND_SET_SUFFIX,
            body,
        });
        assert!(ack.ok, "SET_SUFFIX отвергнут: {}", ack.reason);

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
    fn исключение_снимает_suffix_только_для_точного_имени_и_удаляется() {
        let suffix = "googlevideo.com";
        let mut suffix_body = vec![suffix.len() as u8];
        suffix_body.extend_from_slice(suffix.as_bytes());
        suffix_body.extend_from_slice(&[SHAPE_MODERN, 4]);
        suffix_body.extend_from_slice(&plan_header(0, 2));
        suffix_body.extend_from_slice(&[0x00, 0x01, 0x00, 0x10]);
        suffix_body.extend_from_slice(&[0x31; 16]);
        suffix_body.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x06, 0x01]);

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
}
