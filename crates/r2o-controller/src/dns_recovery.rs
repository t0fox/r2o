use super::{
    ControlClient, DiscoveryOutcome, DiscoveryWorker, Plan, PreparedCandidate, R2oDnsServices,
    R2oDnsTrialEvidence, R2oQuicDiscoveryOutcome, R2oQuicDiscoveryTask, R2oQuicDiscoveryWorker,
    SHAPE_MODERN, SHAPE_QUIC, control, encode_delete_name_bound, encode_set_name_bound,
    flow_socket_addresses, r2o_discovery_task_key, r2o_dns_unique_service, r2o_plan_wire_shape,
    random_id,
};
use r2k_core::dns_config::DnsService;
use r2o_controller::discovery::DiscoveryTarget;
use r2o_controller::dns_health::{DnsHealthFailure, DnsHealthResult, probe_dns_health};
use r2o_controller::live::{DnsRecoveryPhase, DnsServiceState, DnsVerifiedRecovery};
use r2o_controller::r2o_resource_limit::R2oMeasurementGate;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

const ROUTE_TTL: Duration = Duration::from_secs(300);
const ROUTE_COMMAND_TIMEOUT: Duration = Duration::from_secs(4);
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
const CHECK_TIMEOUT: Duration = Duration::from_secs(7);
const RECHECK_INTERVAL: Duration = Duration::from_secs(90);
const RETRY: Duration = Duration::from_secs(300);
// При очереди один TCP-сервис уступает слот, сохраняя полный бюджет без соседей.
const TCP_SEARCH_WITH_WAITERS: Duration = Duration::from_secs(90);

#[derive(Clone)]
struct Request {
    generation: u64,
    endpoint: SocketAddr,
    target: DiscoveryTarget,
    owner: Option<u32>,
}

#[derive(Clone)]
pub(super) struct QuicDnsDiscovery {
    pub(super) generation: u64,
    pub(super) service: DnsService,
    pub(super) direct_mark: u32,
    pub(super) owner: Option<u32>,
}

fn dnsproxy_owner() -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    let uid = passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == "dnsproxy").then_some(())?;
        fields.nth(1)?.parse::<u32>().ok()
    })?;
    if matches!(uid, 0 | u32::MAX)
        || passwd
            .lines()
            .filter(|line| {
                line.split(':').nth(2).and_then(|id| id.parse::<u32>().ok()) == Some(uid)
            })
            .count()
            != 1
    {
        return None;
    }
    // Проверяем именно рабочий процесс, а не родительский ujail от root.
    std::fs::read_dir("/proc")
        .ok()?
        .flatten()
        .any(|entry| {
            if !std::fs::read_link(entry.path().join("exe"))
                .is_ok_and(|exe| exe == std::path::Path::new("/usr/bin/dnsproxy"))
            {
                return false;
            }
            std::fs::read_to_string(entry.path().join("status")).is_ok_and(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("Uid:"))
                    .is_some_and(|ids| {
                        ids.split_ascii_whitespace()
                            .filter(|id| id.parse::<u32>().ok() == Some(uid))
                            .count()
                            == 4
                    })
            })
        })
        .then_some(uid)
}

pub(super) fn with_socket_owner<T, E: From<std::io::Error>>(
    owner: Option<u32>,
    open: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let Some(uid) = owner else {
        return open();
    };
    #[cfg(target_os = "linux")]
    {
        struct RestoreUid(u32);
        impl Drop for RestoreUid {
            fn drop(&mut self) {
                unsafe { libc::setfsuid(self.0) };
            }
        }
        // UID сокета берётся при открытии. setfsuid изменяет только текущий Linux-поток.
        let _restore = RestoreUid(unsafe { libc::setfsuid(uid) } as u32);
        if unsafe { libc::setfsuid(u32::MAX) } as u32 != uid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Не удалось назначить владельца сокета DoH3",
            )
            .into());
        }
        open()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = uid;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Проверка владельца сокета DoH3 доступна на Linux",
        )
        .into())
    }
}

impl Request {
    fn from_failures(
        state: &R2oDnsServices,
        index: usize,
        family: Option<u8>,
        doh3_owner: Option<u32>,
    ) -> Option<Self> {
        let live = state.live.get(index)?;
        let service = state.services.get(index)?;
        if live.state != DnsServiceState::Failed
            || live.consecutive_network_failures < 2
            || service.verification_limitation().is_some()
        {
            return None;
        }
        let owner = match service.protocol.as_str() {
            "doh" | "dot" | "doq" => None,
            "doh3" if matches!(service.source.as_str(), "dnsproxy" | "dnsproxy-http3") => {
                Some(doh3_owner.filter(|uid| !matches!(*uid, 0 | u32::MAX))?)
            }
            _ => return None,
        };
        let endpoint = SocketAddr::new(live.ip.parse().ok()?, service.port);
        let endpoint_family = if endpoint.is_ipv4() { 4 } else { 6 };
        if family.is_some_and(|allowed| allowed != endpoint_family) {
            return None;
        }
        let host = if service.sni.is_empty() {
            &service.host
        } else {
            &service.sni
        };
        if !matches!(
            r2o_dns_unique_service(&state.services, endpoint, host, service.transport()),
            Ok(Some((matched, _))) if matched == index
        ) {
            return None;
        }
        Some(Self {
            generation: live.generation,
            endpoint,
            owner,
            target: DiscoveryTarget {
                host: host.clone(),
                endpoint: endpoint.to_string(),
                family: endpoint_family,
                shape: if service.transport() == 17 {
                    SHAPE_QUIC
                } else {
                    SHAPE_MODERN
                },
                tcp_profile: 0,
            },
        })
    }

    fn transport(&self) -> u8 {
        if self.target.shape == SHAPE_QUIC {
            17
        } else {
            6
        }
    }

    fn index(&self, state: &R2oDnsServices) -> Option<usize> {
        let (index, _) = r2o_dns_unique_service(
            &state.services,
            self.endpoint,
            &self.target.host,
            self.transport(),
        )
        .ok()??;
        let live = state.live.get(index)?;
        (live.generation == self.generation
            && live.ip.parse::<std::net::IpAddr>() == Ok(self.endpoint.ip()))
        .then_some(index)
    }

    fn needs_recovery(&self, state: &R2oDnsServices) -> Option<usize> {
        self.index(state)
            .filter(|&index| state.live[index].consecutive_network_failures >= 2)
    }

    fn matches(&self, target: &DiscoveryTarget) -> bool {
        self.endpoint.to_string() == target.endpoint
            && r2o_discovery_task_key(&self.target) == r2o_discovery_task_key(target)
    }
}

struct RouteCommand {
    child: Child,
    deadline: Instant,
}

impl RouteCommand {
    fn poll(&mut self, now: Instant) -> Option<bool> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status.success()),
            Ok(None) if now < self.deadline => None,
            _ => Some(false),
        }
    }
}

impl Drop for RouteCommand {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct Binding {
    key: String,
    plan_id: [u8; 16],
    records: Vec<u8>,
    context: control::BindingContext,
    expires: Instant,
}

impl Binding {
    fn install(
        client: &mut ControlClient,
        request: &Request,
        service: &DnsService,
        wire_shape: u8,
        evidence: R2oDnsTrialEvidence,
    ) -> Option<Self> {
        let key = if wire_shape == SHAPE_QUIC {
            if let Some(uid) = request.owner {
                control::dns_doh3_plan_key(request.endpoint, service.sni.as_bytes(), uid)?
            } else {
                control::dns_doq_plan_key(request.endpoint, service.sni.as_bytes())?
            }
        } else {
            control::dns_tcp_plan_key(request.endpoint, service.sni.as_bytes())?
        };
        let parsed = Plan::parse(&evidence.records).ok()?;
        if parsed.id != evidence.plan_id || parsed.transport != request.transport() {
            return None;
        }
        let (context, expires) = Self::apply(
            client,
            &key,
            wire_shape,
            request.target.family,
            &evidence.records,
        )?;
        Some(Self {
            key,
            plan_id: evidence.plan_id,
            records: evidence.records,
            context,
            expires,
        })
    }

    fn apply(
        client: &mut ControlClient,
        key: &str,
        shape: u8,
        family: u8,
        records: &[u8],
    ) -> Option<(control::BindingContext, Instant)> {
        let trial = random_id().ok()?;
        let frame = encode_set_name_bound(key, shape, family, records, trial).ok()?;
        let expires = Instant::now() + control::DNS_PLAN_LEASE;
        let ack = client
            .exchange_command_with_timeout(
                &frame,
                control::COMMAND_SET_NAME_BOUND,
                Duration::from_millis(750),
            )
            .ok()?;
        let context = ack.binding_context?;
        (ack.ok
            && ack.trial_id == Some(trial)
            && context.is_known()
            && !context.temporary
            && context.kind == if shape == SHAPE_QUIC { 2 } else { 1 }
            && context.shape == shape
            && context.family == family)
            .then_some((context, expires))
    }

    fn renew(&mut self, client: &mut ControlClient) -> bool {
        let Some((context, expires)) = Self::apply(
            client,
            &self.key,
            self.context.shape,
            self.context.family,
            &self.records,
        ) else {
            return false;
        };
        self.context = context;
        self.expires = expires;
        true
    }

    fn remove(&self, client: &mut ControlClient) {
        if let Ok(frame) = encode_delete_name_bound(&self.key, self.transport(), self.context) {
            let _ = client.exchange_command_with_timeout(
                &frame,
                control::COMMAND_DEL_NAME_BOUND,
                Duration::from_millis(500),
            );
        }
    }

    fn transport(&self) -> u8 {
        if self.context.shape == SHAPE_QUIC {
            17
        } else {
            6
        }
    }
}

fn start_quic_dns_probe(
    request: &Request,
    service: DnsService,
) -> std::io::Result<(SocketAddr, Receiver<DnsHealthResult>)> {
    let endpoint = request.endpoint;
    let (socket, _) = with_socket_owner(request.owner, || {
        r2o_controller::r2o_quic_http3::r2o_quic_http3_udp_socket_fresh(endpoint, None)
            .map_err(|error| error.source)
    })?;
    socket.connect(endpoint)?;
    let local = socket.local_addr()?;
    let host = request.target.host.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        let mut result = runtime.block_on(r2o_controller::dns_health::probe_quic_dns_on(
            socket,
            endpoint,
            &host,
            &service,
            PROBE_TIMEOUT,
        ));
        result.local_endpoint = Some(local);
        let _ = sender.send(result);
    });
    Ok((local, receiver))
}

struct Recheck {
    binding: Binding,
    receiver: Receiver<DnsHealthResult>,
    result: Option<DnsHealthResult>,
    applied_from: Vec<SocketAddr>,
    deadline: Instant,
}

impl Recheck {
    fn new(binding: Binding, request: &Request, mut service: DnsService, now: Instant) -> Self {
        let receiver = if request.transport() == 17 {
            start_quic_dns_probe(request, service)
                .map(|(_, receiver)| receiver)
                .unwrap_or_else(|_| std::sync::mpsc::channel().1)
        } else {
            service.host = request.endpoint.ip().to_string();
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = sender.send(probe_dns_health(&service, None, PROBE_TIMEOUT));
            });
            receiver
        };
        Self {
            binding,
            receiver,
            result: None,
            applied_from: Vec::new(),
            deadline: now + CHECK_TIMEOUT,
        }
    }

    fn observe(&mut self, endpoint: SocketAddr, event: &control::AppliedEvent) {
        if event.key[37] != self.binding.transport()
            || event.trial_id != [0; 16]
            || event.binding != self.binding.context
            || event.plan_id != self.binding.plan_id
        {
            return;
        }
        let (low, high) = flow_socket_addresses(&event.key, true);
        let local = if high == endpoint {
            low
        } else if low == endpoint {
            high
        } else {
            return;
        };
        if self.applied_from.len() < 16 && !self.applied_from.contains(&local) {
            self.applied_from.push(local);
        }
    }

    fn poll(&mut self, now: Instant) -> Option<bool> {
        if now >= self.deadline {
            return Some(false);
        }
        if self.result.is_none() {
            match self.receiver.try_recv() {
                Ok(result) => self.result = Some(result),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => return Some(false),
            }
        }
        let result = self.result.as_ref()?;
        if !result.dns_reply || result.local_endpoint.is_none() {
            return Some(false);
        }
        self.applied_from
            .contains(&result.local_endpoint?)
            .then_some(true)
    }
}

enum Phase {
    Open(RouteCommand, Option<Binding>),
    Search {
        started: Instant,
    },
    QuicCapture {
        local: SocketAddr,
        snapshot: Option<Vec<u8>>,
        deadline: Instant,
    },
    QuicSearch,
    Recheck(Recheck),
}

struct Attempt {
    request: Request,
    phase: Phase,
    expires: Instant,
}

struct Retained {
    request: Request,
    binding: Binding,
    expires: Instant,
    renew_at: Instant,
}

pub(super) struct Recovery {
    firewall: PathBuf,
    family: Option<u8>,
    quic_marks: Option<(u32, u32)>,
    gate: R2oMeasurementGate,
    attempt: Option<Attempt>,
    retained: Vec<Retained>,
    cleanup: Vec<RouteCommand>,
    next_tick: Instant,
    next_scan: Instant,
}

impl Recovery {
    pub(super) fn from_environment(
        mark: Option<u32>,
        confirm_mark: Option<u32>,
        family: Option<u8>,
        gate: R2oMeasurementGate,
    ) -> Option<Self> {
        if mark.unwrap_or(0) == 0
            || super::r2o_control_wire() != control::WireProfile::V48
            || !matches!(std::env::var("R2O_DNS_MODE").as_deref(), Ok("apply"))
        {
            return None;
        }
        let firewall = PathBuf::from(std::env::var_os("R2O_FIREWALL")?);
        if !firewall.is_absolute() {
            return None;
        }
        Some(Self {
            firewall,
            family,
            quic_marks: mark
                .zip(confirm_mark)
                .filter(|(direct, trial)| *trial != 0 && direct != trial),
            gate,
            attempt: None,
            retained: Vec::new(),
            cleanup: Vec::new(),
            next_tick: Instant::now(),
            next_scan: Instant::now(),
        })
    }

    fn route(&self, request: &Request, add: bool, now: Instant) -> Option<RouteCommand> {
        let seconds = if add { ROUTE_TTL.as_secs() } else { 0 };
        let mut command = Command::new(&self.firewall);
        command.args([
            "dns-route",
            if add { "add" } else { "del" },
            &request.endpoint.ip().to_string(),
            if request.transport() == 17 {
                "udp"
            } else {
                "tcp"
            },
            &request.endpoint.port().to_string(),
            &seconds.to_string(),
        ]);
        if let Some(uid) = request.owner {
            command.arg(uid.to_string());
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        Some(RouteCommand {
            child,
            deadline: now + ROUTE_COMMAND_TIMEOUT,
        })
    }

    fn release(
        &mut self,
        request: &Request,
        binding: Option<Binding>,
        client: &mut ControlClient,
        state: &mut R2oDnsServices,
        now: Instant,
        reason: Option<&str>,
    ) {
        if request.transport() == 17 {
            super::r2o_quic_dns_live_clear(request.endpoint);
        }
        if let Some(index) = request.index(state) {
            let live = &mut state.live[index];
            if binding.as_ref().is_some_and(|binding| {
                live.applied_plan_id
                    == binding
                        .plan_id
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
            }) {
                live.plan_applied = false;
                live.applied_plan_id.clear();
                live.plan_applied_at = None;
            }
            live.recovery_phase = None;
            live.verified_recovery = None;
            if let Some(reason) = reason.filter(|_| {
                live.state == DnsServiceState::Failed
                    && live.failure != Some(DnsHealthFailure::NoRoute)
            }) {
                live.reason = reason.to_owned();
            }
            live.recovery_retry_at = Some(now + RETRY);
        }
        if let Some(binding) = binding {
            binding.remove(client);
        }
        if self.cleanup.len() < r2k_core::dns_config::DNS_SERVICE_MAX
            && let Some(cleanup) = self.route(request, false, now)
        {
            self.cleanup.push(cleanup);
        }
    }

    pub(super) fn tick(
        &mut self,
        client: &mut ControlClient,
        state: &mut R2oDnsServices,
        worker: &mut DiscoveryWorker,
        quic: Option<&mut R2oQuicDiscoveryWorker>,
        now: Instant,
        wall: i64,
    ) {
        if now < self.next_tick {
            return;
        }
        self.next_tick = now + Duration::from_millis(250);
        self.cleanup
            .retain_mut(|command| command.poll(now).is_none());
        while let Some(index) = self
            .retained
            .iter()
            .position(|entry| now >= entry.expires || entry.request.needs_recovery(state).is_none())
        {
            let entry = self.retained.swap_remove(index);
            self.release(
                &entry.request,
                Some(entry.binding),
                client,
                state,
                now,
                None,
            );
        }

        if let Some(mut attempt) = self.attempt.take() {
            if let Phase::Search { started } = attempt.phase
                && now < attempt.expires
                && now.saturating_duration_since(started) >= TCP_SEARCH_WITH_WAITERS
                && self
                    .ready_request(
                        state,
                        worker,
                        quic.as_deref(),
                        now,
                        Some(attempt.request.generation),
                    )
                    .is_some()
            {
                attempt.expires = now;
            }
            self.advance(attempt, client, state, worker, quic, now, wall);
            return;
        }
        if now < self.next_scan || !self.cleanup.is_empty() {
            return;
        }
        self.next_scan = now + Duration::from_secs(2);
        if let Some(index) = self.retained.iter().position(|entry| now >= entry.renew_at) {
            let entry = self.retained.remove(index);
            self.open(entry.request, Some(entry.binding), client, state, now);
            return;
        }
        if let Some(request) = self.ready_request(state, worker, quic.as_deref(), now, None) {
            if request.transport() == 6 && worker.r2o_is_watching(&request.target) {
                worker.r2o_forget_watching_task(&r2o_discovery_task_key(&request.target));
            }
            self.open(request, None, client, state, now);
        }
    }

    fn ready_request(
        &self,
        state: &R2oDnsServices,
        worker: &DiscoveryWorker,
        quic: Option<&R2oQuicDiscoveryWorker>,
        now: Instant,
        skip_generation: Option<u64>,
    ) -> Option<Request> {
        let doh3_owner = std::cell::OnceCell::new();
        (0..state.services.len()).find_map(|index| {
            let live = state.live.get(index)?;
            if Some(live.generation) == skip_generation
                || live.recovery_retry_at.is_some_and(|retry| now < retry)
            {
                return None;
            }
            let owner = (state.services[index].protocol == "doh3"
                && live.state == DnsServiceState::Failed
                && live.consecutive_network_failures >= 2)
                .then(|| *doh3_owner.get_or_init(dnsproxy_owner))
                .flatten();
            let request = Request::from_failures(state, index, self.family, owner)?;
            (!self.retained.iter().any(|entry| {
                entry.request.endpoint == request.endpoint
                    && entry.request.transport() == request.transport()
            }) && if request.transport() == 17 {
                self.quic_marks.is_some()
                    && quic.is_some_and(|worker| !worker.active.contains_key(&request.endpoint))
            } else {
                !worker.is_active(&request.target)
            })
            .then_some(request)
        })
    }

    fn open(
        &mut self,
        request: Request,
        binding: Option<Binding>,
        client: &mut ControlClient,
        state: &mut R2oDnsServices,
        now: Instant,
    ) {
        if let Some(command) = self.route(&request, true, now) {
            if let Some(index) = request.index(state) {
                state.live[index].recovery_phase = Some(if binding.is_some() {
                    DnsRecoveryPhase::Recheck
                } else {
                    DnsRecoveryPhase::Discovery
                });
            }
            self.attempt = Some(Attempt {
                request,
                phase: Phase::Open(command, binding),
                expires: now + ROUTE_TTL,
            });
        } else {
            self.release(
                &request,
                binding,
                client,
                state,
                now,
                Some("Не удалось запустить маршрут DNS для подбора."),
            );
        }
    }

    fn advance(
        &mut self,
        mut attempt: Attempt,
        client: &mut ControlClient,
        state: &mut R2oDnsServices,
        worker: &mut DiscoveryWorker,
        quic: Option<&mut R2oQuicDiscoveryWorker>,
        now: Instant,
        wall: i64,
    ) {
        let current = attempt.request.needs_recovery(state);
        match &mut attempt.phase {
            Phase::Search { .. } => {
                if current.is_none() || now >= attempt.expires {
                    attempt.expires = now;
                    let key = r2o_discovery_task_key(&attempt.request.target);
                    if let Some(cancel) = worker
                        .active_cancels
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .get(&key)
                    {
                        cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                if worker.is_active(&attempt.request.target)
                    || worker
                        .pending_rechecks
                        .contains_key(&r2o_discovery_task_key(&attempt.request.target))
                {
                    self.attempt = Some(attempt);
                } else {
                    self.release(&attempt.request, None, client, state, now, None);
                }
            }
            Phase::QuicCapture {
                snapshot, deadline, ..
            } => {
                if let Some(index) = current
                    && now < *deadline
                    && let Some((direct_mark, trial_mark)) = self.quic_marks
                    && let Some(quic) = quic
                {
                    if snapshot.is_some()
                        && quic.has_capacity()
                        && let Some(permit) = self.gate.r2o_try_acquire_queued()
                    {
                        let queued = quic.queue(R2oQuicDiscoveryTask {
                            server: attempt.request.endpoint,
                            snapshot: snapshot.take().expect("снят QUIC Initial"),
                            probe_path: "/".into(),
                            r2o_mark: Some(trial_mark),
                            permit,
                            started_at: now,
                            deny_recheck: false,
                            stall_cut: false,
                            cooldown_key: None,
                            dns: Some(QuicDnsDiscovery {
                                generation: attempt.request.generation,
                                service: state.services[index].clone(),
                                direct_mark,
                                owner: attempt.request.owner,
                            }),
                        });
                        if queued {
                            attempt.phase = Phase::QuicSearch;
                            self.attempt = Some(attempt);
                            return;
                        }
                    } else {
                        self.attempt = Some(attempt);
                        return;
                    }
                }
                self.release(
                    &attempt.request,
                    None,
                    client,
                    state,
                    now,
                    Some("Не удалось подготовить QUIC Initial для DNS Discovery."),
                );
            }
            Phase::QuicSearch => {
                if current.is_some() && now < attempt.expires {
                    self.attempt = Some(attempt);
                } else {
                    self.release(&attempt.request, None, client, state, now, None);
                }
            }
            Phase::Open(command, binding) => {
                let Some(opened) = command.poll(now) else {
                    self.attempt = Some(attempt);
                    return;
                };
                let Some(index) = current.filter(|_| {
                    opened
                        && attempt
                            .request
                            .owner
                            .is_none_or(|uid| dnsproxy_owner() == Some(uid))
                }) else {
                    self.release(
                        &attempt.request,
                        binding.take(),
                        client,
                        state,
                        now,
                        Some("Не удалось подготовить маршрут DNS в firewall."),
                    );
                    return;
                };
                if let Some(mut binding) = binding.take() {
                    state.live[index].verified_recovery = None;
                    if !binding.renew(client) {
                        self.release(
                            &attempt.request,
                            Some(binding),
                            client,
                            state,
                            now,
                            Some("Не удалось продлить план DNS."),
                        );
                        return;
                    }
                    attempt.phase = Phase::Recheck(Recheck::new(
                        binding,
                        &attempt.request,
                        state.services[index].clone(),
                        now,
                    ));
                } else if attempt.request.transport() == 17 {
                    let Ok((local, _)) =
                        start_quic_dns_probe(&attempt.request, state.services[index].clone())
                    else {
                        self.release(
                            &attempt.request,
                            None,
                            client,
                            state,
                            now,
                            Some("Не удалось открыть UDP-сокет для DNS Discovery."),
                        );
                        return;
                    };
                    attempt.phase = Phase::QuicCapture {
                        local,
                        snapshot: None,
                        deadline: now + CHECK_TIMEOUT,
                    };
                } else if !worker.is_active(&attempt.request.target)
                    && worker.queue_with_planned(attempt.request.target.clone(), false)
                {
                    attempt.phase = Phase::Search { started: now };
                } else {
                    self.release(&attempt.request, None, client, state, now, None);
                    return;
                }
                self.attempt = Some(attempt);
            }
            Phase::Recheck(recheck) => {
                let current =
                    current.filter(|_| now < attempt.expires && now < recheck.binding.expires);
                let ready = current.and_then(|_| recheck.poll(now));
                if ready.is_none() && current.is_some() {
                    self.attempt = Some(attempt);
                    return;
                }
                let Phase::Recheck(recheck) = attempt.phase else {
                    unreachable!()
                };
                if let Some(index) = current.filter(|_| ready == Some(true)) {
                    let result = recheck.result.expect("повторная DNS-проверка завершена");
                    let live = &mut state.live[index];
                    live.recovery_phase = None;
                    live.verified_recovery = Some(DnsVerifiedRecovery {
                        plan_id: recheck
                            .binding
                            .plan_id
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect(),
                        checked_at: wall,
                        rtt_ms: result.answer_rtt_ms,
                    });
                    let expires = attempt.expires.min(recheck.binding.expires);
                    self.retained.push(Retained {
                        request: attempt.request,
                        binding: recheck.binding,
                        expires,
                        renew_at: (now + RECHECK_INTERVAL).min(expires - CHECK_TIMEOUT),
                    });
                } else {
                    self.release(
                        &attempt.request,
                        Some(recheck.binding),
                        client,
                        state,
                        now,
                        Some(
                            "Подбор прошёл, но DNS-ответ через установленный план не подтверждён.",
                        ),
                    );
                }
            }
        }
    }

    pub(super) fn observe_applied(&mut self, event: &control::AppliedEvent) {
        if let Some(Attempt {
            request,
            phase: Phase::Recheck(recheck),
            ..
        }) = self.attempt.as_mut()
        {
            recheck.observe(request.endpoint, event);
        }
    }

    pub(super) fn observe_quic_initial(&mut self, key: &[u8; control::KEY_LEN], captured: &[u8]) {
        let Some(Attempt {
            request,
            phase: Phase::QuicCapture {
                local, snapshot, ..
            },
            ..
        }) = self.attempt.as_mut()
        else {
            return;
        };
        let (low, high) = flow_socket_addresses(key, true);
        if snapshot.is_some()
            || !((low == *local && high == request.endpoint)
                || (high == *local && low == request.endpoint))
        {
            return;
        }
        let Some(parsed) = r2k_core::quic_snapshot::r2k_quic_snapshot_parse(captured) else {
            return;
        };
        let sni = if request.owner.is_some() {
            r2k_core::quic::r2k_quic_doh3_sni(parsed.datagrams())
        } else {
            r2k_core::quic::r2k_quic_doq_sni(parsed.datagrams())
        };
        let Ok(sni) = sni else {
            return;
        };
        if sni.as_ref().map_or_else(
            || request.target.host.parse::<std::net::IpAddr>() == Ok(request.endpoint.ip()),
            |sni| sni.eq_ignore_ascii_case(request.target.host.as_bytes()),
        ) {
            *snapshot = Some(captured.to_vec());
        }
    }

    pub(super) fn finish_quic(
        &mut self,
        client: &mut ControlClient,
        state: &mut R2oDnsServices,
        outcome: R2oQuicDiscoveryOutcome,
        now: Instant,
    ) {
        let Some(dns) = outcome.dns else {
            return;
        };
        super::r2o_quic_dns_live_clear(outcome.server);
        if !self.attempt.as_ref().is_some_and(|attempt| {
            matches!(attempt.phase, Phase::QuicSearch)
                && attempt.request.generation == dns.generation
                && attempt.request.owner == dns.owner
                && attempt.request.endpoint == outcome.server
                && attempt
                    .request
                    .target
                    .host
                    .eq_ignore_ascii_case(&outcome.host)
        }) {
            return;
        }
        let proof = outcome.result.ok().flatten().and_then(|(text, _, _)| {
            let plan = PreparedCandidate::new(&text).ok()?;
            Some(R2oDnsTrialEvidence {
                plan_id: plan.plan_id,
                records: plan.wire_records,
            })
        });
        self.finish_attempt(client, state, SHAPE_QUIC, proof, now);
    }

    pub(super) fn finish(
        &mut self,
        client: &mut ControlClient,
        state: &mut R2oDnsServices,
        outcome: &DiscoveryOutcome,
        proof: Option<R2oDnsTrialEvidence>,
        has_timestamp: Option<bool>,
        now: Instant,
    ) -> bool {
        if !self.attempt.as_ref().is_some_and(|attempt| {
            matches!(attempt.phase, Phase::Search { .. })
                && attempt.request.matches(&outcome.target)
        }) {
            return false;
        }
        self.finish_attempt(
            client,
            state,
            r2o_plan_wire_shape(outcome.target.shape, has_timestamp),
            proof,
            now,
        );
        true
    }

    fn finish_attempt(
        &mut self,
        client: &mut ControlClient,
        state: &mut R2oDnsServices,
        shape: u8,
        proof: Option<R2oDnsTrialEvidence>,
        now: Instant,
    ) {
        let mut attempt = self.attempt.take().expect("найдена DNS-задача");
        if let Some(index) = attempt.request.needs_recovery(state)
            && now + CHECK_TIMEOUT < attempt.expires
            && attempt
                .request
                .owner
                .is_none_or(|uid| dnsproxy_owner() == Some(uid))
            && let Some(proof) = proof
            && let Some(binding) = Binding::install(
                client,
                &attempt.request,
                &state.services[index],
                shape,
                proof,
            )
        {
            state.live[index].recovery_phase = Some(DnsRecoveryPhase::Recheck);
            attempt.phase = Phase::Recheck(Recheck::new(
                binding,
                &attempt.request,
                state.services[index].clone(),
                now,
            ));
            self.attempt = Some(attempt);
        } else {
            self.release(
                &attempt.request,
                None,
                client,
                state,
                now,
                Some("Discovery не получил подтверждённого плана для этого DNS-сервиса."),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2o_controller::live::DnsServiceLive;

    #[test]
    fn doq_recovery_refuses_a_shared_identity_with_doh3() {
        let doq = DnsService {
            protocol: "doq".into(),
            host: "resolver.example".into(),
            sni: "resolver.example".into(),
            port: 853,
            ..DnsService::default()
        };
        let doh3 = DnsService {
            protocol: "doh3".into(),
            path: "/dns-query".into(),
            source: "dnsproxy".into(),
            ..doq.clone()
        };
        let mut state = R2oDnsServices {
            services: vec![doq],
            live: vec![DnsServiceLive {
                state: DnsServiceState::Failed,
                ip: "192.0.2.2".into(),
                generation: 1,
                consecutive_network_failures: 2,
                ..DnsServiceLive::default()
            }],
            tasks: Vec::new(),
            generation: 1,
        };
        let job = Request::from_failures(&state, 0, Some(4), None).unwrap();
        assert_eq!(job.transport(), 17);
        assert_eq!(job.target.shape, SHAPE_QUIC);
        state.services.push(doh3);
        state.live.push(state.live[0].clone());
        assert!(job.index(&state).is_none());
        assert!(Request::from_failures(&state, 0, Some(4), None).is_none());
        assert!(Request::from_failures(&state, 1, Some(4), Some(411)).is_none());
        state.services.remove(0);
        state.live.remove(0);
        assert!(Request::from_failures(&state, 0, Some(4), None).is_none());
        assert!(Request::from_failures(&state, 0, Some(4), Some(0)).is_none());
        let owned = Request::from_failures(&state, 0, Some(4), Some(411)).unwrap();
        assert_eq!(owned.owner, Some(411));
        assert_eq!(owned.transport(), 17);
    }

    #[test]
    fn dns_recovery_requires_repeat_failures_for_the_same_endpoint() {
        let service = DnsService {
            protocol: "dot".into(),
            host: "2001:db8::5".into(),
            sni: "resolver.example".into(),
            port: 853,
            ..DnsService::default()
        };
        let mut state = R2oDnsServices {
            services: vec![service.clone()],
            live: vec![DnsServiceLive {
                state: DnsServiceState::Failed,
                ip: "2001:db8::5".into(),
                generation: 17,
                ..DnsServiceLive::default()
            }],
            tasks: vec![r2o_controller::live::DnsTask::default()],
            generation: 17,
        };
        let finish_probe = |state: &mut R2oDnsServices, failure| {
            let slot = state.start_health_task(0, 0).unwrap();
            let generation = state.live[0].generation;
            state.finish_health_task(
                slot,
                generation,
                None,
                DnsHealthResult {
                    failure: Some(failure),
                    ..DnsHealthResult::default()
                },
                1000,
                0,
            );
        };
        finish_probe(&mut state, DnsHealthFailure::Network);
        assert!(Request::from_failures(&state, 0, Some(6), None).is_none());
        finish_probe(&mut state, DnsHealthFailure::Network);
        assert!(Request::from_failures(&state, 0, Some(4), None).is_none());
        let request = Request::from_failures(&state, 0, Some(6), None).unwrap();
        assert_eq!(request.endpoint, "[2001:db8::5]:853".parse().unwrap());
        assert_eq!(request.target.host, "resolver.example");
        assert_eq!(request.index(&state), Some(0));
        for _ in 0..2 {
            finish_probe(&mut state, DnsHealthFailure::NoRoute);
            assert!(Request::from_failures(&state, 0, Some(6), None).is_none());
        }
        assert!(request.needs_recovery(&state).is_none());
        assert!(state.live[0].reason.contains("нет маршрута"));
        finish_probe(&mut state, DnsHealthFailure::Certificate);
        finish_probe(&mut state, DnsHealthFailure::Network);
        assert!(Request::from_failures(&state, 0, Some(6), None).is_none());
        finish_probe(&mut state, DnsHealthFailure::Network);
        finish_probe(&mut state, DnsHealthFailure::Local);
        finish_probe(&mut state, DnsHealthFailure::Network);
        assert!(Request::from_failures(&state, 0, Some(6), None).is_none());
        finish_probe(&mut state, DnsHealthFailure::Network);

        state.services.push(service);
        assert!(Request::from_failures(&state, 0, Some(6), None).is_none());
        assert_eq!(request.index(&state), None);
        state.services.pop();
        state.live[0].generation += 1;
        assert_eq!(request.index(&state), None);
    }

    #[test]
    fn dns_tcp_recovery_yields_only_when_another_service_can_start() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let start = Instant::now();
        let gate = R2oMeasurementGate::new(1);
        let mut worker = DiscoveryWorker::new(None, gate.clone());
        let mut state = R2oDnsServices {
            services: Vec::new(),
            live: Vec::new(),
            tasks: Vec::new(),
            generation: 2,
        };
        for generation in 1..=2 {
            let host = format!("192.0.2.{generation}");
            state.services.push(DnsService {
                protocol: "dot".into(),
                host: host.clone(),
                sni: format!("resolver{generation}.example"),
                port: 853,
                ..Default::default()
            });
            state.live.push(DnsServiceLive {
                state: DnsServiceState::Failed,
                ip: host,
                generation,
                consecutive_network_failures: 2,
                ..Default::default()
            });
        }
        let request = Request::from_failures(&state, 0, Some(4), None).unwrap();
        let key = r2o_discovery_task_key(&request.target);
        let cancel = Arc::new(AtomicBool::new(false));
        worker.active.insert(key.clone(), request.target.clone());
        worker
            .active_cancels
            .lock()
            .unwrap()
            .insert(key, cancel.clone());
        let mut recovery = Recovery {
            firewall: PathBuf::new(),
            family: Some(4),
            quic_marks: None,
            gate,
            attempt: Some(Attempt {
                request,
                phase: Phase::Search { started: start },
                expires: start + ROUTE_TTL,
            }),
            retained: Vec::new(),
            cleanup: Vec::new(),
            next_tick: start,
            next_scan: start,
        };
        let (socket, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(&control::encode_greeting(1500).unwrap())
            .unwrap();
        let mut client = ControlClient::handshake(socket).unwrap();
        let before_share = start + TCP_SEARCH_WITH_WAITERS - Duration::from_secs(1);
        recovery.tick(&mut client, &mut state, &mut worker, None, before_share, 0);
        assert!(!cancel.load(Ordering::Relaxed));

        state.live[1].recovery_retry_at =
            Some(start + TCP_SEARCH_WITH_WAITERS + Duration::from_secs(1));
        let share = start + TCP_SEARCH_WITH_WAITERS;
        recovery.tick(&mut client, &mut state, &mut worker, None, share, 0);
        assert!(!cancel.load(Ordering::Relaxed));

        let ready = share + Duration::from_secs(1);
        recovery.tick(&mut client, &mut state, &mut worker, None, ready, 0);
        assert!(cancel.load(Ordering::Relaxed));
    }

    #[test]
    fn dns_recovery_requires_dns_answer_and_exact_installed_flow() {
        let now = Instant::now();
        let endpoint = "192.0.2.8:853".parse().unwrap();
        let local: SocketAddr = "192.0.2.9:42500".parse().unwrap();
        let context = control::BindingContext {
            generation: 9,
            kind: 1,
            family: 4,
            shape: SHAPE_MODERN,
            temporary: false,
            epoch: [3; 16],
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut recheck = Recheck {
            binding: Binding {
                key: String::new(),
                plan_id: [5; 16],
                records: Vec::new(),
                context,
                expires: now + control::DNS_PLAN_LEASE,
            },
            receiver,
            result: None,
            applied_from: Vec::new(),
            deadline: now + CHECK_TIMEOUT,
        };
        sender
            .send(DnsHealthResult {
                dns_reply: true,
                local_endpoint: Some(local),
                ..DnsHealthResult::default()
            })
            .unwrap();
        assert_eq!(recheck.poll(now), None);
        let mut event = control::AppliedEvent {
            key: super::super::r2o_ask_flow_key(local.ip(), local.port(), endpoint),
            plan_id: [5; 16],
            trial_id: [7; 16],
            execution_id: 1,
            binding: context,
        };
        recheck.observe(endpoint, &event);
        assert_eq!(recheck.poll(now), None);
        event.trial_id = [0; 16];
        event.binding.generation += 1;
        recheck.observe(endpoint, &event);
        assert_eq!(recheck.poll(now), None);
        event.binding = context;
        event.key = super::super::r2o_ask_flow_key(local.ip(), local.port() + 1, endpoint);
        recheck.observe(endpoint, &event);
        assert_eq!(recheck.poll(now), None);
        event.key = super::super::r2o_ask_flow_key(local.ip(), local.port(), endpoint);
        recheck.observe(endpoint, &event);
        assert_eq!(recheck.poll(now), Some(true));
        recheck.result.as_mut().unwrap().dns_reply = false;
        assert_eq!(recheck.poll(now), Some(false));
    }

    #[test]
    fn dns_recovery_sets_and_removes_the_scoped_r2op_binding() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let endpoint = "192.0.2.8:853".parse().unwrap();
        let request = Request {
            endpoint,
            generation: 1,
            owner: None,
            target: DiscoveryTarget {
                host: "resolver.example".into(),
                endpoint: "192.0.2.8:853".into(),
                family: 4,
                shape: SHAPE_MODERN,
                tcp_profile: 0,
            },
        };
        let prepared = super::super::PreparedCandidate::new(
            "r2o-plan 1 11\nid 30313233343536373839616263646566\nproto tcp tls\nsplit sni_middle +0\n",
        ).unwrap();
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let responder = std::thread::spawn(move || {
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            peer.write_all(&control::encode_greeting(1500).unwrap())
                .unwrap();
            let mut plans = r2o_datapath::control::NamePlans::default();
            for command in [
                control::COMMAND_SET_NAME_BOUND,
                control::COMMAND_SET_NAME_BOUND,
                control::COMMAND_DEL_NAME_BOUND,
            ] {
                let frame = control::read_frame(&mut peer).unwrap();
                assert_eq!(frame.kind, command);
                let key_len = usize::from(frame.body[0]);
                assert_eq!(
                    control::dns_tcp_plan_endpoint(&frame.body[1..1 + key_len]),
                    Some(endpoint)
                );
                let ack = plans.handle(&frame);
                assert!(ack.ok);
                peer.write_all(
                    &control::encode_ack_with_binding(
                        ack.command,
                        ack.ok,
                        ack.reason,
                        ack.trial_id,
                        ack.binding_context,
                    )
                    .unwrap(),
                )
                .unwrap();
            }
        });
        let mut client = ControlClient::handshake(socket).unwrap();
        let service = DnsService {
            sni: "resolver.example".into(),
            ..DnsService::default()
        };
        let mut binding = Binding::install(
            &mut client,
            &request,
            &service,
            SHAPE_MODERN,
            R2oDnsTrialEvidence {
                plan_id: prepared.plan_id,
                records: prepared.wire_records,
            },
        )
        .unwrap();
        assert!(binding.context.is_known());
        let old_context = binding.context;
        let old_expires = binding.expires;
        assert!(binding.renew(&mut client));
        assert_ne!(binding.context.generation, old_context.generation);
        assert!(binding.expires >= old_expires);
        binding.remove(&mut client);
        responder.join().unwrap();
    }
}
