use super::{
    ControlClient, DiscoveryOutcome, DiscoveryWorker, Plan, R2oDnsServices, R2oDnsTrialEvidence,
    SHAPE_MODERN, control, encode_delete_name_bound, encode_set_name_bound, flow_socket_addresses,
    r2o_discovery_task_key, r2o_dns_unique_service, r2o_plan_wire_shape, random_id,
};
use r2k_core::dns_config::DnsService;
use r2o_controller::discovery::DiscoveryTarget;
use r2o_controller::dns_health::{DnsHealthResult, probe_dns_health};
use r2o_controller::live::{DnsServiceState, DnsVerifiedRecovery};
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

#[derive(Clone)]
struct Request {
    generation: u64,
    endpoint: SocketAddr,
    target: DiscoveryTarget,
}

impl Request {
    fn from_failures(state: &R2oDnsServices, index: usize, family: Option<u8>) -> Option<Self> {
        let live = state.live.get(index)?;
        let service = state.services.get(index)?;
        if live.state != DnsServiceState::Failed
            || live.consecutive_network_failures < 2
            || service.transport() != 6
            || service.verification_limitation().is_some()
        {
            return None;
        }
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
            r2o_dns_unique_service(&state.services, endpoint, host, 6),
            Ok(Some((matched, _))) if matched == index
        ) {
            return None;
        }
        Some(Self {
            generation: live.generation,
            endpoint,
            target: DiscoveryTarget {
                host: host.clone(),
                endpoint: endpoint.to_string(),
                family: endpoint_family,
                shape: SHAPE_MODERN,
                tcp_profile: 0,
            },
        })
    }

    fn index(&self, state: &R2oDnsServices) -> Option<usize> {
        let (index, _) =
            r2o_dns_unique_service(&state.services, self.endpoint, &self.target.host, 6).ok()??;
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
        let key = control::dns_tcp_plan_key(request.endpoint, service.sni.as_bytes())?;
        let parsed = Plan::parse(&evidence.records).ok()?;
        if parsed.id != evidence.plan_id {
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
            && context.kind == 1
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
        if let Ok(frame) = encode_delete_name_bound(&self.key, 6, self.context) {
            let _ = client.exchange_command_with_timeout(
                &frame,
                control::COMMAND_DEL_NAME_BOUND,
                Duration::from_millis(500),
            );
        }
    }
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
        service.host = request.endpoint.ip().to_string();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(probe_dns_health(&service, None, PROBE_TIMEOUT));
        });
        Self {
            binding,
            receiver,
            result: None,
            applied_from: Vec::new(),
            deadline: now + CHECK_TIMEOUT,
        }
    }

    fn observe(&mut self, endpoint: SocketAddr, event: &control::AppliedEvent) {
        if event.key[37] != 6
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
    Search,
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
    attempt: Option<Attempt>,
    retained: Vec<Retained>,
    cleanup: Vec<RouteCommand>,
    next_tick: Instant,
    next_scan: Instant,
}

impl Recovery {
    pub(super) fn from_environment(mark: Option<u32>, family: Option<u8>) -> Option<Self> {
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
            attempt: None,
            retained: Vec::new(),
            cleanup: Vec::new(),
            next_tick: Instant::now(),
            next_scan: Instant::now(),
        })
    }

    fn route(&self, endpoint: SocketAddr, add: bool, now: Instant) -> Option<RouteCommand> {
        let seconds = if add { ROUTE_TTL.as_secs() } else { 0 };
        let child = Command::new(&self.firewall)
            .args([
                "dns-route",
                if add { "add" } else { "del" },
                &endpoint.ip().to_string(),
                "tcp",
                &endpoint.port().to_string(),
                &seconds.to_string(),
            ])
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
            live.recovery_in_progress = false;
            live.verified_recovery = None;
            if let Some(reason) = reason.filter(|_| live.state == DnsServiceState::Failed) {
                live.reason = reason.to_owned();
            }
            live.recovery_retry_at = Some(now + RETRY);
        }
        if let Some(binding) = binding {
            binding.remove(client);
        }
        if self.cleanup.len() < r2k_core::dns_config::DNS_SERVICE_MAX
            && let Some(cleanup) = self.route(request.endpoint, false, now)
        {
            self.cleanup.push(cleanup);
        }
    }

    pub(super) fn tick(
        &mut self,
        client: &mut ControlClient,
        state: &mut R2oDnsServices,
        worker: &mut DiscoveryWorker,
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

        if let Some(attempt) = self.attempt.take() {
            self.advance(attempt, client, state, worker, now, wall);
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
        let request = (0..state.services.len()).find_map(|index| {
            let request = Request::from_failures(state, index, self.family)?;
            (state.live[index]
                .recovery_retry_at
                .is_none_or(|retry| now >= retry)
                && !self
                    .retained
                    .iter()
                    .any(|entry| entry.request.endpoint == request.endpoint)
                && !worker.is_active(&request.target))
            .then_some(request)
        });
        if let Some(request) = request {
            if worker.r2o_is_watching(&request.target) {
                worker.r2o_forget_watching_task(&r2o_discovery_task_key(&request.target));
            }
            self.open(request, None, client, state, now);
        }
    }

    fn open(
        &mut self,
        request: Request,
        binding: Option<Binding>,
        client: &mut ControlClient,
        state: &mut R2oDnsServices,
        now: Instant,
    ) {
        if let Some(command) = self.route(request.endpoint, true, now) {
            if let Some(index) = request.index(state) {
                state.live[index].recovery_in_progress = true;
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
        now: Instant,
        wall: i64,
    ) {
        let current = attempt.request.needs_recovery(state);
        match &mut attempt.phase {
            Phase::Search => {
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
            Phase::Open(command, binding) => {
                let Some(opened) = command.poll(now) else {
                    self.attempt = Some(attempt);
                    return;
                };
                let Some(index) = current.filter(|_| opened) else {
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
                } else if !worker.is_active(&attempt.request.target)
                    && worker.queue_with_planned(attempt.request.target.clone(), false)
                {
                    attempt.phase = Phase::Search;
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
                    live.recovery_in_progress = false;
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
            matches!(attempt.phase, Phase::Search) && attempt.request.matches(&outcome.target)
        }) {
            return false;
        }
        let mut attempt = self.attempt.take().expect("найдена DNS-задача");
        if let Some(index) = attempt.request.needs_recovery(state)
            && now + CHECK_TIMEOUT < attempt.expires
            && let Some(proof) = proof
            && let Some(binding) = Binding::install(
                client,
                &attempt.request,
                &state.services[index],
                r2o_plan_wire_shape(outcome.target.shape, has_timestamp),
                proof,
            )
        {
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
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2o_controller::live::DnsServiceLive;

    #[test]
    fn dns_recovery_requires_repeat_failures_for_the_same_endpoint() {
        use r2o_controller::dns_health::DnsHealthFailure;
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
        assert!(Request::from_failures(&state, 0, Some(6)).is_none());
        finish_probe(&mut state, DnsHealthFailure::Network);
        assert!(Request::from_failures(&state, 0, Some(4)).is_none());
        let request = Request::from_failures(&state, 0, Some(6)).unwrap();
        assert_eq!(request.endpoint, "[2001:db8::5]:853".parse().unwrap());
        assert_eq!(request.target.host, "resolver.example");
        assert_eq!(request.index(&state), Some(0));
        finish_probe(&mut state, DnsHealthFailure::Certificate);
        finish_probe(&mut state, DnsHealthFailure::Network);
        assert!(Request::from_failures(&state, 0, Some(6)).is_none());
        finish_probe(&mut state, DnsHealthFailure::Network);
        finish_probe(&mut state, DnsHealthFailure::Local);
        finish_probe(&mut state, DnsHealthFailure::Network);
        assert!(Request::from_failures(&state, 0, Some(6)).is_none());
        finish_probe(&mut state, DnsHealthFailure::Network);

        state.services.push(service);
        assert!(Request::from_failures(&state, 0, Some(6)).is_none());
        assert_eq!(request.index(&state), None);
        state.services.pop();
        state.live[0].generation += 1;
        assert_eq!(request.index(&state), None);
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
