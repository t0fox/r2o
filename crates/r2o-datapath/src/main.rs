#[cfg(target_os = "linux")]
mod app {
    use r2k_core::control::{
        ACK_BAD_ARGS, ACK_OK, Ack, AppliedEvent, COMMAND_SET_TCP_STALL_BUDGETS, EVENT_APPLIED,
        EVENT_HELLO, EVENT_HTTP_PORTAL, EVENT_HTTP_RESPONSE, EVENT_R2O_QUIC_STALL,
        EVENT_R2O_QUIC_SUSPECT, EVENT_R2O_TCP_CLEAN_HANDSHAKE, EVENT_R2O_TCP_EARLY_RST,
        EVENT_R2O_TCP_EXCHANGE, EVENT_R2O_TCP_FIN_RETRY, EVENT_R2O_TCP_REPEAT,
        EVENT_R2O_TCP_RST_AFTER_APP, EVENT_R2O_TCP_RST_CUT, EVENT_R2O_TCP_SILENT,
        EVENT_R2O_TCP_STALL, EVENT_R2O_VOICE_SUSPECT, Frame, HttpPortalEvent, HttpResponseEvent,
        PROTOCOL_VERSION, R2oTcpCleanHandshakeEvent, R2oTcpEarlyRstEvent,
        R2oTcpExchangeEvent as R2oTcpExchangeControlEvent, R2oTcpFinRetryEvent, R2oTcpRepeatEvent,
        R2oTcpRstCutSignalEvent, RELEASE_ID, decode_set_tcp_stall_budgets,
    };
    use r2k_core::plan::{EmitKind, OriginalFate, PROTO_VOICE, Plan};
    use r2o_datapath::capture::{tcp_hello_from_packet, tcp_http_hello_from_packet};
    use r2o_datapath::conntrack::R2oConntrackClient;
    use r2o_datapath::control::{ControlServer, NamePlans};
    use r2o_datapath::engine::{
        PacketDecision, R2oTcpExchangeEvent, R2oTcpRstCutEvent, R2oTcpRstEvent, TcpSessions,
        WirePacket, decide_with_session, decide_with_session_mtu, decide_with_session_probe,
        decide_with_session_probe_mtu, validate_runtime_plan,
    };
    use r2o_datapath::flow_capacity::R2oFlowCapacity;
    use r2o_datapath::flow_journal::{R2oFlowJournal, R2oFlowJournalEntry, R2oFlowJournalSummary};
    use r2o_datapath::hold::{HoldOptions, HoldOutcome, HoldTable};
    use r2o_datapath::http_replace::build_http_redirect_packets;
    use r2o_datapath::netlink::{
        MessageIter, NF_ACCEPT, NF_DROP, NFNL_SUBSYS_QUEUE, NFQNL_MSG_PACKET, QueuePacket,
    };
    use r2o_datapath::nfqueue::{QueueSocket, ReceiveError};
    use r2o_datapath::r2o_conntrack_gate::{R2oConntrackGate, guard_decision};
    use r2o_datapath::r2o_icmp_guard::R2oIcmpGuard;
    use r2o_datapath::r2o_quic::R2oQuicSessions;
    use r2o_datapath::r2o_route::{
        R2O_ROUTE_REFRESH_INTERVAL, R2O_ROUTE_SETTLE_INTERVAL, R2oRouteFamily, R2oRouteGate,
        R2oRouteMonitor, R2oRoutePacket, R2oRoutePolicy, R2oRoutedFlows,
    };
    use r2o_datapath::r2o_udp_hold::{
        R2oUdpDeferredResends, R2oUdpDeferredVerdicts, R2oUdpFollowTable, R2oUdpHoldBatch,
        R2oUdpHoldFeed, R2oUdpHoldTable, r2o_release_batch_with, r2o_udp_hold_candidate,
        r2o_udp_send_busy,
    };
    use r2o_datapath::r2o_udp_sessions::R2oUdpSessions;
    use r2o_datapath::r2o_voice::{R2oVoiceSessions, R2oVoiceTrialProofs};
    use r2o_datapath::raw::{RawSocket, r2o_pick_maxlen};
    use r2o_datapath::scheduler::{FlowTicket, ScheduledQueue};
    use std::collections::HashMap;
    use std::error::Error;
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    static STOP: AtomicBool = AtomicBool::new(false);

    fn handle_control_command(
        name_plans: &mut NamePlans,
        tcp_sessions: &mut TcpSessions,
        frame: &Frame,
    ) -> Ack {
        if frame.kind != COMMAND_SET_TCP_STALL_BUDGETS {
            return name_plans.handle(frame);
        }
        let result = decode_set_tcp_stall_budgets(frame)
            .and_then(|budgets| tcp_sessions.set_tcp_stall_budgets(&budgets));
        Ack {
            command: frame.kind,
            ok: result.is_ok(),
            reason: if result.is_ok() { ACK_OK } else { ACK_BAD_ARGS },
            trial_id: None,
        }
    }

    fn r2o_udp_packet_is_neutral(
        route_gate: &R2oRouteGate,
        probe_mark: u32,
        mark: u32,
        bytes: &[u8],
    ) -> bool {
        if mark == 0 || mark == probe_mark {
            return true;
        }
        let Some(view) = r2k_core::packet::PacketView::parse(bytes) else {
            return false;
        };
        let family = if view.family == 4 {
            R2oRouteFamily::Ipv4
        } else {
            R2oRouteFamily::Ipv6
        };
        !route_gate.r2o_mark_is_routed(family, mark)
    }

    fn r2o_udp_mark_plain_pass(
        sessions: &R2oUdpSessions,
        follow: &mut R2oUdpFollowTable,
        route_gate: &R2oRouteGate,
        probe_mark: u32,
        mark: u32,
        packet: &[u8],
        now: Instant,
        receive_seq: u64,
        can_resend: bool,
    ) -> bool {
        if !can_resend
            || !r2k_core::packet::PacketView::parse(packet).is_some_and(|view| {
                view.family == 4 && view.protocol == 17 && view.fragment & 0x3fff == 0
            })
            || !sessions.r2o_udp_opening(packet)
            || !r2o_udp_packet_is_neutral(route_gate, probe_mark, mark, packet)
        {
            return false;
        }
        follow.r2o_mark(packet, now, None, receive_seq)
    }

    fn r2o_release_udp_batch(
        queue: &mut QueueSocket,
        raw: Option<&RawSocket>,
        route_gate: &R2oRouteGate,
        probe_mark: u32,
        batch: &R2oUdpHoldBatch,
        head_verdict: u32,
        head_already_released: bool,
        follow: &mut R2oUdpFollowTable,
        receive_seq: u64,
    ) {
        let now = Instant::now();
        let head = batch.packets.first();
        let head_neutral = head.is_some_and(|packet| {
            raw.is_some()
                && r2o_udp_packet_is_neutral(route_gate, probe_mark, packet.mark, &packet.packet)
        });
        let stats = r2o_release_batch_with(
            batch,
            head_verdict,
            head_already_released,
            raw.is_some(),
            |packet| r2o_udp_packet_is_neutral(route_gate, probe_mark, packet.mark, &packet.packet),
            |packet| raw.expect("raw-сокет проверен").send_packet(&packet.packet),
            |id, verdict| queue.send_verdict(id, verdict),
        );
        if stats.head_succeeded
            && head_verdict == NF_ACCEPT
            && head_neutral
            && let Some(head) = head
        {
            follow.r2o_mark(&head.packet, now, None, receive_seq);
        }
        if stats.resend_failed != 0 {
            eprintln!(
                "r2o-datapath: {} хвостовых UDP-датаграмм не ушли raw и приняты ядром",
                stats.resend_failed
            );
        }
        if stats.verdict_failures != 0 {
            eprintln!(
                "r2o-datapath: не выданы {} вердиктов при освобождении UDP-пачки",
                stats.verdict_failures
            );
        }
    }

    fn r2o_release_udp_batches(
        queue: &mut QueueSocket,
        raw: Option<&RawSocket>,
        route_gate: &R2oRouteGate,
        probe_mark: u32,
        follow: &mut R2oUdpFollowTable,
        receive_seq: u64,
        batches: Vec<R2oUdpHoldBatch>,
    ) {
        for batch in batches {
            r2o_release_udp_batch(
                queue,
                raw,
                route_gate,
                probe_mark,
                &batch,
                NF_ACCEPT,
                false,
                follow,
                receive_seq,
            );
        }
    }

    fn r2o_udp_handle_late_tail(
        queue: &mut QueueSocket,
        raw: Option<&RawSocket>,
        route_gate: &R2oRouteGate,
        probe_mark: u32,
        follow: &mut R2oUdpFollowTable,
        deferred_verdicts: &mut R2oUdpDeferredVerdicts,
        deferred_resends: &mut R2oUdpDeferredResends,
        id: u32,
        mark: u32,
        packet: &[u8],
        now: Instant,
        receive_seq: u64,
        deferred_only: bool,
    ) -> bool {
        let Some(matched) = follow.r2o_match(packet, now, receive_seq) else {
            return false;
        };
        if matched.failed || deferred_only && matched.at.is_none() {
            return false;
        }
        let neutral = r2o_udp_packet_is_neutral(route_gate, probe_mark, mark, packet);
        if let Some(due) = matched.at {
            if neutral && raw.is_some() && deferred_resends.r2o_enqueue(due, id, packet) {
                return true;
            }
            if deferred_verdicts.r2o_enqueue(due, &[id], &[NF_ACCEPT], Some(packet)) {
                return true;
            }
            return false;
        }
        if !neutral {
            return false;
        }
        let Some(raw) = raw else {
            return false;
        };
        match raw.send_packet(packet) {
            Ok(()) => {
                if let Err(error) = queue.send_verdict(id, NF_DROP) {
                    eprintln!("r2o-datapath: не выдан DROP позднего UDP-хвоста: {error}");
                    if let Err(fallback) = queue.send_verdict(id, NF_ACCEPT) {
                        eprintln!("r2o-datapath: не выдан ACCEPT позднего UDP-хвоста: {fallback}");
                    }
                }
            }
            Err(error) => {
                if !r2o_udp_send_busy(&error) {
                    follow.r2o_mark_failed(packet);
                }
                eprintln!("r2o-datapath: поздний UDP-хвост принят ядром: {error}");
                if let Err(verdict_error) = queue.send_verdict(id, NF_ACCEPT) {
                    eprintln!("r2o-datapath: не выдан ACCEPT позднего UDP-хвоста: {verdict_error}");
                }
            }
        }
        true
    }

    fn r2o_release_delayed_udp_batch(
        queue: &mut QueueSocket,
        batch: PendingUdpRelease,
        completed: bool,
    ) {
        let head_fate = if completed {
            batch.fate
        } else if batch.fate == OriginalFate::Drop && batch.payload_on_wire {
            OriginalFate::Drop
        } else {
            OriginalFate::Pass
        };
        let payload_sent = completed || batch.payload_on_wire;
        if let Some((&head, tails)) = batch.ids.split_first() {
            if let Err(error) = release_with(head, head_fate, payload_sent, |id, verdict| {
                queue.send_verdict(id, verdict)
            }) {
                eprintln!("r2o-datapath: не выдан вердикт отложенной UDP-головы: {error}");
            }
            release_accepting(queue, tails);
        }
    }

    fn r2o_cancel_delayed_udp_batch(
        queue: &mut QueueSocket,
        follow: &mut R2oUdpFollowTable,
        deferred_verdicts: &mut R2oUdpDeferredVerdicts,
        deferred_resends: &mut R2oUdpDeferredResends,
        batch: PendingUdpRelease,
    ) {
        follow.r2o_mark_failed(&batch.head_packet);
        let mut late_ids = deferred_verdicts.r2o_cancel_flow(&batch.head_packet);
        late_ids.extend(deferred_resends.r2o_cancel_flow(&batch.head_packet));
        release_accepting(queue, &late_ids);
        r2o_release_delayed_udp_batch(queue, batch, false);
    }

    #[derive(Clone, Copy)]
    struct R2oTcpExecution {
        key: [u8; r2k_core::control::KEY_LEN],
        id: u64,
    }

    fn r2o_finish_tcp_execution(
        sessions: &mut TcpSessions,
        execution: Option<R2oTcpExecution>,
        successful: bool,
        payload_on_wire: bool,
        original_spent: bool,
        original_taken: bool,
    ) -> bool {
        let Some(execution) = execution else {
            return false;
        };
        if successful {
            sessions.r2o_mark_plan_done_for_execution(&execution.key, execution.id);
            false
        } else if payload_on_wire || (original_spent && original_taken) {
            sessions.r2o_mark_damaged_for_execution(&execution.key, execution.id)
        } else {
            sessions.r2o_mark_execution_failed_for_execution(&execution.key, execution.id);
            false
        }
    }

    fn r2o_release_damaged_tcp_hold(
        queue: &mut QueueSocket,
        holding: &mut HoldTable,
        packet: Option<&[u8]>,
    ) {
        if let Some(packet) = packet {
            let ids = holding.r2o_release_damaged_flow(packet);
            release_accepting(queue, &ids);
        }
    }

    fn r2o_execution_is_damaged(
        protocol: u8,
        payload_on_wire: bool,
        original_spent: bool,
        original_taken: bool,
    ) -> bool {
        payload_on_wire || (protocol == 6 && original_spent && original_taken)
    }

    struct PendingApplied {
        event: Option<AppliedEvent>,
        tcp_execution: Option<R2oTcpExecution>,
        sequence: Option<u32>,
        voice_request: Option<Vec<u8>>,
        r2o_udp_packet: Option<Vec<u8>>,
        r2o_tcp_packet: Option<Vec<u8>>,
        r2o_sends_done: bool,
        payload_on_wire: bool,
        original_spent: bool,
        original_taken: bool,
    }

    fn r2o_fail_pending_applied(
        sessions: &mut TcpSessions,
        flow_journal: &mut R2oFlowJournal,
        at_ns: u64,
        pending: &PendingApplied,
        code: u8,
    ) -> bool {
        if pending
            .tcp_execution
            .is_some_and(|execution| !sessions.r2o_send_pending(&execution.key, execution.id))
        {
            return false;
        }
        let damaged = r2o_finish_tcp_execution(
            sessions,
            pending.tcp_execution,
            false,
            pending.payload_on_wire,
            pending.original_spent,
            pending.original_taken,
        );
        if let Some(event) = pending.event.as_ref() {
            flow_journal.record_execution_failure(
                at_ns,
                event,
                code,
                r2o_execution_is_damaged(
                    event.key[37],
                    pending.payload_on_wire,
                    pending.original_spent,
                    pending.original_taken,
                ),
            );
        }
        damaged
    }

    struct PendingUdpRelease {
        ids: Vec<u32>,
        fate: OriginalFate,
        payload_on_wire: bool,
        head_packet: Vec<u8>,
    }

    struct Options {
        plan_path: PathBuf,
        queue: Option<u16>,
        protocol_family: u16,
        mode: RuntimeMode,
        mark: u32,
        interface: Option<String>,
        probe_mark: u32,
        only_mark: Option<R2oRoutePolicy>,
        copy_range: u32,
        queue_len: u32,
        journal_capacity: u32,
        flow_capacity: R2oFlowCapacity,
        r2o_idle_timeout: Duration,
        receive_buffer: i32,
        control_path: Option<PathBuf>,
        controller_only: bool,
        reverse_queue_visible: bool,
        plan_explicit: bool,
        fail_open: bool,
        check_only: bool,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RuntimeMode {
        Observe,
        Apply,
    }

    fn r2o_report_incomplete_captures(holding: &mut HoldTable) {
        for diagnostic in holding.r2o_take_incomplete_diagnostics() {
            match (diagnostic.kind, diagnostic.declared_record_bytes) {
                (r2o_datapath::hold::R2oIncompleteCaptureKind::Tls, Some(declared)) => {
                    eprintln!(
                        "r2o-datapath: TLS ClientHello не собрался для {:?}: запись объявляет {} байт, непрерывно собрано {}",
                        diagnostic.flow, declared, diagnostic.captured_bytes
                    );
                }
                (r2o_datapath::hold::R2oIncompleteCaptureKind::Tls, None) => {
                    eprintln!(
                        "r2o-datapath: TLS ClientHello не собрался для {:?}: заголовок записи не набран, непрерывно собрано {} байт",
                        diagnostic.flow, diagnostic.captured_bytes
                    );
                }
                (r2o_datapath::hold::R2oIncompleteCaptureKind::Http, _) => {
                    eprintln!(
                        "r2o-datapath: HTTP-запрос не собрался для {:?}: непрерывно собрано {} байт",
                        diagnostic.flow, diagnostic.captured_bytes
                    );
                }
            }
        }
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        let arguments: Vec<String> = std::env::args().skip(1).collect();
        if arguments
            .iter()
            .any(|argument| argument == "--help" || argument == "-h")
        {
            print_help();
            return Ok(());
        }
        if arguments
            .iter()
            .any(|argument| argument == "--version" || argument == "-V")
        {
            println!("r2o-datapath release={RELEASE_ID} wire={PROTOCOL_VERSION}");
            return Ok(());
        }
        let options = parse_options(&arguments)?;
        let plan = load_plan(&options)?;
        let mode = if options.mode == RuntimeMode::Observe {
            "observe"
        } else if options.controller_only {
            "controller-only"
        } else if plan.qsplit != 0 {
            "quicsplit"
        } else if plan.qdeny != 0 {
            "quicdeny"
        } else if plan.transport == 6 {
            "tcp"
        } else if plan.proto == PROTO_VOICE {
            "voice"
        } else {
            "udplen"
        };
        if options.check_only {
            println!(
                "план {}: формат исправен, режим {mode}",
                options.plan_path.display()
            );
            return Ok(());
        }
        let send_maxlen = if options.mode == RuntimeMode::Apply {
            r2o_pick_maxlen(options.interface.as_deref())
        } else {
            0
        };

        let queue = options
            .queue
            .ok_or_else(|| invalid("для запуска NFQUEUE укажите --queue N"))?;
        let raw = if needs_raw_socket(options.mode, &plan, options.control_path.is_some()) {
            if options.mark == 0 {
                return Err(invalid("raw-send требует ненулевую --mark"));
            }
            Some(RawSocket::open(
                i32::from(options.protocol_family),
                options.mark,
                options.interface.as_deref(),
            )?)
        } else {
            None
        };
        let family_name = if options.protocol_family == libc::AF_INET as u16 {
            "IPv4"
        } else {
            "IPv6"
        };
        let mut route_gate = R2oRouteGate::default();
        if let Some(policy) = options.only_mark {
            route_gate.r2o_set_policy(Some(policy));
            if policy.found {
                eprintln!(
                    "r2o-datapath: обслуживаю только метку политики 0x{:x}/0x{:x}",
                    policy.mark, policy.mask
                );
            } else {
                eprintln!(
                    "r2o-datapath: выбранная политика не найдена, клиентские потоки пропускаю ядру"
                );
            }
        }
        let mut route_monitor = R2oRouteMonitor::default();
        if let Err(error) = route_monitor.r2o_open_watch() {
            eprintln!(
                "r2o-datapath: уведомления rtnetlink недоступны ({error}); оставляю опрос раз в 30 секунд"
            );
        }
        for error in route_monitor.r2o_refresh(&mut route_gate) {
            eprintln!("r2o-datapath: не удалось обновить маршрутное состояние: {error}");
        }
        if let (Some(raw), Some(ifindices)) = (raw.as_ref(), route_gate.r2o_egress_ifindices())
            && let Some(maxlen) = raw.r2o_adopt_egress(&ifindices)
        {
            eprintln!(
                "r2o-datapath: предел посылки {} байт выбран по MTU выходного маршрута",
                maxlen
            );
        }
        let effective_send_maxlen = raw.as_ref().map_or(send_maxlen, RawSocket::maxlen);
        if effective_send_maxlen != 0 && plan.max_emit() > effective_send_maxlen {
            return Err(invalid(format!(
                "план требует посылку до {} байт, а общий предел равен {}",
                plan.max_emit(),
                effective_send_maxlen
            )));
        }
        let mut control = options
            .control_path
            .as_ref()
            .map(|path| {
                ControlServer::open(
                    path,
                    raw.as_ref()
                        .map_or(u16::MAX as u32, |raw| raw.maxlen() as u32),
                )
            })
            .transpose()?;
        let mut r2o_snapshot_control = options
            .control_path
            .as_ref()
            .map(|path| r2k_core::control::r2k_snapshot_socket_path(path))
            .map(|path| ControlServer::open(path, u16::MAX as u32))
            .transpose()?;
        let mut name_plans = NamePlans::default();
        name_plans.r2o_set_send_maxlen(effective_send_maxlen);
        let mut socket = QueueSocket::open(
            queue,
            options.protocol_family,
            options.copy_range,
            options.queue_len,
            options.fail_open,
            options.receive_buffer,
        )?;
        let mut flow_journal = R2oFlowJournal::with_capacity(options.journal_capacity as usize)?;
        let journal_origin = Instant::now();
        let mut journal_seen = 0_u64;
        let mut journal_peer_connected = false;
        eprintln!(
            "r2o-datapath: очередь {queue}, {family_name}, режим {mode}, fail-open {}",
            if options.fail_open {
                "включён"
            } else {
                "выключен"
            }
        );

        let packet_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET as u16;
        let mut batch = vec![0; 1 << 17];
        let observe_plan = Plan::default();
        let mut scheduled = ScheduledQueue::default();
        let mut pending_applied = HashMap::<FlowTicket, PendingApplied>::new();
        let mut pending_udp_releases = HashMap::<FlowTicket, PendingUdpRelease>::new();
        let mut holding = HoldTable::default();
        let mut tcp_sessions = TcpSessions::try_with_capacity(options.flow_capacity)?;
        let mut conntrack = R2oConntrackClient::open();
        let no_conntrack_table = !std::path::Path::new("/proc/net/nf_conntrack").exists();
        if conntrack.is_none() {
            if no_conntrack_table {
                eprintln!(
                    "r2o-datapath: таблица conntrack отсутствует; планы обычных пакетов используют исходный кортеж, UDP-фрагментация без NAT-контекста отклоняется"
                );
            } else {
                eprintln!(
                    "r2o-datapath: ctnetlink недоступен; обнаружение зависания выключено, планы кроме первого пакета и TCP после SYN-ACK будут отклоняться"
                );
            }
        }
        let mut conntrack_gate =
            R2oConntrackGate::with_table_state(options.flow_capacity.limit(), no_conntrack_table);
        let mut voice_sessions = R2oVoiceSessions::try_with_capacity(options.flow_capacity)?;
        let mut voice_trial_proofs = R2oVoiceTrialProofs::default();
        let mut quic_sessions = R2oQuicSessions::try_with_capacity(options.flow_capacity)?;
        let mut udp_sessions = R2oUdpSessions::with_capacity(options.flow_capacity)?;
        voice_sessions.r2o_set_idle_timeout(options.r2o_idle_timeout);
        quic_sessions.r2o_set_idle_timeout(options.r2o_idle_timeout);
        udp_sessions.r2o_set_idle_timeout(options.r2o_idle_timeout);
        let mut udp_holds = R2oUdpHoldTable::new();
        let mut udp_deferred_verdicts = R2oUdpDeferredVerdicts::new();
        let mut udp_deferred_resends = R2oUdpDeferredResends::new();
        let mut udp_follow = R2oUdpFollowTable::new();
        let mut udp_receive_seq = 0_u64;
        let mut icmp_guard = R2oIcmpGuard::default();
        let mut next_execution_id = 1_u64;
        let mut next_session_sweep = Instant::now();
        let mut routed_flows = R2oRoutedFlows::default();
        let mut last_route_refresh = Instant::now();
        let mut next_route_refresh = last_route_refresh + R2O_ROUTE_REFRESH_INTERVAL;
        install_signal_handlers()?;
        loop {
            if STOP.load(Ordering::Relaxed) {
                eprintln!("r2o-datapath: завершение по сигналу, освобождаю удержанные пакеты");
                drain_queued(&mut socket, &mut batch, packet_type);
                let released = holding.flush(Instant::now(), name_plans.revision(), true);
                r2o_report_incomplete_captures(&mut holding);
                release_accepting(&mut socket, &released);
                for (ticket, pending) in pending_udp_releases.drain() {
                    scheduled.cancel(ticket);
                    r2o_cancel_delayed_udp_batch(
                        &mut socket,
                        &mut udp_follow,
                        &mut udp_deferred_verdicts,
                        &mut udp_deferred_resends,
                        pending,
                    );
                }
                let shutdown_at_ns = journal_timestamp(&journal_origin);
                for (ticket, pending) in pending_applied.drain() {
                    scheduled.cancel(ticket);
                    let damaged = r2o_fail_pending_applied(
                        &mut tcp_sessions,
                        &mut flow_journal,
                        shutdown_at_ns,
                        &pending,
                        r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_QUEUE,
                    );
                    if damaged {
                        r2o_release_damaged_tcp_hold(
                            &mut socket,
                            &mut holding,
                            pending.r2o_tcp_packet.as_deref(),
                        );
                    }
                    if let Some(packet) = pending.r2o_udp_packet.as_deref() {
                        udp_sessions.r2o_note_execution_failure(
                            packet,
                            pending.r2o_sends_done,
                            pending.payload_on_wire,
                            pending.original_spent,
                            pending.original_taken,
                        );
                    }
                }
                r2o_release_udp_batches(
                    &mut socket,
                    raw.as_ref(),
                    &route_gate,
                    options.probe_mark,
                    &mut udp_follow,
                    0,
                    udp_holds.r2o_drain(),
                );
                release_accepting(&mut socket, &udp_deferred_verdicts.r2o_drain_accept());
                release_accepting(&mut socket, &udp_deferred_resends.r2o_drain_accept());
                eprintln!(
                    "r2o-datapath: журнал потоков: {} записей, всего {}, вытеснено {}",
                    flow_journal.count(),
                    flow_journal.added(),
                    flow_journal.dropped()
                );
                let udp_stats = udp_sessions.stats();
                eprintln!(
                    "r2o-datapath: UDP-потоки {} из {}, отказов {}",
                    udp_stats.flows, udp_stats.capacity, udp_stats.refusals
                );
                eprintln!(
                    "r2o-datapath: ответ невидим очереди: {} из {} TCP-потоков с приветствием",
                    tcp_sessions.r2o_reply_hidden(),
                    tcp_sessions.r2o_tcp_hello_flows()
                );
                let payload_stats = tcp_sessions.r2o_tcp_payload_stats();
                eprintln!(
                    "r2o-datapath: нагрузка мимо приветствия: обратная {}, после приветствия {}, за окном {}, не приветствие {} (первый байт {:#04x})",
                    payload_stats.reverse,
                    payload_stats.after_hello,
                    payload_stats.late,
                    payload_stats.not_hello,
                    payload_stats.last_first_byte
                );
                eprintln!(
                    "r2o-datapath: имя ClientHello в следующем сегменте: {}",
                    payload_stats.sni_next_seg
                );
                let http_stats = tcp_sessions.r2o_http_keepalive_stats();
                if http_stats.later != 0 || http_stats.unaligned != 0 || http_stats.open_end != 0 {
                    eprintln!(
                        "r2o-datapath: HTTP с постоянным соединением: следующих запросов распознано {}, границ потеряно или пересечено {}, концов запроса неизвестно {}",
                        http_stats.later, http_stats.unaligned, http_stats.open_end
                    );
                }
                let capture_stats = holding.r2o_capture_stats();
                eprintln!(
                    "r2o-datapath: снимки TLS/TCP: завершено {}, отклонено {}, истекло {}, отказов ёмкости {}",
                    capture_stats.tls_completed,
                    capture_stats.tls_rejected,
                    capture_stats.tls_expired,
                    capture_stats.tls_full
                );
                if icmp_guard.r2o_seen() != 0 || icmp_guard.r2o_noted() != 0 {
                    eprintln!(
                        "r2o-datapath: ICMP: пакетов {}, снято ответов на собственные фальшивки {}, фальшивок с пониженным TTL учтено {}",
                        icmp_guard.r2o_seen(),
                        icmp_guard.r2o_dropped(),
                        icmp_guard.r2o_noted()
                    );
                }
                for entry in flow_journal.iter() {
                    let name = String::from_utf8_lossy(&entry.name[..usize::from(entry.name_len)]);
                    let details = format_journal_details(entry);
                    eprintln!(
                        "r2o-datapath: [{} нс] {} {} {}{}",
                        entry.at_ns,
                        entry.kind.russian_name(),
                        format_journal_key(&entry.key),
                        name,
                        details
                    );
                }
                return Ok(());
            }
            name_plans.r2o_set_send_maxlen(raw.as_ref().map_or(send_maxlen, RawSocket::maxlen));
            let now = Instant::now();
            if now >= next_session_sweep {
                let reverse_queue_visible = options.reverse_queue_visible
                    && control.as_ref().is_some_and(ControlServer::is_connected);
                tcp_sessions.expire_with_silent(now, options.r2o_idle_timeout, |event| {
                    let _ = send_tcp_silent_event(
                        &mut control,
                        &mut flow_journal,
                        &journal_origin,
                        &event,
                    );
                });
                for event in tcp_sessions.sweep_silent(now, reverse_queue_visible) {
                    if send_tcp_silent_event(
                        &mut control,
                        &mut flow_journal,
                        &journal_origin,
                        &event,
                    ) {
                        tcp_sessions.mark_silent(&event.key);
                    }
                }
                if conntrack.is_some() && control.as_ref().is_some_and(ControlServer::is_connected)
                {
                    for probe in tcp_sessions.tcp_stall_candidates() {
                        let Some(info) = conntrack
                            .as_mut()
                            .and_then(|client| client.query(&probe.tuple))
                        else {
                            continue;
                        };
                        let Some(event) = tcp_sessions.update_tcp_stall(now, &probe.key, info)
                        else {
                            continue;
                        };
                        if send_tcp_stall_event(
                            &mut control,
                            &mut flow_journal,
                            &journal_origin,
                            &event,
                        ) {
                            tcp_sessions.mark_tcp_stall(&event.key);
                        }
                    }
                }
                if conntrack.is_some() && reverse_queue_visible {
                    for probe in quic_sessions.r2o_quic_stall_candidates() {
                        let Some(info) = conntrack
                            .as_mut()
                            .and_then(|client| client.query(&probe.tuple))
                        else {
                            continue;
                        };
                        let Some(event) =
                            quic_sessions.update_r2o_quic_stall(now, &probe.key, info)
                        else {
                            continue;
                        };
                        if send_quic_stall_event(
                            &mut control,
                            &mut flow_journal,
                            &journal_origin,
                            &event,
                        ) {
                            quic_sessions.mark_suspected(&event.key);
                        }
                    }
                }
                for event in voice_sessions.sweep(now, reverse_queue_visible) {
                    if send_voice_suspect_event(
                        &mut control,
                        &mut flow_journal,
                        &journal_origin,
                        &event,
                    ) {
                        voice_sessions.mark_suspected(&event.key);
                    }
                }
                for event in quic_sessions.sweep(now, reverse_queue_visible) {
                    if send_quic_suspect_event(
                        &mut control,
                        &mut flow_journal,
                        &journal_origin,
                        &event,
                    ) {
                        quic_sessions.mark_suspected(&event.key);
                    }
                }
                udp_sessions.expire(now);
                next_session_sweep = now + Duration::from_secs(1);
            }
            let timeout = scheduled
                .timeout_ms(now, 200)
                .min(holding.timeout_ms(now, 200))
                .min(udp_holds.timeout_ms(now, 200))
                .min(udp_deferred_verdicts.timeout_ms(now, 200))
                .min(udp_deferred_resends.timeout_ms(now, 200))
                .min(
                    next_route_refresh
                        .saturating_duration_since(now)
                        .as_millis()
                        .min(200) as i32,
                );
            let (received, route_ready) = match socket.receive_timeout_with_fd(
                &mut batch,
                timeout,
                route_monitor.r2o_watch_fd(),
            ) {
                Ok(ready) => ready,
                Err(ReceiveError::LostPackets) => {
                    eprintln!("r2o-datapath: ядро сообщило о потере NFQUEUE пакетов");
                    let released = holding.flush(Instant::now(), name_plans.revision(), true);
                    r2o_report_incomplete_captures(&mut holding);
                    release_accepting(&mut socket, &released);
                    r2o_release_udp_batches(
                        &mut socket,
                        raw.as_ref(),
                        &route_gate,
                        options.probe_mark,
                        &mut udp_follow,
                        0,
                        udp_holds.r2o_drain(),
                    );
                    release_accepting(&mut socket, &udp_deferred_verdicts.r2o_drain_accept());
                    release_accepting(&mut socket, &udp_deferred_resends.r2o_drain_accept());
                    (false, false)
                }
                Err(ReceiveError::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {
                    (false, false)
                }
                Err(ReceiveError::Io(error)) => return Err(error.into()),
            };
            if received {
                udp_receive_seq = udp_receive_seq.wrapping_add(1).max(1);
            }
            let follow_receive_seq = if received { udp_receive_seq } else { 0 };
            udp_follow.r2o_age(now, follow_receive_seq);
            if route_ready {
                match route_monitor.r2o_drain_watch() {
                    Ok(true) => {
                        let settled =
                            (last_route_refresh + R2O_ROUTE_SETTLE_INTERVAL).max(Instant::now());
                        next_route_refresh = next_route_refresh.min(settled);
                    }
                    Ok(false) => {}
                    Err(error) => {
                        eprintln!("r2o-datapath: ошибка чтения уведомлений rtnetlink: {error}");
                    }
                }
            }
            let route_now = Instant::now();
            if route_now >= next_route_refresh {
                for error in route_monitor.r2o_refresh(&mut route_gate) {
                    eprintln!("r2o-datapath: не удалось обновить маршрутное состояние: {error}");
                }
                if let (Some(raw), Some(ifindices)) =
                    (raw.as_ref(), route_gate.r2o_egress_ifindices())
                    && let Some(maxlen) = raw.r2o_adopt_egress(&ifindices)
                {
                    name_plans.r2o_set_send_maxlen(maxlen);
                    if let Some(control) = control.as_mut() {
                        control.r2o_set_send_maxlen(maxlen as u32)?;
                    }
                    eprintln!(
                        "r2o-datapath: предел посылки обновлён до {} байт по MTU выходного маршрута",
                        maxlen
                    );
                }
                last_route_refresh = Instant::now();
                next_route_refresh = last_route_refresh + R2O_ROUTE_REFRESH_INTERVAL;
            }
            if let Some(control) = control.as_mut() {
                for command in control.poll()? {
                    let ack = if command.kind == r2k_core::control::COMMAND_ARM_SHAPE {
                        let (ack, captured) = control.arm_client_shape(&command);
                        if let Some(body) = captured
                            && let Err(error) =
                                control.send_event(r2k_core::control::EVENT_CLIENT_SHAPE, &body)
                        {
                            eprintln!(
                                "r2o-datapath: сохранённый ClientHello не отправлен: {error}"
                            );
                        }
                        ack
                    } else {
                        handle_control_command(&mut name_plans, &mut tcp_sessions, &command)
                    };
                    control.send_ack(ack)?;
                }
                if control.is_connected() && !journal_peer_connected {
                    send_journal_snapshot(control, &flow_journal)?;
                    journal_seen = flow_journal.added();
                    journal_peer_connected = true;
                } else if !control.is_connected() {
                    if journal_peer_connected {
                        voice_sessions.rearm_pending_suspicions();
                    }
                    journal_seen = 0;
                    journal_peer_connected = false;
                    name_plans.clear_probes();
                    // Keep voice proofs for the bounded retry window after a short IPC reconnect.
                }
            }
            if control.as_ref().is_some_and(ControlServer::is_connected) {
                for proof in voice_trial_proofs.pending_proof_events(Instant::now()) {
                    if send_voice_proof_event(
                        &mut control,
                        &mut flow_journal,
                        &journal_origin,
                        &proof,
                    ) {
                        voice_trial_proofs.acknowledge_proof_event(&proof);
                    }
                }
            }
            send_pending_tcp_fin_retry(
                &mut tcp_sessions,
                &mut control,
                &mut flow_journal,
                &journal_origin,
            );
            send_pending_tcp_rst_after_app(
                &mut tcp_sessions,
                &mut control,
                &mut flow_journal,
                &journal_origin,
            );
            if let Some(r2o_snapshot_control) = r2o_snapshot_control.as_mut() {
                let _ = r2o_snapshot_control.poll()?;
            }
            let released = holding.flush(Instant::now(), name_plans.revision(), false);
            r2o_report_incomplete_captures(&mut holding);
            release_accepting(&mut socket, &released);
            r2o_release_udp_batches(
                &mut socket,
                raw.as_ref(),
                &route_gate,
                options.probe_mark,
                &mut udp_follow,
                follow_receive_seq,
                udp_holds.r2o_flush(Instant::now()),
            );
            for event in holding.sweep_http_responses(Instant::now()) {
                send_http_response_event(&mut control, &event);
            }
            if received {
                for message in MessageIter::new(&batch) {
                    if message.kind != packet_type {
                        continue;
                    }
                    let Some(packet) = QueuePacket::parse(&message) else {
                        return Err(invalid(
                            "повреждённое NFQUEUE сообщение без разбора атрибутов",
                        ));
                    };
                    let Some(mut packet_id) = packet.id else {
                        return Err(invalid("NFQUEUE пакет без id; закрываю очередь fail-open"));
                    };
                    let queue_hook = packet.hook;
                    if let Some(bytes) = packet.payload
                        && let Some(drop) = icmp_guard.r2o_handle_at_hook(
                            bytes,
                            queue_hook,
                            journal_timestamp(&journal_origin),
                        )
                    {
                        if drop && icmp_guard.r2o_dropped() == 1 {
                            eprintln!(
                                "r2o-datapath: снят ICMP «время жизни истекло» на собственный пакет с пониженным TTL"
                            );
                        }
                        send_verdicts(
                            &mut socket,
                            std::slice::from_ref(&packet_id),
                            if drop { NF_DROP } else { NF_ACCEPT },
                            drop,
                        )?;
                        continue;
                    }
                    let now = Instant::now();
                    let controller_probe = r2o_is_controller_probe(packet.mark, options.probe_mark);
                    let original_from_queue = r2o_datapath_payload(&packet, options.mark);
                    if options.mode == RuntimeMode::Apply
                        && let Some(bytes) = original_from_queue
                        && r2o_udp_handle_late_tail(
                            &mut socket,
                            raw.as_ref(),
                            &route_gate,
                            options.probe_mark,
                            &mut udp_follow,
                            &mut udp_deferred_verdicts,
                            &mut udp_deferred_resends,
                            packet_id,
                            packet.mark.unwrap_or(0),
                            bytes,
                            now,
                            follow_receive_seq,
                            true,
                        )
                    {
                        continue;
                    }
                    if r2o_packet_route_skip(
                        &mut route_gate,
                        &mut routed_flows,
                        &packet,
                        queue_hook,
                        options.protocol_family,
                        options.probe_mark,
                        options.mark,
                        now,
                    ) {
                        send_verdicts(
                            &mut socket,
                            std::slice::from_ref(&packet_id),
                            NF_ACCEPT,
                            false,
                        )?;
                        continue;
                    }
                    let udp_admitted_from_queue = original_from_queue
                        .map(|bytes| {
                            r2o_udp_packet_admitted_for_mode(
                                options.mode,
                                &mut udp_sessions,
                                bytes,
                                now,
                                queue_hook,
                                controller_probe,
                            )
                        })
                        .unwrap_or(true);
                    let mut replay_packet = None;
                    let mut udp_replay = None;
                    let mut prefetched_quic_hello = None;
                    if options.mode == RuntimeMode::Apply
                        && udp_admitted_from_queue
                        && let Some(bytes) = original_from_queue
                    {
                        r2o_release_udp_batches(
                            &mut socket,
                            raw.as_ref(),
                            &route_gate,
                            options.probe_mark,
                            &mut udp_follow,
                            follow_receive_seq,
                            udp_holds.r2o_flush(Instant::now()),
                        );
                        if r2o_udp_hold_candidate(bytes, queue_hook)
                            && udp_sessions.r2o_begin_hold(bytes)
                        {
                            match udp_holds.r2o_feed(
                                packet_id,
                                packet.mark.unwrap_or(0),
                                bytes,
                                now,
                            ) {
                                R2oUdpHoldFeed::Held => {
                                    prefetched_quic_hello =
                                        quic_sessions.capture_hello_at_hook(bytes, queue_hook);
                                    if prefetched_quic_hello.is_none() {
                                        continue;
                                    }
                                    udp_sessions.r2o_mark_hello_seen(bytes);
                                    let Some(batch) = udp_holds.r2o_take(bytes) else {
                                        continue;
                                    };
                                    let Some(head) = batch.packets.first() else {
                                        continue;
                                    };
                                    packet_id = head.id;
                                    replay_packet = Some(head.packet.clone());
                                    udp_replay = Some(batch);
                                }
                                R2oUdpHoldFeed::Overflow(batch) => {
                                    r2o_release_udp_batch(
                                        &mut socket,
                                        raw.as_ref(),
                                        &route_gate,
                                        options.probe_mark,
                                        &batch,
                                        NF_ACCEPT,
                                        false,
                                        &mut udp_follow,
                                        udp_receive_seq,
                                    );
                                }
                                R2oUdpHoldFeed::Refused => {}
                            }
                        }
                    }
                    if let Some(replay) = replay_packet.as_deref() {
                        udp_sessions.r2o_mark_hold_replay_first(replay);
                    }
                    let original = replay_packet.as_deref().or(original_from_queue);
                    let udp_admitted = original
                        .map(|bytes| {
                            if replay_packet.is_some() {
                                r2o_udp_packet_admitted_at_hook(
                                    &mut udp_sessions,
                                    bytes,
                                    now,
                                    queue_hook,
                                    controller_probe,
                                )
                            } else {
                                udp_admitted_from_queue
                            }
                        })
                        .unwrap_or(true);
                    if options.mode == RuntimeMode::Observe
                        && udp_admitted
                        && let Some(bytes) = original
                    {
                        if controller_probe {
                            let _ =
                                decide_with_session_probe(&mut tcp_sessions, &observe_plan, bytes);
                        } else {
                            let _ = decide_with_session(&mut tcp_sessions, &observe_plan, bytes);
                        }
                    }
                    let quic_hook = original
                        .filter(|_| udp_admitted)
                        .map(|bytes| {
                            quic_sessions.quic_direction_hook_for_packet(bytes, queue_hook)
                        })
                        .unwrap_or(queue_hook);
                    let mut batch_ids = Vec::new();
                    let mut synthetic = None;
                    let mut response_candidate = None;
                    let mut portal_candidate = None;
                    let mut redirect_candidate = None;
                    let mut udp_quic_deny = false;
                    let decision = if let Some(bytes) = original.filter(|_| udp_admitted) {
                        if options.mode == RuntimeMode::Apply {
                            if !controller_probe {
                                scheduled.observe(bytes, now);
                            }
                            pending_applied.retain(|ticket, _| scheduled.has_pending(*ticket));
                            if !controller_probe {
                                voice_sessions.observe_packet(bytes, now);
                                observe_stun_packet(
                                    &mut udp_sessions,
                                    bytes,
                                    now,
                                    queue_hook,
                                    &mut flow_journal,
                                    &journal_origin,
                                );
                                if let Some(r2o_proof) =
                                    voice_trial_proofs.observe_response(bytes, now)
                                {
                                    if send_voice_proof_event(
                                        &mut control,
                                        &mut flow_journal,
                                        &journal_origin,
                                        &r2o_proof,
                                    ) {
                                        voice_trial_proofs.acknowledge_proof_event(&r2o_proof);
                                    }
                                }
                            }
                        }
                        let family =
                            r2k_core::packet::PacketView::parse(bytes).map(|view| view.family);
                        let allow_tls = options.mode == RuntimeMode::Apply
                            && (is_tls_plan(&plan)
                                || family
                                    .is_some_and(|family| name_plans.has_tls_candidate(family)));
                        let allow_http = options.mode == RuntimeMode::Apply
                            && family.is_some_and(|family| name_plans.has_http_candidate(family));
                        let observe_tls = !controller_probe
                            && (control.as_ref().is_some_and(ControlServer::is_connected)
                                || r2o_snapshot_control
                                    .as_ref()
                                    .is_some_and(ControlServer::is_connected));
                        let observe_http = !controller_probe
                            && control.as_ref().is_some_and(ControlServer::is_connected);
                        let tcp_flow_damaged = tcp_sessions.r2o_is_damaged_packet(bytes);
                        if tcp_flow_damaged {
                            let released = holding.r2o_release_damaged_flow(bytes);
                            release_accepting(&mut socket, &released);
                        }
                        let inspect_quic = observe_tls
                            || family.is_some_and(|family| name_plans.has_quic_candidate(family));
                        let quic_hello = prefetched_quic_hello.take().or_else(|| {
                            inspect_quic
                                .then(|| quic_sessions.capture_hello_at_hook(bytes, queue_hook))
                                .flatten()
                        });
                        if quic_hello.is_some() {
                            udp_sessions.r2o_mark_hello_seen(bytes);
                        }
                        let selected_plan = name_plans
                            .select_with_quic_host_at_hook(
                                bytes,
                                quic_hello.as_ref().map(|hello| hello.host.as_slice()),
                                quic_hook,
                            )
                            .unwrap_or(&plan);
                        udp_quic_deny = selected_plan.qdeny != 0 && !controller_probe;
                        if options.mode == RuntimeMode::Apply {
                            if selected_plan.qdeny != 0 && !controller_probe {
                                quic_sessions.suppress_packet(bytes);
                            } else if !controller_probe {
                                observe_quic_packet(
                                    &mut quic_sessions,
                                    bytes,
                                    now,
                                    queue_hook,
                                    &mut flow_journal,
                                    &journal_origin,
                                );
                            }
                        }
                        if !controller_probe
                            && observe_tls
                            && let Some(body) =
                                quic_hello.as_ref().and_then(|hello| hello.event_body())
                        {
                            send_hello_event(
                                &mut control,
                                &mut r2o_snapshot_control,
                                &mut flow_journal,
                                journal_origin.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                                &body,
                                None,
                            );
                        }
                        let hold_options = HoldOptions {
                            revision: name_plans.revision(),
                            allow_tls: allow_tls && !tcp_flow_damaged,
                            allow_http: allow_http && !tcp_flow_damaged,
                            observe_tls,
                            observe_http,
                        };
                        let fed = if controller_probe {
                            holding.feed_controller_probe(packet_id, bytes, now, hold_options)
                        } else {
                            holding.feed_observing(packet_id, bytes, now, hold_options)
                        };
                        r2o_report_incomplete_captures(&mut holding);
                        release_accepting(&mut socket, &fed.released);
                        match fed.outcome {
                            HoldOutcome::Pass => {
                                if options.mode == RuntimeMode::Observe {
                                    PacketDecision::Accept
                                } else {
                                    let first_udp_packet =
                                        udp_sessions.r2o_is_first_client_packet(bytes);
                                    r2o_udp_decide_once(
                                        &mut udp_sessions,
                                        &mut quic_sessions,
                                        selected_plan,
                                        bytes,
                                        || {
                                            let decision = decide_with_tcp_session_mode(
                                                &mut tcp_sessions,
                                                selected_plan,
                                                bytes,
                                                &mut control,
                                                &mut flow_journal,
                                                &journal_origin,
                                                controller_probe,
                                                raw.as_ref().map_or(0, |raw| {
                                                    raw.tls_route_segment_cap(bytes)
                                                }),
                                            );
                                            let tcp_syn_ack_seen =
                                                tcp_sessions.r2o_syn_ack_seen_for_packet(bytes);
                                            guard_decision(
                                                &mut conntrack_gate,
                                                &mut conntrack,
                                                bytes,
                                                decision,
                                                selected_plan.id,
                                                first_udp_packet,
                                                tcp_syn_ack_seen,
                                            )
                                        },
                                    )
                                }
                            }
                            HoldOutcome::Waiting => continue,
                            HoldOutcome::Drop => PacketDecision::Drop,
                            HoldOutcome::Ready { ids, packet } => {
                                if !controller_probe
                                    && let Some(hello) = tcp_hello_from_packet(&packet)
                                        .or_else(|| tcp_http_hello_from_packet(&packet))
                                {
                                    send_hello_event(
                                        &mut control,
                                        &mut r2o_snapshot_control,
                                        &mut flow_journal,
                                        journal_origin.elapsed().as_nanos().min(u64::MAX as u128)
                                            as u64,
                                        &hello.event_body(),
                                        hello.shape_event_body(),
                                    );
                                }
                                let decision = if options.mode == RuntimeMode::Observe {
                                    PacketDecision::Accept
                                } else {
                                    let decision = decide_with_tcp_session_mode(
                                        &mut tcp_sessions,
                                        name_plans
                                            .select_with_quic_host(&packet, None)
                                            .unwrap_or(&plan),
                                        &packet,
                                        &mut control,
                                        &mut flow_journal,
                                        &journal_origin,
                                        controller_probe,
                                        raw.as_ref()
                                            .map_or(0, |raw| raw.tls_route_segment_cap(&packet)),
                                    );
                                    let selected = name_plans
                                        .select_with_quic_host(&packet, None)
                                        .unwrap_or(&plan);
                                    let tcp_syn_ack_seen =
                                        tcp_sessions.r2o_syn_ack_seen_for_packet(&packet);
                                    guard_decision(
                                        &mut conntrack_gate,
                                        &mut conntrack,
                                        &packet,
                                        decision,
                                        selected.id,
                                        false,
                                        tcp_syn_ack_seen,
                                    )
                                };
                                batch_ids = ids;
                                synthetic = Some(packet);
                                decision
                            }
                            HoldOutcome::Observed { hello } => {
                                tcp_sessions.r2o_note_captured_client_shape(bytes, hello.shape);
                                if !controller_probe {
                                    send_hello_event(
                                        &mut control,
                                        &mut r2o_snapshot_control,
                                        &mut flow_journal,
                                        journal_origin.elapsed().as_nanos().min(u64::MAX as u128)
                                            as u64,
                                        &hello.event_body(),
                                        hello.shape_event_body(),
                                    );
                                }
                                if options.mode == RuntimeMode::Observe {
                                    PacketDecision::Accept
                                } else {
                                    let decision = decide_with_tcp_session_mode(
                                        &mut tcp_sessions,
                                        selected_plan,
                                        bytes,
                                        &mut control,
                                        &mut flow_journal,
                                        &journal_origin,
                                        controller_probe,
                                        raw.as_ref()
                                            .map_or(0, |raw| raw.tls_route_segment_cap(bytes)),
                                    );
                                    let tcp_syn_ack_seen =
                                        tcp_sessions.r2o_syn_ack_seen_for_packet(bytes);
                                    guard_decision(
                                        &mut conntrack_gate,
                                        &mut conntrack,
                                        bytes,
                                        decision,
                                        selected_plan.id,
                                        false,
                                        tcp_syn_ack_seen,
                                    )
                                }
                            }
                            HoldOutcome::HttpResponse {
                                event,
                                portal,
                                redirect,
                            } => {
                                if !controller_probe {
                                    response_candidate = Some(event);
                                    portal_candidate = portal;
                                    redirect_candidate = redirect;
                                }
                                PacketDecision::Accept
                            }
                        }
                    } else {
                        PacketDecision::Accept
                    };
                    let ids = if batch_ids.is_empty() {
                        std::slice::from_ref(&packet_id)
                    } else {
                        batch_ids.as_slice()
                    };
                    let redirect_packets = if options.mode == RuntimeMode::Apply
                        && raw.is_some()
                        && let (Some(redirect), Some(event), Some(packet)) = (
                            redirect_candidate.as_deref(),
                            response_candidate.as_ref(),
                            original,
                        )
                        && name_plans.has_verified_https(&event.host, Instant::now())
                    {
                        build_http_redirect_packets(packet, redirect)
                    } else {
                        None
                    };
                    let tx_original = synthetic.as_deref().or(original);
                    let tx_sequence = tx_original.and_then(|packet| {
                        r2k_core::packet::PacketView::parse(packet)?
                            .tcp_segment(packet)
                            .map(|segment| segment.sequence)
                    });
                    if !controller_probe
                        && let (PacketDecision::Refused { plan_id }, Some(packet)) =
                            (&decision, tx_original)
                        && let Some(key) =
                            r2o_datapath::control::flow_journal_key_for_packet(packet)
                    {
                        let event = name_plans
                            .applied_event_for_packet_at_hook(packet, next_execution_id, quic_hook)
                            .filter(|event| event.plan_id == *plan_id);
                        let (trial_id, execution_id, binding) = if let Some(event) = event {
                            next_execution_id = next_execution_id.wrapping_add(1).max(1);
                            (event.trial_id, event.execution_id, Some(event.binding))
                        } else {
                            ([0; 16], 0, None)
                        };
                        flow_journal.record_plan_refused(
                            journal_timestamp(&journal_origin),
                            key,
                            *plan_id,
                            trial_id,
                            execution_id,
                            binding,
                        );
                    }
                    let decision_execution_id = if matches!(
                        &decision,
                        PacketDecision::Replace(_) | PacketDecision::Transmit { .. }
                    ) && tx_original.is_some()
                    {
                        let execution_id = next_execution_id;
                        next_execution_id = next_execution_id.wrapping_add(1).max(1);
                        Some(execution_id)
                    } else {
                        None
                    };
                    let tcp_execution =
                        tx_original
                            .zip(decision_execution_id)
                            .and_then(|(packet, id)| {
                                tcp_sessions
                                    .r2o_begin_execution(packet, id)
                                    .map(|key| R2oTcpExecution { key, id })
                            });
                    let mut applied_candidate = decision_execution_id.and_then(|execution_id| {
                        tx_original.and_then(|bytes| {
                            name_plans.applied_event_for_packet_at_hook(
                                bytes,
                                execution_id,
                                quic_hook,
                            )
                        })
                    });
                    if !controller_probe && let Some(event) = applied_candidate.as_ref() {
                        flow_journal
                            .record_plan_prepared(journal_timestamp(&journal_origin), event);
                    }
                    let mut execution_succeeded = false;
                    let mut response_delivered = false;
                    let mut udp_batch_handled = false;
                    let mut udp_batch_deferred = false;
                    let mut udp_head_verdict = NF_ACCEPT;
                    if let Some((replacement, reset)) = redirect_packets {
                        if ids.len() == 1 {
                            let id = ids[0];
                            if let Err(error) = socket.send_replacement(id, &replacement) {
                                eprintln!("r2o-datapath: не отправлен HTTPS verdict: {error}");
                                socket.send_verdict(id, NF_ACCEPT)?;
                                if let Some(event) = applied_candidate.as_ref() {
                                    flow_journal.record_execution_failure(
                                        journal_timestamp(&journal_origin),
                                        event,
                                        r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_SEND,
                                        false,
                                    );
                                }
                            } else {
                                if let Some(raw) = raw.as_ref()
                                    && let Err(error) = raw.send_packet(&reset)
                                {
                                    eprintln!(
                                        "r2o-datapath: не отправлен сброс исходного HTTP-потока: {error}"
                                    );
                                }
                                if let Some(event) = response_candidate.as_ref() {
                                    holding
                                        .mark_http_response_answered(&event.key, event.request_no);
                                }
                                if let Some(portal) = portal_candidate.as_mut() {
                                    portal.answered = true;
                                }
                            }
                            response_delivered = true;
                        } else {
                            send_verdicts(&mut socket, ids, NF_ACCEPT, false)?;
                            response_delivered = true;
                        }
                    } else {
                        match decision {
                            PacketDecision::Accept => {
                                let late_tail_handled = udp_replay.is_none()
                                    && original.is_some_and(|bytes| {
                                        r2o_udp_handle_late_tail(
                                            &mut socket,
                                            raw.as_ref(),
                                            &route_gate,
                                            options.probe_mark,
                                            &mut udp_follow,
                                            &mut udp_deferred_verdicts,
                                            &mut udp_deferred_resends,
                                            packet_id,
                                            packet.mark.unwrap_or(0),
                                            bytes,
                                            Instant::now(),
                                            follow_receive_seq,
                                            false,
                                        )
                                    });
                                if !late_tail_handled {
                                    send_verdicts(&mut socket, ids, NF_ACCEPT, false)?;
                                    if options.mode == RuntimeMode::Apply
                                        && !controller_probe
                                        && let Some(bytes) = original
                                    {
                                        observe_voice_trial_rtp_packet(
                                            &mut voice_trial_proofs,
                                            bytes,
                                            now,
                                            &mut control,
                                            &mut flow_journal,
                                            &journal_origin,
                                        );
                                    }
                                    if options.mode == RuntimeMode::Apply
                                        && !controller_probe
                                        && udp_replay.is_none()
                                        && let Some(bytes) = original
                                    {
                                        r2o_udp_mark_plain_pass(
                                            &udp_sessions,
                                            &mut udp_follow,
                                            &route_gate,
                                            options.probe_mark,
                                            packet.mark.unwrap_or(0),
                                            bytes,
                                            now,
                                            udp_receive_seq,
                                            raw.is_some(),
                                        );
                                    }
                                }
                                response_delivered = true;
                            }
                            PacketDecision::Refused { .. } => {
                                let late_tail_handled = udp_replay.is_none()
                                    && original.is_some_and(|bytes| {
                                        r2o_udp_handle_late_tail(
                                            &mut socket,
                                            raw.as_ref(),
                                            &route_gate,
                                            options.probe_mark,
                                            &mut udp_follow,
                                            &mut udp_deferred_verdicts,
                                            &mut udp_deferred_resends,
                                            packet_id,
                                            packet.mark.unwrap_or(0),
                                            bytes,
                                            Instant::now(),
                                            follow_receive_seq,
                                            false,
                                        )
                                    });
                                if !late_tail_handled {
                                    send_verdicts(&mut socket, ids, NF_ACCEPT, false)?;
                                    if options.mode == RuntimeMode::Apply
                                        && !controller_probe
                                        && let Some(bytes) = original
                                    {
                                        observe_voice_trial_rtp_packet(
                                            &mut voice_trial_proofs,
                                            bytes,
                                            now,
                                            &mut control,
                                            &mut flow_journal,
                                            &journal_origin,
                                        );
                                    }
                                    if options.mode == RuntimeMode::Apply
                                        && !controller_probe
                                        && udp_replay.is_none()
                                        && let Some(bytes) = original
                                    {
                                        r2o_udp_mark_plain_pass(
                                            &udp_sessions,
                                            &mut udp_follow,
                                            &route_gate,
                                            options.probe_mark,
                                            packet.mark.unwrap_or(0),
                                            bytes,
                                            now,
                                            udp_receive_seq,
                                            raw.is_some(),
                                        );
                                    }
                                }
                                response_delivered = true;
                            }
                            PacketDecision::Drop => {
                                if udp_quic_deny && let Some(batch) = udp_replay.as_ref() {
                                    let all_ids = batch
                                        .packets
                                        .iter()
                                        .map(|packet| packet.id)
                                        .collect::<Vec<_>>();
                                    send_verdicts(&mut socket, &all_ids, NF_DROP, true)?;
                                    udp_batch_handled = true;
                                } else {
                                    send_verdicts(&mut socket, ids, NF_DROP, true)?;
                                    udp_head_verdict = NF_DROP;
                                }
                            }
                            PacketDecision::Replace(replacement) => {
                                if ids.len() == 1 {
                                    let id = ids[0];
                                    if let Err(error) = socket.send_replacement(id, &replacement) {
                                        eprintln!(
                                            "r2o-datapath: не отправлен replacement verdict: {error}"
                                        );
                                        socket.send_verdict(id, NF_ACCEPT)?;
                                        if let Some(event) = applied_candidate.as_ref() {
                                            flow_journal.record_execution_failure(
                                                journal_timestamp(&journal_origin),
                                                event,
                                                r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_SEND,
                                                false,
                                            );
                                        }
                                        let damaged = r2o_finish_tcp_execution(
                                            &mut tcp_sessions,
                                            tcp_execution,
                                            false,
                                            false,
                                            false,
                                            false,
                                        );
                                        if damaged {
                                            r2o_release_damaged_tcp_hold(
                                                &mut socket,
                                                &mut holding,
                                                tx_original,
                                            );
                                        }
                                        response_delivered = true;
                                    } else {
                                        execution_succeeded = true;
                                    }
                                } else {
                                    send_verdicts(&mut socket, ids, NF_ACCEPT, false)?;
                                    r2o_finish_tcp_execution(
                                        &mut tcp_sessions,
                                        tcp_execution,
                                        false,
                                        false,
                                        false,
                                        false,
                                    );
                                    response_delivered = true;
                                }
                            }
                            PacketDecision::Transmit { packets, fate } => {
                                let deferred_due = udp_replay
                                    .as_ref()
                                    .and_then(|_| r2o_udp_deferred_due(&packets, now));
                                let Some(tx_original) = tx_original else {
                                    if let Some(batch) = udp_replay.as_ref() {
                                        let all_ids = batch
                                            .packets
                                            .iter()
                                            .map(|packet| packet.id)
                                            .collect::<Vec<_>>();
                                        release_accepting(&mut socket, &all_ids);
                                    } else {
                                        send_verdicts(&mut socket, ids, NF_ACCEPT, false)?;
                                    }
                                    if let Some(event) = applied_candidate.as_ref() {
                                        flow_journal.record_execution_failure(
                                            journal_timestamp(&journal_origin),
                                            event,
                                            r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_SEND,
                                            false,
                                        );
                                    }
                                    continue;
                                };
                                match transmit_many(
                                    &mut socket,
                                    raw.as_ref(),
                                    &mut scheduled,
                                    &mut icmp_guard,
                                    if udp_replay.is_some() { &[] } else { ids },
                                    tx_original,
                                    packets,
                                    fate,
                                    &journal_origin,
                                )? {
                                    TransmissionOutcome::Complete => {
                                        if udp_replay.is_some() {
                                            let verdict = if fate == OriginalFate::Pass {
                                                NF_ACCEPT
                                            } else {
                                                NF_DROP
                                            };
                                            send_verdicts(
                                                &mut socket,
                                                std::slice::from_ref(&packet_id),
                                                verdict,
                                                verdict == NF_DROP,
                                            )?;
                                            udp_head_verdict = verdict;
                                        }
                                        execution_succeeded = true;
                                        response_delivered = fate == OriginalFate::Pass;
                                    }
                                    TransmissionOutcome::Pending {
                                        ticket,
                                        r2o_sends_done,
                                        payload_on_wire,
                                    } => {
                                        response_delivered = fate == OriginalFate::Pass;
                                        if let Some(batch) = udp_replay.as_ref() {
                                            let all_ids = batch
                                                .packets
                                                .iter()
                                                .map(|packet| packet.id)
                                                .collect::<Vec<_>>();
                                            let due = deferred_due.unwrap_or_else(Instant::now);
                                            let head_packet = batch
                                                .packets
                                                .first()
                                                .map(|head| head.packet.clone())
                                                .unwrap_or_default();
                                            pending_udp_releases.insert(
                                                ticket,
                                                PendingUdpRelease {
                                                    ids: all_ids,
                                                    fate,
                                                    payload_on_wire,
                                                    head_packet: head_packet.clone(),
                                                },
                                            );
                                            udp_batch_deferred = true;
                                            if fate == OriginalFate::Pass
                                                && !head_packet.is_empty()
                                                && raw.is_some()
                                                && batch.packets.first().is_some_and(|head| {
                                                    r2o_udp_packet_is_neutral(
                                                        &route_gate,
                                                        options.probe_mark,
                                                        head.mark,
                                                        &head.packet,
                                                    )
                                                })
                                            {
                                                udp_follow.r2o_mark(
                                                    &head_packet,
                                                    Instant::now(),
                                                    Some(due),
                                                    udp_receive_seq,
                                                );
                                            }
                                        }
                                        if !udp_batch_handled {
                                            let event = applied_candidate.take();
                                            let r2o_is_udp =
                                                r2k_core::packet::PacketView::parse(tx_original)
                                                    .is_some_and(|view| view.protocol == 17);
                                            if event.is_some()
                                                || r2o_is_udp
                                                || tcp_execution.is_some()
                                            {
                                                let voice_request = event
                                                    .as_ref()
                                                    .is_some_and(|event| {
                                                        event.binding.kind == 2
                                                            && event.binding.temporary
                                                    })
                                                    .then(|| tx_original.to_vec());
                                                let r2o_udp_packet =
                                                    r2o_is_udp.then(|| tx_original.to_vec());
                                                pending_applied.insert(
                                                    ticket,
                                                    PendingApplied {
                                                        event,
                                                        tcp_execution,
                                                        sequence: tx_sequence,
                                                        voice_request,
                                                        r2o_udp_packet,
                                                        r2o_tcp_packet: tcp_execution
                                                            .map(|_| tx_original.to_vec()),
                                                        r2o_sends_done,
                                                        payload_on_wire,
                                                        original_spent: !udp_batch_deferred,
                                                        original_taken: fate == OriginalFate::Drop,
                                                    },
                                                );
                                            }
                                        }
                                    }
                                    TransmissionOutcome::Failed {
                                        code,
                                        r2o_sends_done,
                                        payload_on_wire,
                                        original_spent,
                                        original_taken,
                                    } => {
                                        if let Some(batch) = udp_replay.as_ref() {
                                            let pending = PendingUdpRelease {
                                                ids: batch
                                                    .packets
                                                    .iter()
                                                    .map(|packet| packet.id)
                                                    .collect(),
                                                fate,
                                                payload_on_wire,
                                                head_packet: batch
                                                    .packets
                                                    .first()
                                                    .map(|head| head.packet.clone())
                                                    .unwrap_or_default(),
                                            };
                                            udp_head_verdict =
                                                if fate == OriginalFate::Drop && payload_on_wire {
                                                    NF_DROP
                                                } else {
                                                    NF_ACCEPT
                                                };
                                            r2o_release_delayed_udp_batch(
                                                &mut socket,
                                                pending,
                                                false,
                                            );
                                            udp_batch_handled = true;
                                        }
                                        if let Some(event) = applied_candidate.as_ref() {
                                            flow_journal.record_execution_failure(
                                                journal_timestamp(&journal_origin),
                                                event,
                                                code,
                                                r2o_execution_is_damaged(
                                                    event.key[37],
                                                    payload_on_wire,
                                                    original_spent,
                                                    original_taken,
                                                ),
                                            );
                                        }
                                        let damaged = r2o_finish_tcp_execution(
                                            &mut tcp_sessions,
                                            tcp_execution,
                                            false,
                                            payload_on_wire,
                                            original_spent,
                                            original_taken,
                                        );
                                        if damaged {
                                            r2o_release_damaged_tcp_hold(
                                                &mut socket,
                                                &mut holding,
                                                Some(tx_original),
                                            );
                                        }
                                        udp_sessions.r2o_note_execution_failure(
                                            tx_original,
                                            r2o_sends_done,
                                            payload_on_wire,
                                            false,
                                            fate == OriginalFate::Drop,
                                        );
                                    }
                                }
                            }
                        }
                    }
                    if let Some(batch) = udp_replay.as_ref()
                        && !udp_batch_deferred
                        && !udp_batch_handled
                    {
                        r2o_release_udp_batch(
                            &mut socket,
                            raw.as_ref(),
                            &route_gate,
                            options.probe_mark,
                            batch,
                            udp_head_verdict,
                            true,
                            &mut udp_follow,
                            udp_receive_seq,
                        );
                    }
                    if !controller_probe && let Some(mut event) = response_candidate {
                        if !response_delivered {
                            holding.reject_http_response(&event.key, event.request_no);
                            event.code = 2;
                            portal_candidate = None;
                        }
                        send_http_response_event(&mut control, &event);
                        if let Some(portal) = portal_candidate {
                            send_http_portal_event(&mut control, &portal);
                        }
                    }
                    if execution_succeeded {
                        r2o_finish_tcp_execution(
                            &mut tcp_sessions,
                            tcp_execution,
                            true,
                            false,
                            false,
                            false,
                        );
                    }
                    if execution_succeeded && let Some(event) = applied_candidate {
                        if !controller_probe && let Some(packet) = tx_original {
                            voice_trial_proofs.note_applied(packet, &event, Instant::now());
                        }
                        if !controller_probe && let Some(sequence) = tx_sequence {
                            holding.note_http_execution(sequence, &event);
                        }
                        send_applied_event(
                            &mut tcp_sessions,
                            &mut control,
                            &mut flow_journal,
                            journal_origin.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                            &event,
                        );
                    }
                }
            }
            flush_scheduled(
                &mut socket,
                raw.as_ref(),
                &mut scheduled,
                &mut pending_applied,
                &mut pending_udp_releases,
                &mut udp_follow,
                &mut udp_deferred_verdicts,
                &mut udp_deferred_resends,
                &mut tcp_sessions,
                &mut udp_sessions,
                &mut control,
                &mut holding,
                &mut voice_trial_proofs,
                &mut flow_journal,
                &journal_origin,
            );
            let deferred_resend_stats = udp_deferred_resends.r2o_flush(
                Instant::now(),
                |_id, packet| {
                    raw.as_ref()
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::NotConnected, "raw-сокет недоступен")
                        })?
                        .send_packet(packet)
                },
                |id, verdict| socket.send_verdict(id, verdict),
                |packet| {
                    udp_follow.r2o_mark_failed(packet);
                },
            );
            if deferred_resend_stats.resend_failed != 0 {
                eprintln!(
                    "r2o-datapath: {} отложенных UDP-хвостов не отправлены raw и приняты ядром",
                    deferred_resend_stats.resend_failed
                );
            }
            if deferred_resend_stats.verdict_failed != 0 {
                eprintln!(
                    "r2o-datapath: {} вердиктов отложенных UDP-хвостов не выданы",
                    deferred_resend_stats.verdict_failed
                );
            }
            if let Err(error) = udp_deferred_verdicts.r2o_flush(Instant::now(), |id, verdict| {
                socket.send_verdict(id, verdict)
            }) {
                eprintln!("r2o-datapath: ошибка выдачи отложенных UDP-вердиктов: {error}");
            }
            if let Some(control) = control.as_mut() {
                if control.is_connected() {
                    send_journal_updates(control, &flow_journal, &mut journal_seen)?;
                } else {
                    journal_seen = 0;
                    journal_peer_connected = false;
                }
            }
        }
    }

    fn send_journal_snapshot(
        control: &mut ControlServer,
        journal: &R2oFlowJournal,
    ) -> io::Result<()> {
        for entry in journal.iter() {
            let frame = entry
                .to_event_frame()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            control.send_event(frame.kind, &frame.body)?;
        }
        let summary = R2oFlowJournalSummary {
            added: journal.added(),
            dropped: journal.dropped(),
            count: journal.count() as u32,
        }
        .to_event_frame();
        control.send_event(summary.kind, &summary.body)
    }

    fn send_journal_updates(
        control: &mut ControlServer,
        journal: &R2oFlowJournal,
        seen: &mut u64,
    ) -> io::Result<()> {
        let added = journal.added();
        if added <= *seen {
            return Ok(());
        }
        let count = journal.count();
        let fresh = added - *seen;
        let from = if fresh >= count as u64 {
            0
        } else {
            count - fresh as usize
        };
        for entry in journal.iter().skip(from) {
            let frame = entry
                .to_event_frame()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            control.send_event(frame.kind, &frame.body)?;
        }
        *seen = added;
        Ok(())
    }

    fn parse_options(arguments: &[String]) -> Result<Options, Box<dyn Error>> {
        let mut options = Options {
            plan_path: PathBuf::from("/etc/r2o/plans/current.r2op"),
            queue: None,
            protocol_family: libc::AF_INET as u16,
            mode: RuntimeMode::Apply,
            mark: 0,
            interface: None,
            probe_mark: 0,
            only_mark: None,
            copy_range: u16::MAX as u32,
            queue_len: 1024,
            journal_capacity: 256,
            flow_capacity: R2oFlowCapacity::default(),
            r2o_idle_timeout: Duration::from_secs(120),
            receive_buffer: 4 * 1024 * 1024,
            control_path: None,
            controller_only: false,
            reverse_queue_visible: false,
            plan_explicit: false,
            fail_open: true,
            check_only: false,
        };
        let mut cursor = 0;
        while cursor < arguments.len() {
            let option = arguments[cursor].as_str();
            cursor += 1;
            match option {
                "--plan" => {
                    options.plan_path = PathBuf::from(next_value(arguments, &mut cursor, option)?);
                    options.plan_explicit = true;
                }
                "--controller-only" => options.controller_only = true,
                "--r2o-udp-reverse-visible" => options.reverse_queue_visible = true,
                "--control" => {
                    options.control_path =
                        Some(PathBuf::from(next_value(arguments, &mut cursor, option)?))
                }
                "--queue" => options.queue = Some(parse_value(arguments, &mut cursor, option)?),
                "--journal" => {
                    options.journal_capacity = parse_value(arguments, &mut cursor, option)?
                }
                "--r2o-flow-capacity" => {
                    let requested: u32 = parse_value(arguments, &mut cursor, option)?;
                    options.flow_capacity = R2oFlowCapacity::from_requested(requested as usize)
                        .ok_or_else(|| invalid("--r2o-flow-capacity должен быть больше нуля"))?;
                }
                "--idle" => {
                    let seconds: u32 = parse_value(arguments, &mut cursor, option)?;
                    options.r2o_idle_timeout = Duration::from_secs(u64::from(seconds));
                }
                "--family" => {
                    options.protocol_family = match next_value(arguments, &mut cursor, option)? {
                        "ipv4" | "4" => libc::AF_INET as u16,
                        "ipv6" | "6" => libc::AF_INET6 as u16,
                        _ => return Err(invalid("--family принимает ipv4 или ipv6")),
                    }
                }
                "--mode" => {
                    options.mode = match next_value(arguments, &mut cursor, option)? {
                        "observe" => RuntimeMode::Observe,
                        "apply" => RuntimeMode::Apply,
                        _ => return Err(invalid("--mode принимает observe или apply")),
                    }
                }
                "--mark" => {
                    options.mark = parse_mark(next_value(arguments, &mut cursor, option)?)
                        .ok_or_else(|| invalid("неверное значение --mark"))?;
                }
                "--iface" => {
                    options.interface = Some(next_value(arguments, &mut cursor, option)?.into());
                }
                "--probe-mark" => {
                    let value = next_value(arguments, &mut cursor, option)?;
                    options.probe_mark = parse_mark(value)
                        .ok_or_else(|| invalid("неверное значение --probe-mark"))?;
                }
                "--only-mark" => {
                    options.only_mark = Some(parse_only_mark(next_value(
                        arguments,
                        &mut cursor,
                        option,
                    )?)?);
                }
                "--copy-range" => options.copy_range = parse_value(arguments, &mut cursor, option)?,
                "--queue-len" => options.queue_len = parse_value(arguments, &mut cursor, option)?,
                "--rcvbuf" => options.receive_buffer = parse_value(arguments, &mut cursor, option)?,
                "--no-fail-open" => options.fail_open = false,
                "--check" => options.check_only = true,
                _ => {
                    return Err(invalid(format!(
                        "неизвестный параметр {option}; используйте --help"
                    )));
                }
            }
        }
        if !(64..=u16::MAX as u32).contains(&options.copy_range) {
            return Err(invalid("--copy-range должен быть от 64 до 65535"));
        }
        if options.queue_len == 0 || options.receive_buffer < 0 {
            return Err(invalid(
                "--queue-len должен быть больше нуля, --rcvbuf неотрицательным",
            ));
        }
        if options.probe_mark != 0 && options.probe_mark == options.mark {
            return Err(invalid("--probe-mark и --mark должны различаться"));
        }
        if options.controller_only && options.plan_explicit {
            return Err(invalid("--controller-only нельзя сочетать с --plan"));
        }
        if options.controller_only && options.control_path.is_none() {
            return Err(invalid("--controller-only требует --control PATH"));
        }
        if options.controller_only && options.check_only {
            return Err(invalid("--check требует --plan FILE"));
        }
        Ok(options)
    }

    fn next_value<'a>(
        arguments: &'a [String],
        cursor: &mut usize,
        option: &str,
    ) -> Result<&'a str, Box<dyn Error>> {
        let value = arguments
            .get(*cursor)
            .ok_or_else(|| invalid(format!("{option} требует значение")))?;
        *cursor += 1;
        Ok(value)
    }

    fn parse_value<T: std::str::FromStr>(
        arguments: &[String],
        cursor: &mut usize,
        option: &str,
    ) -> Result<T, Box<dyn Error>>
    where
        T::Err: std::fmt::Display,
    {
        let value = next_value(arguments, cursor, option)?;
        value
            .parse()
            .map_err(|error| invalid(format!("неверное значение {option}: {error}")))
    }

    fn invalid(message: impl Into<String>) -> Box<dyn Error> {
        Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
    }

    fn parse_mark(value: &str) -> Option<u32> {
        value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .map_or_else(
                || value.parse().ok(),
                |hex| u32::from_str_radix(hex, 16).ok(),
            )
    }

    fn parse_only_mark(value: &str) -> Result<R2oRoutePolicy, Box<dyn Error>> {
        if value == "none" {
            return Ok(R2oRoutePolicy::new(false, 0, 0));
        }
        let (mark, mask) = value.split_once('/').unwrap_or((value, "0xffffffff"));
        let mark = parse_mark(mark).ok_or_else(|| invalid("неверная метка --only-mark"))?;
        let mask = parse_mark(mask).ok_or_else(|| invalid("неверная маска --only-mark"))?;
        if mask == 0 {
            return Err(invalid("маска --only-mark не может быть нулевой"));
        }
        Ok(R2oRoutePolicy::new(true, mark, mask))
    }

    fn print_help() {
        println!(
            r#"r2o-datapath — Linux NFQUEUE datapath

Использование: r2o-datapath --queue N [--plan FILE | --controller-only --control PATH] [параметры]

Параметры:
  --plan FILE        статический план R2OP (по умолчанию /etc/r2o/plans/current.r2op)
  --controller-only  запуск без статического плана; планы поступают через control socket
  --r2o-udp-reverse-visible  обратные UDP-пакеты проходят через ту же NFQUEUE
  --queue N          номер очереди NFQUEUE
  --idle SEC         срок удаления молчащего состояния потока (по умолчанию 120; 0 — без ожидания)
  --r2o-flow-capacity N число слотов TCP/UDP (по умолчанию 2048)
  --family ipv4|ipv6 протокол очереди (по умолчанию ipv4)
  --mode observe|apply пропускать пакеты или исполнять планы (по умолчанию apply)
  --mark N           ненулевая метка для raw-send и защиты от повторной обработки
  --iface NAME       интерфейс, чей MTU ограничивает длину посылки
  --probe-mark N     метка зондов контроллера, исключаемая из route-gate
  --only-mark M[/K]|none  обслуживать только потоки с меткой выбранной политики
  --copy-range N     размер копии пакета (64..65535)
  --queue-len N      глубина очереди (по умолчанию 1024)
  --journal N        глубина журнала потоков (256; 0 — выключить)
  --rcvbuf N         размер приёмного буфера сокета
  --control PATH     Unix-сокет r2o-controller; также открывает PATH.snapshot для снимков
  --no-fail-open     не пропускать пакеты при переполнении очереди
  --check            проверить формат и поддерживаемый режим плана
  --version          версия
  --help             эта справка"#
        );
    }

    fn format_journal_key(key: &[u8; r2k_core::control::KEY_LEN]) -> String {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let client_port = u16::from_be_bytes([key[33], key[34]]);
        let server_port = u16::from_be_bytes([key[35], key[36]]);
        if key[0] == 6 {
            let client = Ipv6Addr::from(<[u8; 16]>::try_from(&key[1..17]).unwrap());
            let server = Ipv6Addr::from(<[u8; 16]>::try_from(&key[17..33]).unwrap());
            format!("[{client}]:{client_port} → [{server}]:{server_port}")
        } else {
            let client = Ipv4Addr::from(<[u8; 4]>::try_from(&key[1..5]).unwrap());
            let server = Ipv4Addr::from(<[u8; 4]>::try_from(&key[17..21]).unwrap());
            format!("{client}:{client_port} → {server}:{server_port}")
        }
    }

    fn journal_timestamp(journal_origin: &Instant) -> u64 {
        journal_origin.elapsed().as_nanos().min(u64::MAX as u128) as u64
    }

    fn format_journal_details(entry: &R2oFlowJournalEntry) -> String {
        use r2o_datapath::flow_journal::R2oFlowJournalKind;
        use std::net::Ipv4Addr;

        let direction = match entry.client_is_low {
            Some(true) => "клиент ниже сервера",
            Some(false) => "клиент выше сервера",
            None => "направление неизвестно",
        };
        match entry.kind {
            R2oFlowJournalKind::Hello if entry.client_shape != 0 => {
                format!(" форма={}, длина={} байт", entry.client_shape, entry.num)
            }
            R2oFlowJournalKind::PlanApplied | R2oFlowJournalKind::PlanDone => format!(
                " план={:02x?} попытка={:02x?} исполнение={}",
                entry.plan_id, entry.trial_id, entry.execution_id
            ),
            R2oFlowJournalKind::PlanRefused
            | R2oFlowJournalKind::PlanUnsent
            | R2oFlowJournalKind::PlanDamaged => format!(
                " причина={} план={:02x?} попытка={:02x?} исполнение={}",
                format_journal_refusal_code(entry.code),
                entry.plan_id,
                entry.trial_id,
                entry.execution_id
            ),
            R2oFlowJournalKind::R2oVoiceProof if entry.code == 1 => format!(
                " Discovery попытка={:02x?} внешний_адрес={}:{}",
                entry.trial_id,
                Ipv4Addr::from(entry.mapped_ip),
                entry.mapped_port
            ),
            R2oFlowJournalKind::R2oVoiceProof if entry.code == 3 => format!(
                " двусторонний RTP попытка={:02x?}, принятых пакетов исход/вход={}/{}",
                entry.trial_id,
                (entry.num >> 8) & 0xff,
                entry.num & 0xff
            ),
            R2oFlowJournalKind::R2oVoiceProof => {
                format!(" STUN Binding попытка={:02x?}", entry.trial_id)
            }
            R2oFlowJournalKind::R2oTcpSilent => {
                format!(
                    " {direction}, план={}, прошло={} мс",
                    if entry.planned == 1 { "да" } else { "нет" },
                    entry.elapsed_ms
                )
            }
            R2oFlowJournalKind::R2oTcpStall => format!(
                " {direction}, прошло={} мс, пакетов={}",
                entry.elapsed_ms, entry.num
            ),
            R2oFlowJournalKind::R2oVoiceSuspect
            | R2oFlowJournalKind::R2oQuicSuspect
            | R2oFlowJournalKind::R2oQuicStall
            | R2oFlowJournalKind::R2oTcpFinRetry
            | R2oFlowJournalKind::R2oTcpRstAfterApp => format!(" {direction}, код={}", entry.code),
            R2oFlowJournalKind::R2oTcpRst => format!(
                " {direction}, TTL={}, опорный_TTL={}, класс={}, IP_ID={}, ServerHello={}, план={}, форма={}",
                entry.ttl,
                entry.reference_ttl,
                entry.tos,
                entry.ip_id,
                entry.server_hello,
                entry.planned,
                entry.client_shape
            ),
            _ => String::new(),
        }
    }

    fn format_journal_refusal_code(code: u8) -> &'static str {
        match code {
            0 => "причина не указана",
            1 => "ошибка отправки",
            2 => "очередь отправки заполнена или закрыта",
            3 => "срок отправки переполнен",
            4 => "поток повреждён недоисполнением",
            5 => "исполнитель отклонил план",
            _ => "неизвестная причина",
        }
    }

    fn is_tls_plan(plan: &Plan) -> bool {
        plan.transport == 6 && plan.proto == 1 && plan.stream_input()
    }

    fn needs_raw_socket(mode: RuntimeMode, plan: &Plan, has_control: bool) -> bool {
        mode == RuntimeMode::Apply
            && (plan.transport == 6
                || plan.proto == PROTO_VOICE
                || plan.r2k_is_quic_ipfrag_plan()
                || plan.r2k_is_quic_clearance_probe()
                || plan.r2k_is_quic_ttl_probe()
                || plan.r2k_is_quic_fallback_ttl_probe()
                || plan.r2k_is_quic_fake_probe()
                || has_control)
    }

    fn send_hello_event(
        control: &mut Option<ControlServer>,
        r2o_snapshot_control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        at_ns: u64,
        body: &[u8],
        client_shape: Option<Vec<u8>>,
    ) {
        flow_journal.record_control_event(at_ns, EVENT_HELLO, body);
        if let Some(client_shape) = client_shape
            && let Some(control) = control.as_mut()
        {
            match control.observe_client_shape(&client_shape) {
                Ok(Some(body)) if control.is_connected() => {
                    if let Err(error) =
                        control.send_event(r2k_core::control::EVENT_CLIENT_SHAPE, &body)
                    {
                        eprintln!("r2o-datapath: снимок ClientHello не отправлен: {error}");
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    eprintln!("r2o-datapath: неверный снимок ClientHello: {error}");
                }
            }
        }
        for r2o_channel in [control.as_mut(), r2o_snapshot_control.as_mut()]
            .into_iter()
            .flatten()
        {
            if let Err(error) = r2o_channel.send_event(EVENT_HELLO, body) {
                eprintln!("r2o-datapath: событие ClientHello не отправлено: {error}");
            }
        }
    }

    fn send_http_portal_event(control: &mut Option<ControlServer>, event: &HttpPortalEvent) {
        let Some(body) = event.event_body() else {
            return;
        };
        let Some(control) = control.as_mut() else {
            return;
        };
        if let Err(error) = control.send_event(EVENT_HTTP_PORTAL, &body) {
            eprintln!("r2o-datapath: событие HTTP portal не отправлено: {error}");
        }
    }

    fn send_http_response_event(control: &mut Option<ControlServer>, event: &HttpResponseEvent) {
        let Some(body) = event.event_body() else {
            return;
        };
        let Some(control) = control.as_mut() else {
            return;
        };
        if let Err(error) = control.send_event(EVENT_HTTP_RESPONSE, &body) {
            eprintln!("r2o-datapath: событие HTTP_RESPONSE не отправлено: {error}");
        }
    }

    fn send_observed_control_event(
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
        event_type: u16,
        body: &[u8],
        description: &str,
    ) -> bool {
        flow_journal.record_control_event(journal_timestamp(journal_origin), event_type, body);
        let Some(control) = control.as_mut() else {
            return false;
        };
        match control.send_event(event_type, body) {
            Ok(()) => true,
            Err(error) => {
                eprintln!("r2o-datapath: событие {description} не отправлено: {error}");
                false
            }
        }
    }

    fn send_voice_suspect_event(
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
        event: &r2k_core::control::R2oVoiceSuspectEvent,
    ) -> bool {
        let Some(body) = event.event_body() else {
            return false;
        };
        send_observed_control_event(
            control,
            flow_journal,
            journal_origin,
            EVENT_R2O_VOICE_SUSPECT,
            &body,
            "голосового потока",
        )
    }

    fn send_quic_suspect_event(
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
        event: &r2k_core::control::R2oQuicSuspectEvent,
    ) -> bool {
        let Some(body) = event.event_body() else {
            return false;
        };
        send_observed_control_event(
            control,
            flow_journal,
            journal_origin,
            EVENT_R2O_QUIC_SUSPECT,
            &body,
            "молчания QUIC",
        )
    }

    fn send_quic_stall_event(
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
        event: &r2k_core::control::R2oQuicSuspectEvent,
    ) -> bool {
        let Some(body) = event.event_body() else {
            return false;
        };
        send_observed_control_event(
            control,
            flow_journal,
            journal_origin,
            EVENT_R2O_QUIC_STALL,
            &body,
            "зависания QUIC после ответа",
        )
    }

    fn send_tcp_silent_event(
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
        event: &r2k_core::control::R2oTcpSilenceEvent,
    ) -> bool {
        let Some(body) = event.event_body() else {
            return false;
        };
        send_observed_control_event(
            control,
            flow_journal,
            journal_origin,
            EVENT_R2O_TCP_SILENT,
            &body,
            "молчания TCP",
        )
    }

    fn send_tcp_stall_event(
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
        event: &r2k_core::control::R2oTcpStallEvent,
    ) -> bool {
        let Some(body) = event.event_body() else {
            return false;
        };
        send_observed_control_event(
            control,
            flow_journal,
            journal_origin,
            EVENT_R2O_TCP_STALL,
            &body,
            "зависания TCP",
        )
    }

    fn send_pending_tcp_fin_retry(
        sessions: &mut TcpSessions,
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
    ) {
        if !control.as_ref().is_some_and(ControlServer::is_connected) {
            return;
        }
        for event in sessions.fin_retry_candidates() {
            if send_tcp_fin_retry_event(control, flow_journal, journal_origin, &event) {
                sessions.mark_fin_retry(&event.key);
            } else if !control.as_ref().is_some_and(ControlServer::is_connected) {
                break;
            }
        }
    }

    fn send_tcp_fin_retry_event(
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
        event: &R2oTcpFinRetryEvent,
    ) -> bool {
        let Some(body) = event.event_body() else {
            return false;
        };
        send_observed_control_event(
            control,
            flow_journal,
            journal_origin,
            EVENT_R2O_TCP_FIN_RETRY,
            &body,
            "повтора FIN TCP",
        )
    }

    fn send_pending_tcp_rst_after_app(
        sessions: &mut TcpSessions,
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
    ) {
        if !control.as_ref().is_some_and(ControlServer::is_connected) {
            return;
        }
        for event in sessions.rst_after_app_candidates() {
            let Some(body) = event.event_body() else {
                continue;
            };
            if send_observed_control_event(
                control,
                flow_journal,
                journal_origin,
                EVENT_R2O_TCP_RST_AFTER_APP,
                &body,
                "позднего TCP RST после TLS-данных",
            ) {
                sessions.mark_rst_after_app(&event.key);
            } else if !control.as_ref().is_some_and(ControlServer::is_connected) {
                break;
            }
        }
    }

    #[cfg(test)]
    fn decide_with_tcp_session(
        sessions: &mut TcpSessions,
        plan: &Plan,
        packet: &[u8],
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
    ) -> PacketDecision {
        decide_with_tcp_session_mode(
            sessions,
            plan,
            packet,
            control,
            flow_journal,
            journal_origin,
            false,
            0,
        )
    }

    fn decide_with_tcp_session_mode(
        sessions: &mut TcpSessions,
        plan: &Plan,
        packet: &[u8],
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
        controller_probe: bool,
        tcp_segment_cap: usize,
    ) -> PacketDecision {
        if controller_probe && plan.qdeny != 0 {
            return PacketDecision::Accept;
        }
        let decision = if controller_probe {
            decide_with_session_probe_mtu(sessions, plan, packet, tcp_segment_cap)
        } else {
            decide_with_session_mtu(sessions, plan, packet, tcp_segment_cap)
        };
        let at_ns = journal_timestamp(journal_origin);
        for event in sessions.take_tcp_exchange_events() {
            if !controller_probe {
                flow_journal.record_tcp_exchange(at_ns, &event);
                if let Some(body) = (R2oTcpExchangeControlEvent {
                    key: event.key,
                    first_record_type: event.code,
                    bytes_after_client_hello: event.num,
                    record_types: event.tos,
                    server_hello: event.server_hello,
                    planned: event.planned == R2oTcpExchangeEvent::PLANNED_YES,
                })
                .event_body()
                    && let Some(control) = control.as_mut()
                    && let Err(error) = control.send_event(EVENT_R2O_TCP_EXCHANGE, &body)
                {
                    eprintln!("r2o-datapath: событие TCP-обмена не отправлено: {error}");
                }
            }
            if !controller_probe
                && let Some(clean) = r2o_clean_handshake_event(&event)
                && let Some(body) = clean.event_body()
            {
                send_observed_control_event(
                    control,
                    flow_journal,
                    journal_origin,
                    EVENT_R2O_TCP_CLEAN_HANDSHAKE,
                    &body,
                    "чистого TCP-рукопожатия",
                );
            }
        }
        for event in sessions.take_tcp_rst_events() {
            if !controller_probe {
                flow_journal.record_tcp_rst(at_ns, &event);
            }
            if !controller_probe
                && let Some(early_rst) = r2o_tcp_early_rst_event(&event)
                && let Some(body) = early_rst.event_body()
            {
                send_observed_control_event(
                    control,
                    flow_journal,
                    journal_origin,
                    EVENT_R2O_TCP_EARLY_RST,
                    &body,
                    "раннего TCP RST",
                );
            }
        }
        for event in sessions.take_tcp_repeat_events() {
            if !controller_probe
                && let Some(body) = (R2oTcpRepeatEvent {
                    key: event.key,
                    client_is_low: event.client_is_low,
                    planned: event.planned,
                })
                .event_body()
            {
                send_observed_control_event(
                    control,
                    flow_journal,
                    journal_origin,
                    EVENT_R2O_TCP_REPEAT,
                    &body,
                    "повтора ClientHello TCP",
                );
            }
        }
        for event in sessions.take_tcp_rst_cut_events() {
            if !controller_probe {
                flow_journal.record_tcp_rst_cut(at_ns, &event);
            }
            let signal = r2o_tcp_rst_cut_signal_event(&event);
            if !controller_probe && let Some(body) = signal.event_body() {
                send_observed_control_event(
                    control,
                    flow_journal,
                    journal_origin,
                    EVENT_R2O_TCP_RST_CUT,
                    &body,
                    "защитно снятого TCP RST",
                );
            }
        }
        send_pending_tcp_fin_retry(sessions, control, flow_journal, journal_origin);
        decision
    }

    fn r2o_clean_handshake_event(
        exchange: &R2oTcpExchangeEvent,
    ) -> Option<R2oTcpCleanHandshakeEvent> {
        (exchange.server_hello && exchange.planned == R2oTcpExchangeEvent::PLANNED_NO)
            .then_some(R2oTcpCleanHandshakeEvent { key: exchange.key })
    }

    fn r2o_tcp_early_rst_event(event: &R2oTcpRstEvent) -> Option<R2oTcpEarlyRstEvent> {
        (event.planned == R2oTcpExchangeEvent::PLANNED_YES
            || event.planned == R2oTcpExchangeEvent::PLANNED_NO)
            .then_some(R2oTcpEarlyRstEvent {
                key: event.key,
                client_is_low: event.client_is_low,
                planned: event.planned == R2oTcpExchangeEvent::PLANNED_YES,
            })
    }

    fn r2o_tcp_rst_cut_signal_event(event: &R2oTcpRstCutEvent) -> R2oTcpRstCutSignalEvent {
        R2oTcpRstCutSignalEvent {
            key: event.key,
            client_is_low: event.client_is_low,
        }
    }

    fn observe_quic_packet(
        sessions: &mut R2oQuicSessions,
        packet: &[u8],
        now: Instant,
        hook: Option<u8>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
    ) {
        sessions.observe_packet_at_hook(packet, now, hook);
        let events = sessions.take_udp_exchange_events();
        if events.is_empty() {
            return;
        }
        let at_ns = journal_timestamp(journal_origin);
        for event in events {
            flow_journal.record_udp_exchange(at_ns, &event);
        }
    }

    fn observe_stun_packet(
        sessions: &mut R2oUdpSessions,
        packet: &[u8],
        now: Instant,
        hook: Option<u8>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
    ) {
        sessions.r2o_observe_stun_packet_at_hook(packet, now, hook);
        let events = sessions.r2o_take_udp_exchange_events();
        if events.is_empty() {
            return;
        }
        let at_ns = journal_timestamp(journal_origin);
        for event in events {
            flow_journal.record_udp_exchange(at_ns, &event);
        }
    }

    #[cfg(test)]
    fn udp_packet_admitted(sessions: &mut R2oUdpSessions, packet: &[u8], now: Instant) -> bool {
        r2o_udp_packet_admitted_at_hook(sessions, packet, now, None, false)
    }

    fn r2o_udp_packet_admitted_at_hook(
        sessions: &mut R2oUdpSessions,
        packet: &[u8],
        now: Instant,
        hook: Option<u8>,
        controller_probe: bool,
    ) -> bool {
        !r2k_core::packet::PacketView::parse(packet).is_some_and(|view| view.protocol == 17)
            || if controller_probe {
                sessions.r2o_observe_probe_packet_at_hook(packet, now, hook)
            } else {
                sessions.r2o_observe_packet_at_hook(packet, now, hook)
            }
    }

    fn r2o_udp_packet_admitted_for_mode(
        mode: RuntimeMode,
        sessions: &mut R2oUdpSessions,
        packet: &[u8],
        now: Instant,
        hook: Option<u8>,
        controller_probe: bool,
    ) -> bool {
        let admitted =
            r2o_udp_packet_admitted_at_hook(sessions, packet, now, hook, controller_probe);
        mode == RuntimeMode::Observe || admitted
    }

    fn r2o_udp_decide_once(
        sessions: &mut R2oUdpSessions,
        quic_sessions: &mut R2oQuicSessions,
        plan: &Plan,
        packet: &[u8],
        decide: impl FnOnce() -> PacketDecision,
    ) -> PacketDecision {
        if sessions.r2o_plan_applied(packet) {
            return PacketDecision::Accept;
        }
        let decision = decide();
        let applied = matches!(
            &decision,
            PacketDecision::Replace(_) | PacketDecision::Transmit { .. }
        ) || (plan.qdeny == 0 && decision == PacketDecision::Drop);
        if applied {
            sessions.r2o_mark_plan_applied(packet);
            quic_sessions.mark_plan_applied(packet);
        }
        decision
    }

    fn r2o_udp_deferred_due(packets: &[WirePacket], now: Instant) -> Option<Instant> {
        let mut due = now;
        let mut deferred = false;
        for packet in packets {
            due = due.checked_add(Duration::from_micros(u64::from(packet.delay_us)))?;
            deferred |= due > now;
        }
        deferred.then_some(due)
    }

    fn r2o_datapath_payload<'a>(packet: &QueuePacket<'a>, mark: u32) -> Option<&'a [u8]> {
        packet
            .payload
            .filter(|_| !packet.truncated && !(mark != 0 && packet.mark == Some(mark)))
    }

    fn r2o_is_controller_probe(mark: Option<u32>, probe_mark: u32) -> bool {
        probe_mark != 0 && mark == Some(probe_mark)
    }

    fn r2o_packet_route_skip(
        gate: &mut R2oRouteGate,
        flows: &mut R2oRoutedFlows,
        packet: &QueuePacket<'_>,
        hook: Option<u8>,
        protocol_family: u16,
        probe_mark: u32,
        datapath_mark: u32,
        now: Instant,
    ) -> bool {
        let family = packet
            .payload
            .and_then(|bytes| bytes.first())
            .map(|first| first >> 4)
            .map(|family| match family {
                6 => R2oRouteFamily::Ipv6,
                _ => R2oRouteFamily::Ipv4,
            })
            .unwrap_or(if protocol_family == libc::AF_INET6 as u16 {
                R2oRouteFamily::Ipv6
            } else {
                R2oRouteFamily::Ipv4
            });
        let route_mark = gate.r2o_route_mark(R2oRoutePacket {
            family,
            outbound: matches!(
                hook,
                Some(
                    r2o_datapath::netlink::R2O_NF_INET_LOCAL_OUT
                        | r2o_datapath::netlink::R2O_NF_INET_POST_ROUTING
                )
            ),
            mark: packet.mark,
            probe_mark,
            datapath_mark,
            output_ifindex: packet.output_device,
        });
        packet.payload.map_or(route_mark != 0, |bytes| {
            flows.r2o_skip_packet(bytes, route_mark, now)
        })
    }

    fn send_voice_proof_event(
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
        event: &r2k_core::control::R2oVoiceProofEvent,
    ) -> bool {
        let Some(body) = event.event_body() else {
            return false;
        };
        let description = match event.proof {
            r2k_core::control::R2oVoiceProofKind::DiscordDiscovery { .. } => {
                "подтверждение Discord Discovery"
            }
            r2k_core::control::R2oVoiceProofKind::StunBinding => "подтверждение STUN Binding",
            r2k_core::control::R2oVoiceProofKind::RtpMedia { .. } => {
                "подтверждение двустороннего RTP"
            }
        };
        let Some(control) = control.as_mut() else {
            return false;
        };
        match control.try_send_event(event.event_type(), &body) {
            Ok(true) => {
                flow_journal.record_control_event(
                    journal_timestamp(journal_origin),
                    event.event_type(),
                    &body,
                );
                true
            }
            Ok(false) => false,
            Err(error) => {
                eprintln!("r2o-datapath: событие {description} не отправлено: {error}");
                false
            }
        }
    }

    fn observe_voice_trial_rtp_packet(
        proofs: &mut R2oVoiceTrialProofs,
        packet: &[u8],
        now: Instant,
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
    ) {
        if let Some(event) = proofs.observe_forwarded_rtp_packet(packet, now) {
            if send_voice_proof_event(control, flow_journal, journal_origin, &event) {
                proofs.acknowledge_rtp_proof(&event);
            }
        }
    }

    fn send_applied_event(
        sessions: &mut TcpSessions,
        control: &mut Option<ControlServer>,
        flow_journal: &mut R2oFlowJournal,
        at_ns: u64,
        event: &AppliedEvent,
    ) {
        let Some(body) = event.event_body() else {
            return;
        };
        flow_journal.record_applied(at_ns, event);
        if event.key[37] == 6 {
            sessions.r2o_mark_plan_done_for_execution(&event.key, event.execution_id);
        }
        let Some(control) = control.as_mut() else {
            return;
        };
        if let Err(error) = control.send_event(EVENT_APPLIED, &body) {
            eprintln!("r2o-datapath: событие APPLIED не отправлено: {error}");
        }
    }

    fn install_signal_handlers() -> io::Result<()> {
        STOP.store(false, Ordering::Relaxed);
        for signal in [libc::SIGINT, libc::SIGTERM] {
            // Обработчик меняет только атомарный флаг; пакеты освобождает главный цикл.
            let previous =
                unsafe { libc::signal(signal, request_stop as *const () as libc::sighandler_t) };
            if previous == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn load_plan(options: &Options) -> Result<Plan, Box<dyn Error>> {
        if options.controller_only
            || (options.mode == RuntimeMode::Observe
                && !options.plan_explicit
                && !options.check_only)
        {
            return Ok(Plan::default());
        }
        let bytes = std::fs::read(&options.plan_path)?;
        let plan = Plan::parse(&bytes)
            .map_err(|error| invalid(format!("план {}: {}", options.plan_path.display(), error)))?;
        validate_runtime_plan(&plan).map_err(invalid)?;
        Ok(plan)
    }

    extern "C" fn request_stop(_signal: libc::c_int) {
        STOP.store(true, Ordering::Relaxed);
    }

    fn release_accepting(queue: &mut QueueSocket, ids: &[u32]) {
        for &id in ids {
            if let Err(error) = queue.send_verdict(id, NF_ACCEPT) {
                eprintln!(
                    "r2o-datapath: не отправлен fail-open ACCEPT для NFQUEUE id {id}: {error}"
                );
            }
        }
    }

    fn drain_queued(queue: &mut QueueSocket, batch: &mut Vec<u8>, packet_type: u16) {
        loop {
            match queue.receive_timeout(batch, 0) {
                Ok(true) => {
                    for message in MessageIter::new(batch) {
                        if message.kind != packet_type {
                            continue;
                        }
                        let Some(id) = QueuePacket::parse(&message).and_then(|packet| packet.id)
                        else {
                            continue;
                        };
                        if let Err(error) = queue.send_verdict(id, NF_ACCEPT) {
                            eprintln!(
                                "r2o-datapath: не отправлен ACCEPT при остановке для id {id}: {error}"
                            );
                        }
                    }
                }
                Ok(false) => break,
                Err(ReceiveError::LostPackets) => {
                    eprintln!("r2o-datapath: потеря пакетов при остановке очереди");
                    break;
                }
                Err(ReceiveError::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(ReceiveError::Io(error)) => {
                    eprintln!("r2o-datapath: не удалось дочитать очередь при остановке: {error}");
                    break;
                }
            }
        }
    }

    fn send_verdicts(
        queue: &mut QueueSocket,
        ids: &[u32],
        verdict: u32,
        fallback_accept: bool,
    ) -> io::Result<()> {
        let mut first_error = None;
        for &id in ids {
            if let Err(error) = queue.send_verdict(id, verdict) {
                if verdict == NF_DROP && fallback_accept {
                    eprintln!("r2o-datapath: не отправлен DROP verdict: {error}");
                    if let Err(fallback_error) = queue.send_verdict(id, NF_ACCEPT) {
                        first_error.get_or_insert(fallback_error);
                    }
                } else {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    enum TransmissionOutcome {
        Complete,
        Pending {
            ticket: FlowTicket,
            r2o_sends_done: bool,
            payload_on_wire: bool,
        },
        Failed {
            code: u8,
            r2o_sends_done: bool,
            payload_on_wire: bool,
            original_spent: bool,
            original_taken: bool,
        },
    }

    fn r2o_first_oversized_emit(
        packets: &[WirePacket],
        mut route_maxlen: impl FnMut(&[u8]) -> usize,
    ) -> Option<(usize, usize)> {
        packets.iter().find_map(|packet| {
            let limit = route_maxlen(&packet.packet);
            (packet.packet.len() > limit).then_some((packet.packet.len(), limit))
        })
    }

    fn transmit_many(
        queue: &mut QueueSocket,
        raw: Option<&RawSocket>,
        scheduled: &mut ScheduledQueue,
        icmp_guard: &mut R2oIcmpGuard,
        packet_ids: &[u32],
        original: &[u8],
        packets: Vec<WirePacket>,
        fate: OriginalFate,
        journal_origin: &Instant,
    ) -> io::Result<TransmissionOutcome> {
        let Some(raw) = raw else {
            eprintln!("r2o-datapath: нет raw socket для emit; исходный пакет пропущен");
            release_many(queue, packet_ids, OriginalFate::Pass, false)?;
            return Ok(TransmissionOutcome::Failed {
                code: r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_SEND,
                r2o_sends_done: false,
                payload_on_wire: false,
                original_spent: !packet_ids.is_empty(),
                original_taken: false,
            });
        };
        if let Some((packet_len, route_maxlen)) =
            r2o_first_oversized_emit(&packets, |packet| raw.packet_route_maxlen(packet))
        {
            eprintln!(
                "r2o-datapath: план отклонён до отправки: пакет {packet_len} байт превышает предел маршрута {route_maxlen}"
            );
            release_many(queue, packet_ids, OriginalFate::Pass, false)?;
            return Ok(TransmissionOutcome::Failed {
                code: r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_TOO_LONG,
                r2o_sends_done: false,
                payload_on_wire: false,
                original_spent: !packet_ids.is_empty(),
                original_taken: false,
            });
        }
        let now = Instant::now();
        let mut due = now;
        let mut first_delayed = packets.len();
        for (index, emitted) in packets.iter().enumerate() {
            let Some(next_due) =
                due.checked_add(Duration::from_micros(u64::from(emitted.delay_us)))
            else {
                eprintln!("r2o-datapath: переполнение срока emit; исходный пакет пропущен");
                release_many(queue, packet_ids, OriginalFate::Pass, false)?;
                return Ok(TransmissionOutcome::Failed {
                    code: r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_TOO_LONG,
                    r2o_sends_done: false,
                    payload_on_wire: false,
                    original_spent: !packet_ids.is_empty(),
                    original_taken: false,
                });
            };
            due = next_due;
            if due > now {
                first_delayed = index;
                break;
            }
        }
        let ticket = if first_delayed < packets.len() {
            let Some(ticket) = scheduled.reserve(original, packets.len() - first_delayed) else {
                eprintln!(
                    "r2o-datapath: очередь TCP заполнена или поток уже закрыт; пакет пропущен"
                );
                release_many(queue, packet_ids, OriginalFate::Pass, false)?;
                return Ok(TransmissionOutcome::Failed {
                    code: r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_QUEUE,
                    r2o_sends_done: false,
                    payload_on_wire: false,
                    original_spent: !packet_ids.is_empty(),
                    original_taken: false,
                });
            };
            Some(ticket)
        } else {
            None
        };

        if let Some(original_ttl) =
            r2k_core::packet::PacketView::parse(original).map(|view| view.hop_limit)
        {
            let at_ns = journal_timestamp(journal_origin);
            for emitted in &packets {
                icmp_guard.r2o_note(&emitted.packet, original_ttl, at_ns);
            }
        }

        let mut due = now;
        let mut payload_committed = false;
        let mut r2o_sends_done = false;
        let mut payload_on_wire = false;
        for (index, emitted) in packets.into_iter().enumerate() {
            let Some(next_due) =
                due.checked_add(Duration::from_micros(u64::from(emitted.delay_us)))
            else {
                if let Some(ticket) = ticket {
                    scheduled.cancel(ticket);
                }
                release_many(queue, packet_ids, OriginalFate::Pass, payload_committed)?;
                return Ok(TransmissionOutcome::Failed {
                    code: r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_TOO_LONG,
                    r2o_sends_done,
                    payload_on_wire,
                    original_spent: !packet_ids.is_empty(),
                    original_taken: false,
                });
            };
            due = next_due;
            if index < first_delayed {
                if let Err(error) = raw.send_packet(&emitted.packet) {
                    eprintln!("r2o-datapath: raw-send не выполнен: {error}");
                    if let Some(ticket) = ticket {
                        scheduled.cancel(ticket);
                    }
                    release_many(
                        queue,
                        packet_ids,
                        if payload_committed {
                            OriginalFate::Drop
                        } else {
                            OriginalFate::Pass
                        },
                        payload_committed,
                    )?;
                    return Ok(TransmissionOutcome::Failed {
                        code: r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_SEND,
                        r2o_sends_done,
                        payload_on_wire,
                        original_spent: !packet_ids.is_empty(),
                        original_taken: payload_committed,
                    });
                }
                r2o_sends_done = true;
                if emitted.kind == EmitKind::Payload {
                    payload_committed = true;
                    payload_on_wire = true;
                }
                continue;
            }

            let Some(ticket) = ticket else {
                release_many(queue, packet_ids, OriginalFate::Pass, payload_committed)?;
                return Ok(TransmissionOutcome::Failed {
                    code: r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_QUEUE,
                    r2o_sends_done,
                    payload_on_wire,
                    original_spent: !packet_ids.is_empty(),
                    original_taken: false,
                });
            };
            let kind = emitted.kind;
            if let Err(_emitted) = scheduled.push_reserved(ticket, due, emitted) {
                eprintln!("r2o-datapath: потерян зарезервированный emit; отменяю его пачку");
                scheduled.cancel(ticket);
                release_many(
                    queue,
                    packet_ids,
                    if payload_committed {
                        OriginalFate::Drop
                    } else {
                        OriginalFate::Pass
                    },
                    payload_committed,
                )?;
                return Ok(TransmissionOutcome::Failed {
                    code: r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_QUEUE,
                    r2o_sends_done,
                    payload_on_wire,
                    original_spent: !packet_ids.is_empty(),
                    original_taken: payload_committed,
                });
            }
            payload_committed |= kind == EmitKind::Payload;
        }
        release_many(queue, packet_ids, fate, payload_committed)?;
        Ok(ticket.map_or(TransmissionOutcome::Complete, |ticket| {
            TransmissionOutcome::Pending {
                ticket,
                r2o_sends_done,
                payload_on_wire,
            }
        }))
    }

    fn flush_scheduled(
        queue: &mut QueueSocket,
        raw: Option<&RawSocket>,
        scheduled: &mut ScheduledQueue,
        pending_applied: &mut HashMap<FlowTicket, PendingApplied>,
        pending_udp_releases: &mut HashMap<FlowTicket, PendingUdpRelease>,
        udp_follow: &mut R2oUdpFollowTable,
        udp_deferred_verdicts: &mut R2oUdpDeferredVerdicts,
        udp_deferred_resends: &mut R2oUdpDeferredResends,
        tcp_sessions: &mut TcpSessions,
        udp_sessions: &mut R2oUdpSessions,
        control: &mut Option<ControlServer>,
        holding: &mut HoldTable,
        voice_trial_proofs: &mut R2oVoiceTrialProofs,
        flow_journal: &mut R2oFlowJournal,
        journal_origin: &Instant,
    ) {
        while let Some((emitted, ticket)) = scheduled.pop_due(Instant::now()) {
            if pending_applied
                .get(&ticket)
                .and_then(|pending| pending.tcp_execution)
                .is_some_and(|execution| {
                    !tcp_sessions.r2o_send_pending(&execution.key, execution.id)
                })
            {
                scheduled.cancel(ticket);
                pending_applied.remove(&ticket);
                continue;
            }
            let Some(raw) = raw else {
                eprintln!("r2o-datapath: отложенный emit отменён без raw socket");
                scheduled.cancel(ticket);
                if let Some(pending) = pending_udp_releases.remove(&ticket) {
                    r2o_cancel_delayed_udp_batch(
                        queue,
                        udp_follow,
                        udp_deferred_verdicts,
                        udp_deferred_resends,
                        pending,
                    );
                }
                if let Some(pending) = pending_applied.remove(&ticket) {
                    let damaged = r2o_fail_pending_applied(
                        tcp_sessions,
                        flow_journal,
                        journal_timestamp(journal_origin),
                        &pending,
                        r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_SEND,
                    );
                    if damaged {
                        r2o_release_damaged_tcp_hold(
                            queue,
                            holding,
                            pending.r2o_tcp_packet.as_deref(),
                        );
                    }
                    if let Some(packet) = pending.r2o_udp_packet.as_deref() {
                        udp_sessions.r2o_note_execution_failure(
                            packet,
                            pending.r2o_sends_done,
                            pending.payload_on_wire,
                            pending.original_spent,
                            pending.original_taken,
                        );
                    }
                }
                continue;
            };
            if let Err(error) = raw.send_packet(&emitted.packet) {
                eprintln!("r2o-datapath: отложенный raw-send не выполнен: {error}");
                scheduled.cancel(ticket);
                if let Some(pending) = pending_udp_releases.remove(&ticket) {
                    r2o_cancel_delayed_udp_batch(
                        queue,
                        udp_follow,
                        udp_deferred_verdicts,
                        udp_deferred_resends,
                        pending,
                    );
                }
                if let Some(pending) = pending_applied.remove(&ticket) {
                    let damaged = r2o_fail_pending_applied(
                        tcp_sessions,
                        flow_journal,
                        journal_timestamp(journal_origin),
                        &pending,
                        r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_SEND,
                    );
                    if damaged {
                        r2o_release_damaged_tcp_hold(
                            queue,
                            holding,
                            pending.r2o_tcp_packet.as_deref(),
                        );
                    }
                    if let Some(packet) = pending.r2o_udp_packet.as_deref() {
                        udp_sessions.r2o_note_execution_failure(
                            packet,
                            pending.r2o_sends_done,
                            pending.payload_on_wire,
                            pending.original_spent,
                            pending.original_taken,
                        );
                    }
                }
            } else {
                if let Some(pending) = pending_applied.get_mut(&ticket) {
                    pending.r2o_sends_done = true;
                    pending.payload_on_wire |= emitted.kind == EmitKind::Payload;
                }
                if emitted.kind == EmitKind::Payload
                    && let Some(pending) = pending_udp_releases.get_mut(&ticket)
                {
                    pending.payload_on_wire = true;
                }
                if !scheduled.has_pending(ticket)
                    && let Some(pending) = pending_udp_releases.remove(&ticket)
                {
                    r2o_release_delayed_udp_batch(queue, pending, true);
                }
                if !scheduled.has_pending(ticket)
                    && let Some(pending) = pending_applied.remove(&ticket)
                {
                    r2o_finish_tcp_execution(
                        tcp_sessions,
                        pending.tcp_execution,
                        true,
                        false,
                        false,
                        false,
                    );
                    if let Some(event) = pending.event {
                        if let Some(sequence) = pending.sequence {
                            holding.note_http_execution(sequence, &event);
                        }
                        if let Some(packet) = pending.voice_request {
                            voice_trial_proofs.note_applied(&packet, &event, Instant::now());
                        }
                        send_applied_event(
                            tcp_sessions,
                            control,
                            flow_journal,
                            journal_timestamp(journal_origin),
                            &event,
                        );
                    }
                }
            }
        }
        let stale_tickets = pending_udp_releases
            .keys()
            .copied()
            .filter(|ticket| !scheduled.has_pending(*ticket))
            .collect::<Vec<_>>();
        for ticket in stale_tickets {
            if let Some(pending) = pending_udp_releases.remove(&ticket) {
                r2o_cancel_delayed_udp_batch(
                    queue,
                    udp_follow,
                    udp_deferred_verdicts,
                    udp_deferred_resends,
                    pending,
                );
            }
        }
        let at_ns = journal_timestamp(journal_origin);
        pending_applied.retain(|ticket, pending| {
            if scheduled.has_pending(*ticket) {
                true
            } else {
                let damaged = r2o_fail_pending_applied(
                    tcp_sessions,
                    flow_journal,
                    at_ns,
                    pending,
                    r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_QUEUE,
                );
                if damaged {
                    r2o_release_damaged_tcp_hold(queue, holding, pending.r2o_tcp_packet.as_deref());
                }
                if let Some(packet) = pending.r2o_udp_packet.as_deref() {
                    udp_sessions.r2o_note_execution_failure(
                        packet,
                        pending.r2o_sends_done,
                        pending.payload_on_wire,
                        pending.original_spent,
                        pending.original_taken,
                    );
                }
                false
            }
        });
    }

    fn release_many(
        queue: &mut QueueSocket,
        packet_ids: &[u32],
        fate: OriginalFate,
        payload_sent: bool,
    ) -> io::Result<()> {
        release_many_with(packet_ids, fate, payload_sent, |id, action| {
            queue.send_verdict(id, action)
        })
    }

    fn release_many_with(
        packet_ids: &[u32],
        fate: OriginalFate,
        payload_sent: bool,
        mut send_verdict: impl FnMut(u32, u32) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut first_error = None;
        for &packet_id in packet_ids {
            let result = release_with(packet_id, fate, payload_sent, &mut send_verdict);
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn release_with(
        packet_id: u32,
        fate: OriginalFate,
        payload_sent: bool,
        mut send_verdict: impl FnMut(u32, u32) -> io::Result<()>,
    ) -> io::Result<()> {
        match fate {
            OriginalFate::Pass => send_verdict(packet_id, NF_ACCEPT),
            OriginalFate::Drop => {
                if let Err(error) = send_verdict(packet_id, NF_DROP) {
                    if payload_sent {
                        return Err(error);
                    }
                    eprintln!("r2o-datapath: не отправлен DROP verdict: {error}");
                    send_verdict(packet_id, NF_ACCEPT)?;
                }
                Ok(())
            }
            OriginalFate::Hold => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TCP runtime не удерживает NFQUEUE packet",
            )),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            ControlServer, EmitKind, NF_ACCEPT, NF_DROP, OriginalFate, PacketDecision,
            PendingApplied, Plan, R2oFlowJournal, R2oQuicSessions, R2oTcpExecution, RuntimeMode,
            TcpSessions, WirePacket, decide_with_tcp_session_mode, format_journal_details,
            format_journal_key, handle_control_command, load_plan, needs_raw_socket,
            observe_quic_packet, observe_stun_packet, parse_options, r2o_clean_handshake_event,
            r2o_datapath_payload, r2o_execution_is_damaged, r2o_fail_pending_applied,
            r2o_finish_tcp_execution, r2o_first_oversized_emit, r2o_is_controller_probe,
            r2o_packet_route_skip, r2o_tcp_early_rst_event, r2o_tcp_rst_cut_signal_event,
            r2o_udp_decide_once, r2o_udp_mark_plain_pass, r2o_udp_packet_admitted_at_hook,
            r2o_udp_packet_admitted_for_mode, release_many_with, release_with, send_applied_event,
            send_hello_event, send_journal_snapshot, send_journal_updates, udp_packet_admitted,
        };
        use r2k_core::control::{
            KEY_LEN, R2oTcpCleanHandshakeEvent, R2oTcpEarlyRstEvent, R2oTcpRstCutSignalEvent,
        };
        use r2k_core::stun::binding_request;
        use r2o_datapath::engine::decide_with_session;
        use r2o_datapath::engine::{R2oTcpExchangeEvent, R2oTcpRstCutEvent, R2oTcpRstEvent};
        use r2o_datapath::netlink::{
            QueuePacket, R2O_NF_INET_FORWARD, R2O_NF_INET_LOCAL_OUT, R2O_NF_INET_POST_ROUTING,
        };
        use r2o_datapath::r2o_route::{
            R2O_ROUTE_OTHER_DEV, R2oRouteFamily, R2oRouteGate, R2oRoutedFlows,
        };
        use r2o_datapath::r2o_udp_hold::R2oUdpFollowTable;
        use r2o_datapath::r2o_udp_sessions::R2oUdpSessions;
        use std::io;

        const QUIC_INITIAL: &[u8] =
            include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin");

        #[test]
        fn учёт_повреждения_исполнения_различает_tcp_и_udp() {
            assert!(r2o_execution_is_damaged(6, false, true, true));
            assert!(!r2o_execution_is_damaged(17, false, true, true));
            assert!(r2o_execution_is_damaged(17, true, false, false));
            assert!(!r2o_execution_is_damaged(6, false, true, false));
        }

        #[test]
        fn tcp_отказ_при_снятом_оригинале_повреждает_поток() {
            fn syn_packet() -> Vec<u8> {
                let mut packet = vec![0; 40];
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
                packet[8] = 64;
                packet[9] = 6;
                packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
                packet[16..20].copy_from_slice(&[198, 51, 100, 20]);
                packet[20..22].copy_from_slice(&41000_u16.to_be_bytes());
                packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
                packet[24..28].copy_from_slice(&700_u32.to_be_bytes());
                packet[32] = 0x50;
                packet[33] = 0x02;
                packet
            }

            let packet = syn_packet();
            let mut damaged = TcpSessions::default();
            assert_eq!(
                decide_with_session(&mut damaged, &Plan::default(), &packet),
                PacketDecision::Accept,
            );
            let key = damaged.r2o_begin_execution(&packet, 71).unwrap();
            r2o_finish_tcp_execution(
                &mut damaged,
                Some(R2oTcpExecution { key, id: 71 }),
                false,
                false,
                true,
                true,
            );
            assert!(damaged.r2o_is_damaged_packet(&packet));

            let mut intact = TcpSessions::default();
            decide_with_session(&mut intact, &Plan::default(), &packet);
            let key = intact.r2o_begin_execution(&packet, 72).unwrap();
            assert!(intact.r2o_send_pending(&key, 72));
            assert!(!r2o_finish_tcp_execution(
                &mut intact,
                Some(R2oTcpExecution { key, id: 72 }),
                false,
                false,
                true,
                false,
            ));
            assert!(!intact.r2o_is_damaged_packet(&packet));
            assert!(!intact.r2o_send_pending(&key, 72));
            assert!(!intact.r2o_mark_plan_done_for_execution(&key, 72));
        }

        #[test]
        fn завершение_отмечает_и_журналирует_незаконченный_tcp_план_один_раз() {
            let mut packet = vec![0; 40];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
            packet[8] = 64;
            packet[9] = 6;
            packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
            packet[16..20].copy_from_slice(&[198, 51, 100, 20]);
            packet[20..22].copy_from_slice(&41000_u16.to_be_bytes());
            packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
            packet[24..28].copy_from_slice(&700_u32.to_be_bytes());
            packet[32] = 0x50;
            packet[33] = 0x02;

            let mut sessions = TcpSessions::default();
            decide_with_session(&mut sessions, &Plan::default(), &packet);
            let key = sessions.r2o_begin_execution(&packet, 77).unwrap();
            let event = r2k_core::control::AppliedEvent {
                key,
                plan_id: [0xa5; 16],
                trial_id: [0x5a; 16],
                execution_id: 77,
                binding: r2k_core::control::BindingContext {
                    generation: 9,
                    kind: 1,
                    family: 4,
                    shape: 2,
                    temporary: true,
                    epoch: [0x3c; 16],
                },
            };
            let pending = PendingApplied {
                event: Some(event),
                tcp_execution: Some(R2oTcpExecution { key, id: 77 }),
                sequence: None,
                voice_request: None,
                r2o_udp_packet: None,
                r2o_tcp_packet: Some(packet),
                r2o_sends_done: false,
                payload_on_wire: false,
                original_spent: true,
                original_taken: true,
            };
            let mut journal = R2oFlowJournal::with_capacity(4).unwrap();

            assert!(r2o_fail_pending_applied(
                &mut sessions,
                &mut journal,
                123,
                &pending,
                r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_QUEUE,
            ));
            assert_eq!(journal.count(), 2);
            assert_eq!(
                journal.get(0).unwrap().kind,
                r2o_datapath::flow_journal::R2oFlowJournalKind::PlanUnsent,
            );
            assert_eq!(
                journal.get(1).unwrap().kind,
                r2o_datapath::flow_journal::R2oFlowJournalKind::PlanDamaged,
            );
            assert!(!r2o_fail_pending_applied(
                &mut sessions,
                &mut journal,
                124,
                &pending,
                r2o_datapath::flow_journal::R2O_JOURNAL_REFUSE_QUEUE,
            ));
            assert_eq!(journal.count(), 2);
        }

        #[test]
        fn метка_зонда_требует_ненулевого_точного_совпадения() {
            assert!(!r2o_is_controller_probe(None, 0x2e));
            assert!(!r2o_is_controller_probe(Some(0x2e), 0));
            assert!(r2o_is_controller_probe(Some(0x2e), 0x2e));
            assert!(!r2o_is_controller_probe(Some(0x2f), 0x2e));
        }

        #[test]
        fn проверяет_все_посылки_по_маршрутному_mtu_до_первой_отправки() {
            let packets = [
                WirePacket {
                    packet: vec![1; 100],
                    kind: EmitKind::Fake,
                    delay_us: 0,
                },
                WirePacket {
                    packet: vec![2; 1501],
                    kind: EmitKind::Payload,
                    delay_us: 0,
                },
            ];
            let mut checked = 0;
            assert_eq!(
                r2o_first_oversized_emit(&packets, |_| {
                    checked += 1;
                    1500
                }),
                Some((1501, 1500))
            );
            assert_eq!(checked, 2);
        }

        #[test]
        fn quicdeny_пропускает_проверочный_initial_контроллера() {
            let mut packet = udp_packet([192, 0, 2, 10], [198, 51, 100, 20], 50_501, 443);
            packet.extend_from_slice(QUIC_INITIAL);
            let ip_length = packet.len() as u16;
            packet[2..4].copy_from_slice(&ip_length.to_be_bytes());
            packet[24..26].copy_from_slice(&(8_u16 + QUIC_INITIAL.len() as u16).to_be_bytes());
            let plan = Plan {
                transport: 17,
                proto: 2,
                qdeny: 1,
                ..Plan::default()
            };
            assert!(r2k_core::quic::is_authenticated_initial(QUIC_INITIAL));

            let mut sessions = TcpSessions::default();
            let mut control = None;
            let mut journal = R2oFlowJournal::with_capacity(4).unwrap();
            let origin = std::time::Instant::now();
            assert_eq!(
                decide_with_tcp_session_mode(
                    &mut sessions,
                    &plan,
                    &packet,
                    &mut control,
                    &mut journal,
                    &origin,
                    true,
                    0,
                ),
                PacketDecision::Accept
            );
            assert!(sessions.is_empty());
            assert_eq!(journal.count(), 0);
        }

        #[test]
        fn чистым_событием_считается_только_tcp_serverhello_без_плана() {
            let mut key = [0; KEY_LEN];
            key[0] = 4;
            key[1..5].copy_from_slice(&[192, 0, 2, 10]);
            key[17..21].copy_from_slice(&[198, 51, 100, 80]);
            key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
            key[35..37].copy_from_slice(&443_u16.to_be_bytes());
            key[37] = 6;
            let exchange = R2oTcpExchangeEvent {
                key,
                code: 22,
                num: 40,
                tos: 1,
                server_hello: true,
                planned: R2oTcpExchangeEvent::PLANNED_NO,
            };

            assert_eq!(
                r2o_clean_handshake_event(&exchange),
                Some(R2oTcpCleanHandshakeEvent { key })
            );
            let mut planned = exchange;
            planned.planned = R2oTcpExchangeEvent::PLANNED_YES;
            assert_eq!(r2o_clean_handshake_event(&planned), None);
            let mut incomplete = exchange;
            incomplete.server_hello = false;
            assert_eq!(r2o_clean_handshake_event(&incomplete), None);
        }

        #[test]
        fn ранний_rst_сохраняет_направление_и_факт_исполнения_плана() {
            let mut key = [0; KEY_LEN];
            key[0] = 4;
            key[1..5].copy_from_slice(&[192, 0, 2, 10]);
            key[17..21].copy_from_slice(&[198, 51, 100, 80]);
            key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
            key[35..37].copy_from_slice(&443_u16.to_be_bytes());
            key[37] = 6;
            let event = R2oTcpRstEvent {
                key,
                ttl: 124,
                reference_ttl: 64,
                traffic_class: 0,
                ip_id: 0,
                server_hello: false,
                planned: R2oTcpExchangeEvent::PLANNED_NO,
                client_shape: 0,
                client_is_low: true,
            };

            assert_eq!(
                r2o_tcp_early_rst_event(&event),
                Some(R2oTcpEarlyRstEvent {
                    key,
                    client_is_low: true,
                    planned: false,
                })
            );
            let mut unknown = event;
            unknown.planned = 0;
            assert_eq!(r2o_tcp_early_rst_event(&unknown), None);
        }

        #[test]
        fn защитно_снятый_rst_передаёт_сигнал_для_планировщика() {
            let mut key = [0; KEY_LEN];
            key[0] = 4;
            key[1..5].copy_from_slice(&[192, 0, 2, 10]);
            key[17..21].copy_from_slice(&[198, 51, 100, 80]);
            key[33..35].copy_from_slice(&45_000_u16.to_be_bytes());
            key[35..37].copy_from_slice(&443_u16.to_be_bytes());
            key[37] = 6;
            let packet_event = R2oTcpRstCutEvent {
                key,
                ttl: 127,
                reference_ttl: 64,
                traffic_class: 0x2e,
                ip_id: 1234,
                server_hello: false,
                planned: 2,
                client_shape: 1,
                client_is_low: true,
            };

            let signal = r2o_tcp_rst_cut_signal_event(&packet_event);
            let frame = r2k_core::control::Frame {
                kind: r2k_core::control::EVENT_R2O_TCP_RST_CUT,
                body: signal.event_body().unwrap(),
            };
            assert_eq!(
                r2k_core::control::decode_r2o_tcp_rst_cut_signal(&frame),
                Ok(R2oTcpRstCutSignalEvent {
                    key,
                    client_is_low: true,
                })
            );
        }
        use std::os::unix::net::UnixStream;
        use std::time::{Duration, Instant};

        #[test]
        fn управляющая_команда_обновляет_бюджеты_tcp_и_отвергает_ошибку() {
            let mut plans = r2o_datapath::control::NamePlans::default();
            let mut sessions = TcpSessions::default();
            let valid = r2k_core::control::Frame {
                kind: r2k_core::control::COMMAND_SET_TCP_STALL_BUDGETS,
                body: vec![2, 0, 15, 0, 35],
            };
            let ack = handle_control_command(&mut plans, &mut sessions, &valid);
            assert!(ack.ok);
            assert_eq!(ack.command, valid.kind);

            let invalid = r2k_core::control::Frame {
                kind: r2k_core::control::COMMAND_SET_TCP_STALL_BUDGETS,
                body: vec![1, 0, 0],
            };
            let ack = handle_control_command(&mut plans, &mut sessions, &invalid);
            assert!(!ack.ok);
            assert_eq!(ack.reason, r2k_core::control::ACK_BAD_ARGS);
        }

        #[test]
        fn заполненная_udp_таблица_останавливает_обработку_нового_потока() {
            let mut sessions = R2oUdpSessions::new().unwrap();
            let now = Instant::now();
            for index in 0..1536_u16 {
                let packet = udp_packet(
                    [10, (index >> 8) as u8, index as u8, 1],
                    [203, 0, 113, 8],
                    53000,
                    7000,
                );
                assert!(udp_packet_admitted(&mut sessions, &packet, now));
            }

            let refused = udp_packet([10, 7, 0, 1], [203, 0, 113, 8], 53000, 7000);
            assert!(!udp_packet_admitted(
                &mut sessions,
                &refused,
                now + Duration::from_secs(1)
            ));
            assert_eq!(sessions.stats().flows, 1536);
            assert_eq!(sessions.stats().refusals, 1);
        }

        #[test]
        fn observe_режим_сохраняет_udp_поток_для_наблюдения() {
            let mut sessions = R2oUdpSessions::new().unwrap();
            let now = Instant::now();
            let packet = udp_packet([10, 7, 0, 1], [203, 0, 113, 8], 53000, 7000);

            assert!(r2o_udp_packet_admitted_for_mode(
                RuntimeMode::Observe,
                &mut sessions,
                &packet,
                now,
                Some(R2O_NF_INET_LOCAL_OUT),
                false,
            ));
            assert_eq!(sessions.stats().flows, 1);
            assert_eq!(sessions.stats().refusals, 0);
        }

        #[test]
        fn observe_режим_не_отказывает_при_полной_udp_таблице() {
            let mut sessions = R2oUdpSessions::new().unwrap();
            let now = Instant::now();
            for index in 0..1536_u16 {
                let packet = udp_packet(
                    [10, (index >> 8) as u8, index as u8, 1],
                    [203, 0, 113, 8],
                    53000,
                    7000,
                );
                assert!(r2o_udp_packet_admitted_at_hook(
                    &mut sessions,
                    &packet,
                    now,
                    Some(R2O_NF_INET_LOCAL_OUT),
                    false,
                ));
            }

            let packet = udp_packet([10, 7, 0, 1], [203, 0, 113, 8], 53000, 7000);
            assert!(r2o_udp_packet_admitted_for_mode(
                RuntimeMode::Observe,
                &mut sessions,
                &packet,
                now + Duration::from_secs(1),
                Some(R2O_NF_INET_LOCAL_OUT),
                false,
            ));
            assert!(!r2o_udp_packet_admitted_for_mode(
                RuntimeMode::Apply,
                &mut sessions,
                &packet,
                now + Duration::from_secs(1),
                Some(R2O_NF_INET_LOCAL_OUT),
                false,
            ));
            assert_eq!(sessions.stats().flows, 1536);
            assert_eq!(sessions.stats().refusals, 2);
        }

        #[test]
        fn r2o_udp_hold_считает_повторную_обработку_головы_в_окне() {
            let now = Instant::now();
            let mut sessions = R2oUdpSessions::new().unwrap();
            let packet = udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 40_000, 443);
            let hook = Some(R2O_NF_INET_LOCAL_OUT);

            for index in 0..7 {
                assert!(r2o_udp_packet_admitted_at_hook(
                    &mut sessions,
                    &packet,
                    now + Duration::from_millis(index),
                    hook,
                    false,
                ));
            }
            assert!(r2o_udp_packet_admitted_at_hook(
                &mut sessions,
                &packet,
                now + Duration::from_millis(7),
                hook,
                false,
            ));
            assert!(sessions.r2o_begin_hold(&packet));

            assert!(r2o_udp_packet_admitted_at_hook(
                &mut sessions,
                &packet,
                now + Duration::from_millis(8),
                hook,
                false,
            ));
            assert!(r2o_udp_packet_admitted_at_hook(
                &mut sessions,
                &packet,
                now + Duration::from_millis(9),
                hook,
                false,
            ));
            assert!(!sessions.r2o_begin_hold(&packet));
        }

        #[test]
        fn обычный_принятый_первый_udp_пакет_открывает_окно_только_для_клиента() {
            let now = Instant::now();
            let hook = Some(R2O_NF_INET_LOCAL_OUT);
            let packet = udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 40_000, 3478);
            let mut sessions = R2oUdpSessions::new().unwrap();
            let mut follow = R2oUdpFollowTable::new();
            let route_gate = R2oRouteGate::default();

            assert!(r2o_udp_packet_admitted_at_hook(
                &mut sessions,
                &packet,
                now,
                hook,
                false,
            ));
            assert!(r2o_udp_mark_plain_pass(
                &sessions,
                &mut follow,
                &route_gate,
                0,
                0,
                &packet,
                now,
                1,
                true,
            ));
            assert!(follow.r2o_match(&packet, now, 1).is_some());

            assert!(r2o_udp_packet_admitted_at_hook(
                &mut sessions,
                &packet,
                now + std::time::Duration::from_millis(1),
                hook,
                false,
            ));
            assert!(!r2o_udp_mark_plain_pass(
                &sessions,
                &mut follow,
                &route_gate,
                0,
                0,
                &packet,
                now + std::time::Duration::from_millis(1),
                2,
                true,
            ));
            assert!(
                follow
                    .r2o_match(&packet, now + std::time::Duration::from_millis(6), 2)
                    .is_none()
            );

            let reply = udp_packet([198, 51, 100, 2], [192, 0, 2, 1], 3478, 40_000);
            assert!(r2o_udp_packet_admitted_at_hook(
                &mut sessions,
                &reply,
                now + std::time::Duration::from_millis(7),
                Some(r2o_datapath::netlink::R2O_NF_INET_LOCAL_IN),
                false,
            ));
            assert!(!r2o_udp_mark_plain_pass(
                &sessions,
                &mut follow,
                &route_gate,
                0,
                0,
                &reply,
                now + std::time::Duration::from_millis(7),
                3,
                true,
            ));
        }

        #[test]
        fn r2o_udp_план_исполняется_один_раз_на_поток_и_снова_после_истечения() {
            let now = Instant::now();
            let mut sessions = R2oUdpSessions::new().unwrap();
            let mut quic_sessions = R2oQuicSessions::default();
            let request = udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 40_000, 443);
            assert!(udp_packet_admitted(&mut sessions, &request, now));

            let mut executions = 0;
            let plan = Plan::default();
            let first =
                r2o_udp_decide_once(&mut sessions, &mut quic_sessions, &plan, &request, || {
                    executions += 1;
                    PacketDecision::Drop
                });
            assert_eq!(first, PacketDecision::Drop);

            let reply = udp_packet([198, 51, 100, 2], [192, 0, 2, 1], 443, 40_000);
            assert!(udp_packet_admitted(
                &mut sessions,
                &reply,
                now + Duration::from_millis(1)
            ));
            let repeated =
                r2o_udp_decide_once(&mut sessions, &mut quic_sessions, &plan, &reply, || {
                    executions += 1;
                    PacketDecision::Drop
                });
            assert_eq!(repeated, PacketDecision::Accept);
            assert_eq!(executions, 1);

            sessions.expire(now + Duration::from_secs(120) + Duration::from_millis(1));
            assert!(udp_packet_admitted(
                &mut sessions,
                &request,
                now + Duration::from_secs(120) + Duration::from_millis(1)
            ));
            let next_flow =
                r2o_udp_decide_once(&mut sessions, &mut quic_sessions, &plan, &request, || {
                    executions += 1;
                    PacketDecision::Drop
                });
            assert_eq!(next_flow, PacketDecision::Drop);
            assert_eq!(executions, 2);

            sessions.expire(now + Duration::from_secs(240) + Duration::from_millis(1));
            assert!(udp_packet_admitted(
                &mut sessions,
                &request,
                now + Duration::from_secs(240) + Duration::from_millis(1)
            ));
            let qdeny = Plan {
                qdeny: 1,
                ..Plan::default()
            };
            for expected_executions in [3, 4] {
                assert_eq!(
                    r2o_udp_decide_once(
                        &mut sessions,
                        &mut quic_sessions,
                        &qdeny,
                        &request,
                        || {
                            executions += 1;
                            PacketDecision::Drop
                        }
                    ),
                    PacketDecision::Drop
                );
                assert_eq!(executions, expected_executions);
            }
        }

        #[test]
        fn r2o_метка_контроллера_исключает_зондовые_пакеты_из_состояния_datapath() {
            let payload = [0x16, 0x03, 0x03];
            let marked = super::QueuePacket {
                mark: Some(45),
                payload: Some(&payload),
                ..Default::default()
            };
            assert!(r2o_datapath_payload(&marked, 45).is_none());
            assert_eq!(r2o_datapath_payload(&marked, 46), Some(payload.as_slice()));
            assert_eq!(r2o_datapath_payload(&marked, 0), Some(payload.as_slice()));

            let truncated = super::QueuePacket {
                payload: Some(&payload),
                truncated: true,
                ..Default::default()
            };
            assert!(r2o_datapath_payload(&truncated, 45).is_none());
        }

        #[test]
        fn r2o_runtime_оставляет_весь_маршрутный_udp_поток_ядру() {
            let mut gate = R2oRouteGate::default();
            gate.r2o_set_rules(R2oRouteFamily::Ipv4, Vec::new());
            gate.r2o_set_default_ifindices(R2oRouteFamily::Ipv4, Some(vec![5]));
            let mut flows = R2oRoutedFlows::default();
            let now = Instant::now();
            let request = udp_packet([192, 0, 2, 1], [198, 51, 100, 2], 40000, 443);
            let reply = udp_packet([198, 51, 100, 2], [192, 0, 2, 1], 443, 40000);
            let outbound = QueuePacket {
                payload: Some(&request),
                hook: Some(R2O_NF_INET_POST_ROUTING),
                output_device: Some(9),
                ..Default::default()
            };
            assert!(r2o_packet_route_skip(
                &mut gate,
                &mut flows,
                &outbound,
                outbound.hook,
                libc::AF_INET as u16,
                0x2e,
                0x2d,
                now,
            ));

            let inbound = QueuePacket {
                payload: Some(&reply),
                hook: Some(R2O_NF_INET_FORWARD),
                output_device: Some(2),
                ..Default::default()
            };
            assert!(r2o_packet_route_skip(
                &mut gate,
                &mut flows,
                &inbound,
                inbound.hook,
                libc::AF_INET as u16,
                0x2e,
                0x2d,
                now + Duration::from_millis(1),
            ));
            assert_eq!(
                gate.r2o_route_mark(super::R2oRoutePacket {
                    family: R2oRouteFamily::Ipv4,
                    outbound: true,
                    mark: None,
                    probe_mark: 0x2e,
                    datapath_mark: 0x2d,
                    output_ifindex: Some(9),
                }),
                R2O_ROUTE_OTHER_DEV
            );
        }

        fn udp_packet(
            source: [u8; 4],
            destination: [u8; 4],
            source_port: u16,
            destination_port: u16,
        ) -> Vec<u8> {
            let mut packet = vec![0; 28];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
            packet[8] = 64;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&source);
            packet[16..20].copy_from_slice(&destination);
            packet[20..22].copy_from_slice(&source_port.to_be_bytes());
            packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
            packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
            packet
        }

        #[test]
        fn controller_only_mode_requires_control_and_keeps_the_legacy_plan_mode() {
            let args = [
                "--controller-only",
                "--control",
                "/tmp/r2o-datapath.sock",
                "--r2o-udp-reverse-visible",
                "--queue",
                "2000",
                "--iface",
                "eth0",
                "--mark",
                "45",
            ]
            .map(str::to_owned);
            let options = parse_options(&args).unwrap();
            assert!(options.controller_only);
            assert!(options.reverse_queue_visible);
            assert_eq!(options.mode, RuntimeMode::Apply);
            assert_eq!(options.interface.as_deref(), Some("eth0"));
            assert_eq!(
                options.control_path.as_deref(),
                Some(std::path::Path::new("/tmp/r2o-datapath.sock"))
            );
            assert!(options.plan_path.ends_with("current.r2op"));
            assert_eq!(load_plan(&options).unwrap(), super::Plan::default());

            let old_options = parse_options(&["--queue".into(), "2000".into()]).unwrap();
            assert!(!old_options.controller_only);
            assert_eq!(
                old_options.plan_path,
                std::path::Path::new("/etc/r2o/plans/current.r2op")
            );
        }

        #[test]
        fn r2o_параметры_route_gate_принимают_шестнадцатеричные_метки_и_none() {
            let args = [
                "--mark",
                "0x2d",
                "--probe-mark",
                "0x2e",
                "--only-mark",
                "0xffffaaa/0xffffff00",
            ]
            .map(str::to_owned);
            let options = parse_options(&args).unwrap();
            assert_eq!(options.mark, 0x2d);
            assert_eq!(options.probe_mark, 0x2e);
            assert_eq!(
                options.only_mark,
                Some(super::R2oRoutePolicy::new(true, 0xffffaaa, 0xffffff00))
            );

            let none = parse_options(&["--only-mark".into(), "none".into()]).unwrap();
            assert_eq!(
                none.only_mark,
                Some(super::R2oRoutePolicy::new(false, 0, 0))
            );
            assert!(parse_options(&["--only-mark".into(), "0x20/0".into()]).is_err());
            assert!(parse_options(&["--mark".into(), "bad".into()]).is_err());
            assert!(
                parse_options(&[
                    "--mark".into(),
                    "0x2e".into(),
                    "--probe-mark".into(),
                    "0x2e".into(),
                ])
                .is_err()
            );
        }

        #[test]
        fn r2o_ёмкость_таблиц_потоков_настраивается_и_ноль_отклоняется() {
            let configured = parse_options(&["--r2o-flow-capacity".into(), "64".into()]).unwrap();
            assert_eq!(configured.flow_capacity.slots(), 64);
            assert_eq!(configured.flow_capacity.limit(), 48);
            assert_eq!(parse_options(&[]).unwrap().flow_capacity.limit(), 1536);
            assert!(parse_options(&["--r2o-flow-capacity".into(), "0".into(),]).is_err());
            assert!(parse_options(&["--r2o-flow-capacity".into(), "4294967296".into()]).is_err());
        }

        #[test]
        fn r2o_срок_хранения_потоков_совпадает_с_донорским_параметром_idle() {
            assert_eq!(parse_options(&[]).unwrap().r2o_idle_timeout.as_secs(), 120);
            assert_eq!(
                parse_options(&["--idle".into(), "17".into()])
                    .unwrap()
                    .r2o_idle_timeout
                    .as_secs(),
                17
            );
            assert_eq!(
                parse_options(&["--idle".into(), "0".into()])
                    .unwrap()
                    .r2o_idle_timeout,
                Duration::ZERO
            );
            assert!(parse_options(&["--idle".into(), "4294967296".into()]).is_err());
        }

        #[test]
        fn r2o_глубина_журнала_совпадает_с_донорским_значением_и_допускает_отключение() {
            assert_eq!(parse_options(&[]).unwrap().journal_capacity, 256);
            assert_eq!(
                parse_options(&["--journal".into(), "0".into()])
                    .unwrap()
                    .journal_capacity,
                0
            );
            assert_eq!(
                parse_options(&["--journal".into(), "17".into()])
                    .unwrap()
                    .journal_capacity,
                17
            );
            assert!(parse_options(&["--journal".into(), "bad".into()]).is_err());
        }

        #[test]
        fn r2o_журнал_печатает_ipv4_и_ipv6_ключи_потоков() {
            let mut ipv4 = [0; r2k_core::control::KEY_LEN];
            ipv4[0] = 4;
            ipv4[1..5].copy_from_slice(&[192, 0, 2, 1]);
            ipv4[17..21].copy_from_slice(&[198, 51, 100, 2]);
            ipv4[33..35].copy_from_slice(&12345_u16.to_be_bytes());
            ipv4[35..37].copy_from_slice(&443_u16.to_be_bytes());
            assert_eq!(
                format_journal_key(&ipv4),
                "192.0.2.1:12345 → 198.51.100.2:443"
            );

            let mut ipv6 = [0; r2k_core::control::KEY_LEN];
            ipv6[0] = 6;
            ipv6[1..17].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
            ipv6[17..33].copy_from_slice(
                &"2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
            assert_eq!(format_journal_key(&ipv6), "[::1]:0 → [2001:db8::1]:0");
        }

        #[test]
        fn r2o_журнал_показывает_детали_подозрения() {
            let entry = r2o_datapath::flow_journal::R2oFlowJournalEntry {
                kind: r2o_datapath::flow_journal::R2oFlowJournalKind::R2oTcpStall,
                client_is_low: Some(true),
                elapsed_ms: 3000,
                num: 25,
                ..r2o_datapath::flow_journal::R2oFlowJournalEntry::default()
            };

            assert_eq!(
                format_journal_details(&entry),
                " клиент ниже сервера, прошло=3000 мс, пакетов=25"
            );
        }

        #[test]
        fn r2o_журнал_показывает_причину_и_контекст_отказа() {
            let entry = r2o_datapath::flow_journal::R2oFlowJournalEntry {
                kind: r2o_datapath::flow_journal::R2oFlowJournalKind::PlanDamaged,
                code: 4,
                plan_id: [0xa5; 16],
                trial_id: [0x5a; 16],
                execution_id: 77,
                ..r2o_datapath::flow_journal::R2oFlowJournalEntry::default()
            };

            let details = format_journal_details(&entry);

            assert!(details.contains("поток повреждён недоисполнением"));
            assert!(details.contains("исполнение=77"));
            assert!(details.contains("план=[a5"));
            assert!(details.contains("попытка=[5a"));
        }

        #[test]
        fn r2o_передаёт_clienthello_контроллеру_и_снимку_одновременно() {
            use std::time::{SystemTime, UNIX_EPOCH};

            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!("r2o-snapshot-fanout-{nonce}"));
            std::fs::create_dir(&directory).unwrap();
            let control_path = directory.join("datapath.sock");
            let snapshot_path = r2k_core::control::r2k_snapshot_socket_path(&control_path);
            let mut control = Some(ControlServer::open(&control_path, u16::MAX as u32).unwrap());
            let mut snapshot = Some(ControlServer::open(&snapshot_path, u16::MAX as u32).unwrap());
            let mut flow_journal = R2oFlowJournal::with_capacity(2).unwrap();
            let mut controller = UnixStream::connect(&control_path).unwrap();
            let mut browser_capture = UnixStream::connect(&snapshot_path).unwrap();
            control.as_mut().unwrap().poll().unwrap();
            snapshot.as_mut().unwrap().poll().unwrap();
            assert_eq!(
                r2k_core::control::decode_greeting(
                    &r2k_core::control::read_frame(&mut controller).unwrap()
                )
                .unwrap()
                .version,
                r2k_core::control::PROTOCOL_VERSION
            );
            assert_eq!(
                r2k_core::control::decode_greeting(
                    &r2k_core::control::read_frame(&mut browser_capture).unwrap()
                )
                .unwrap()
                .version,
                r2k_core::control::PROTOCOL_VERSION
            );

            use std::io::Write;
            controller
                .write_all(&r2k_core::control::encode_arm_shape("__SNI__", 6, 4).unwrap())
                .unwrap();
            let mut commands = control.as_mut().unwrap().poll().unwrap();
            assert_eq!(commands.len(), 1);
            let (ack, cached) = control
                .as_mut()
                .unwrap()
                .arm_client_shape(&commands.remove(0));
            assert!(ack.ok);
            assert!(cached.is_none());
            control.as_mut().unwrap().send_ack(ack).unwrap();
            assert!(
                r2k_core::control::decode_ack(
                    &r2k_core::control::read_frame(&mut controller).unwrap()
                )
                .unwrap()
                .ok
            );

            let mut body = vec![0; r2k_core::control::KEY_LEN];
            body[0] = 4;
            body[37] = 6;
            body.push(7);
            body.extend_from_slice(b"__SNI__");
            body.push(r2k_core::control::SHAPE_MODERN);
            body.extend_from_slice(&1275_u16.to_be_bytes());
            let client_hello = include_str!("../../r2o-controller/src/profiles/modern.hex")
                .lines()
                .flat_map(|line| line.split('#').next().unwrap_or_default().bytes())
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect::<Vec<_>>()
                .chunks_exact(2)
                .map(|pair| {
                    let digit = |byte: u8| (byte as char).to_digit(16).unwrap() as u8;
                    (digit(pair[0]) << 4) | digit(pair[1])
                })
                .collect::<Vec<_>>();
            let key = body[..r2k_core::control::KEY_LEN].try_into().unwrap();
            let client_shape = r2k_core::control::ClientShapeEvent {
                key,
                host: b"__SNI__".to_vec(),
                shape: r2k_core::control::SHAPE_MODERN,
                client_hello: client_hello.clone(),
            }
            .event_body()
            .unwrap();
            send_hello_event(
                &mut control,
                &mut snapshot,
                &mut flow_journal,
                42,
                &body,
                Some(client_shape),
            );

            let captured_shape = r2k_core::control::read_frame(&mut controller).unwrap();
            assert_eq!(captured_shape.kind, r2k_core::control::EVENT_CLIENT_SHAPE);
            assert_eq!(
                r2k_core::control::decode_client_shape(&captured_shape)
                    .unwrap()
                    .client_hello,
                client_hello
            );
            let cached_arm = r2k_core::control::Frame {
                kind: r2k_core::control::COMMAND_ARM_SHAPE,
                body: vec![7, b'_', b'_', b'S', b'N', b'I', b'_', b'_', 6, 4],
            };
            let (cached_ack, cached_body) = control.as_mut().unwrap().arm_client_shape(&cached_arm);
            assert!(cached_ack.ok);
            assert_eq!(cached_body, Some(captured_shape.body));
            for reader in [&mut controller, &mut browser_capture] {
                let frame = r2k_core::control::read_frame(reader).unwrap();
                assert_eq!(frame.kind, r2k_core::control::EVENT_HELLO);
                assert_eq!(
                    r2k_core::control::decode_hello(&frame)
                        .unwrap()
                        .r2o_wire_len,
                    Some(1275)
                );
            }
            assert_eq!(flow_journal.count(), 1);
            let recorded = flow_journal.get(0).unwrap();
            assert_eq!(recorded.at_ns, 42);
            assert_eq!(recorded.name_len, 7);
            assert_eq!(recorded.client_shape, r2k_core::control::SHAPE_MODERN);
            assert_eq!(recorded.num, 1275);
            drop(browser_capture);
            drop(controller);
            drop(snapshot);
            drop(control);
            std::fs::remove_dir_all(directory).unwrap();
        }

        #[test]
        fn r2o_передаёт_снимок_кольца_и_последующие_записи_контроллеру() {
            use std::time::{SystemTime, UNIX_EPOCH};

            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!("r2o-journal-stream-{nonce}"));
            std::fs::create_dir(&directory).unwrap();
            let control_path = directory.join("datapath.sock");
            let mut control = ControlServer::open(&control_path, u16::MAX as u32).unwrap();
            let mut journal = R2oFlowJournal::with_capacity(3).unwrap();
            let mut first = r2o_datapath::flow_journal::R2oFlowJournalEntry {
                at_ns: 11,
                ..r2o_datapath::flow_journal::R2oFlowJournalEntry::default()
            };
            first.key[0] = 4;
            first.key[37] = 6;
            journal.push(first);
            let mut second = r2o_datapath::flow_journal::R2oFlowJournalEntry {
                at_ns: 22,
                ..r2o_datapath::flow_journal::R2oFlowJournalEntry::default()
            };
            second.key[0] = 4;
            second.key[37] = 6;
            journal.push(second);

            let mut client = UnixStream::connect(&control_path).unwrap();
            control.poll().unwrap();
            r2k_core::control::read_frame(&mut client).unwrap();
            send_journal_snapshot(&mut control, &journal).unwrap();

            let first_frame = r2k_core::control::read_frame(&mut client).unwrap();
            let second_frame = r2k_core::control::read_frame(&mut client).unwrap();
            let summary_frame = r2k_core::control::read_frame(&mut client).unwrap();
            assert_eq!(
                r2o_datapath::flow_journal::R2oFlowJournalEntry::from_event_frame(&first_frame)
                    .unwrap()
                    .at_ns,
                11
            );
            assert_eq!(
                r2o_datapath::flow_journal::R2oFlowJournalEntry::from_event_frame(&second_frame)
                    .unwrap()
                    .at_ns,
                22
            );
            assert_eq!(
                r2o_datapath::flow_journal::R2oFlowJournalSummary::from_event_frame(&summary_frame)
                    .unwrap()
                    .count,
                2
            );

            let mut seen = journal.added();
            let mut third = r2o_datapath::flow_journal::R2oFlowJournalEntry {
                at_ns: 33,
                ..r2o_datapath::flow_journal::R2oFlowJournalEntry::default()
            };
            third.key[0] = 4;
            third.key[37] = 6;
            journal.push(third);
            send_journal_updates(&mut control, &journal, &mut seen).unwrap();

            assert_eq!(
                r2o_datapath::flow_journal::R2oFlowJournalEntry::from_event_frame(
                    &r2k_core::control::read_frame(&mut client).unwrap()
                )
                .unwrap()
                .at_ns,
                33
            );
            drop(client);
            drop(control);
            std::fs::remove_dir(directory).unwrap();
        }

        #[test]
        fn r2o_журналирует_исполненный_план_даже_без_подключённого_контроллера() {
            let mut key = [0; r2k_core::control::KEY_LEN];
            key[0] = 4;
            key[37] = 6;
            let event = r2k_core::control::AppliedEvent {
                key,
                plan_id: [0xa5; 16],
                trial_id: [0x5a; 16],
                execution_id: 77,
                binding: r2k_core::control::BindingContext {
                    generation: 9,
                    kind: 1,
                    family: 4,
                    shape: 2,
                    temporary: true,
                    epoch: [0x3c; 16],
                },
            };
            let mut control = None;
            let mut flow_journal = R2oFlowJournal::with_capacity(2).unwrap();

            send_applied_event(
                &mut super::TcpSessions::default(),
                &mut control,
                &mut flow_journal,
                123,
                &event,
            );

            let entry = flow_journal.get(0).unwrap();
            assert_eq!(entry.at_ns, 123);
            assert_eq!(
                entry.kind,
                r2o_datapath::flow_journal::R2oFlowJournalKind::PlanDone
            );
            assert_eq!(entry.plan_id, [0xa5; 16]);
            assert_eq!(entry.trial_id, [0x5a; 16]);
            assert_eq!(entry.execution_id, 77);
            assert_eq!(entry.binding, Some(event.binding));
        }

        #[test]
        fn r2o_передаёт_tcp_обмен_из_runtime_в_общий_журнал() {
            fn отправить_tcp_пакет(
                sessions: &mut TcpSessions,
                journal: &mut R2oFlowJournal,
                control: &mut Option<ControlServer>,
                origin: &Instant,
                source: ([u8; 4], u16),
                destination: ([u8; 4], u16),
                flags: u8,
                sequence: u32,
                payload: &[u8],
            ) -> Vec<u8> {
                let mut packet = vec![0; 40 + payload.len()];
                let packet_len = packet.len() as u16;
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
                packet[8] = 64;
                packet[9] = 6;
                packet[12..16].copy_from_slice(&source.0);
                packet[16..20].copy_from_slice(&destination.0);
                packet[20..22].copy_from_slice(&source.1.to_be_bytes());
                packet[22..24].copy_from_slice(&destination.1.to_be_bytes());
                packet[24..28].copy_from_slice(&sequence.to_be_bytes());
                packet[32] = 0x50;
                packet[33] = flags;
                packet[34..36].copy_from_slice(&4096_u16.to_be_bytes());
                packet[40..].copy_from_slice(payload);
                super::decide_with_tcp_session(
                    sessions,
                    &super::Plan::default(),
                    &packet,
                    control,
                    journal,
                    origin,
                );
                packet
            }

            let клиент: ([u8; 4], u16) = ([192, 0, 2, 10], 41000);
            let сервер: ([u8; 4], u16) = ([198, 51, 100, 20], 443);
            let mut ключ = [0; r2k_core::control::KEY_LEN];
            ключ[0] = 4;
            ключ[1..5].copy_from_slice(&клиент.0);
            ключ[17..21].copy_from_slice(&сервер.0);
            ключ[33..35].copy_from_slice(&клиент.1.to_be_bytes());
            ключ[35..37].copy_from_slice(&сервер.1.to_be_bytes());
            ключ[37] = 6;

            let mut client_hello = vec![0x16, 0x03, 0x03, 0, 47, 1, 0, 0, 43, 0x03, 0x03];
            client_hello.extend_from_slice(&[0; 32]);
            client_hello.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0, 0, 0]);
            let mut server_hello = vec![0x16, 0x03, 0x03, 0, 42, 2, 0, 0, 38];
            server_hello.extend_from_slice(&[0; 38]);
            let application_data = [0x17, 0x03, 0x03, 0, 1, 0];

            let mut sessions = TcpSessions::default();
            let mut journal = R2oFlowJournal::with_capacity(4).unwrap();
            let mut control = None;
            let origin = Instant::now();
            отправить_tcp_пакет(
                &mut sessions,
                &mut journal,
                &mut control,
                &origin,
                клиент,
                сервер,
                0x02,
                700,
                &[],
            );
            отправить_tcp_пакет(
                &mut sessions,
                &mut journal,
                &mut control,
                &origin,
                сервер,
                клиент,
                0x12,
                900,
                &[],
            );
            let hello_packet = отправить_tcp_пакет(
                &mut sessions,
                &mut journal,
                &mut control,
                &origin,
                клиент,
                сервер,
                0x18,
                701,
                &client_hello,
            );
            let applied = super::AppliedEvent {
                key: ключ,
                plan_id: [0xa5; 16],
                trial_id: [0x5a; 16],
                execution_id: 77,
                binding: r2k_core::control::BindingContext {
                    generation: 9,
                    kind: 1,
                    family: 4,
                    shape: 2,
                    temporary: true,
                    epoch: [0x3c; 16],
                },
            };
            assert_eq!(sessions.r2o_begin_execution(&hello_packet, 77), Some(ключ));
            send_applied_event(&mut sessions, &mut control, &mut journal, 1, &applied);
            отправить_tcp_пакет(
                &mut sessions,
                &mut journal,
                &mut control,
                &origin,
                сервер,
                клиент,
                0x18,
                900,
                &server_hello,
            );
            assert_eq!(journal.count(), 2);
            let первый_обмен = journal.get(1).unwrap();
            assert_eq!(первый_обмен.key, ключ);
            assert_eq!(
                первый_обмен.kind,
                r2o_datapath::flow_journal::R2oFlowJournalKind::Exchange
            );
            assert_eq!(первый_обмен.code, 0x16);
            assert_eq!(первый_обмен.num, 47);
            assert_eq!(первый_обмен.tos, 0x04);
            assert!(первый_обмен.server_hello);
            assert_eq!(первый_обмен.planned, 1);

            отправить_tcp_пакет(
                &mut sessions,
                &mut journal,
                &mut control,
                &origin,
                сервер,
                клиент,
                0x18,
                947,
                &application_data,
            );
            assert_eq!(journal.count(), 3);
            let второй_обмен = journal.get(2).unwrap();
            assert_eq!(
                второй_обмен.kind,
                r2o_datapath::flow_journal::R2oFlowJournalKind::Exchange
            );
            assert_eq!(второй_обмен.code, 0x16);
            assert_eq!(второй_обмен.num, 53);
            assert_eq!(второй_обмен.tos, 0x0c);
            assert!(второй_обмен.server_hello);
        }

        #[test]
        fn r2o_передаёт_снятый_чужой_rst_из_runtime_в_общий_журнал() {
            fn пакет_tcp(
                source: ([u8; 4], u16),
                destination: ([u8; 4], u16),
                flags: u8,
                ttl: u8,
                sequence: u32,
                payload: &[u8],
            ) -> Vec<u8> {
                let mut packet = vec![0; 40 + payload.len()];
                let packet_len = packet.len() as u16;
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
                packet[8] = ttl;
                packet[9] = 6;
                packet[12..16].copy_from_slice(&source.0);
                packet[16..20].copy_from_slice(&destination.0);
                packet[20..22].copy_from_slice(&source.1.to_be_bytes());
                packet[22..24].copy_from_slice(&destination.1.to_be_bytes());
                packet[24..28].copy_from_slice(&sequence.to_be_bytes());
                packet[32] = 0x50;
                packet[33] = flags;
                packet[34..36].copy_from_slice(&4096_u16.to_be_bytes());
                packet[40..].copy_from_slice(payload);
                packet
            }

            let клиент: ([u8; 4], u16) = ([192, 0, 2, 10], 41000);
            let сервер: ([u8; 4], u16) = ([198, 51, 100, 20], 443);
            let mut client_hello = vec![0x16, 0x03, 0x03, 0, 47, 1, 0, 0, 43, 0x03, 0x03];
            client_hello.extend_from_slice(&[0; 32]);
            client_hello.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0, 0, 0]);

            let mut план = super::Plan::default();
            план.transport = 6;
            план.proto = 1;
            план.guards = r2k_core::plan::GUARD_RST_ALIEN;
            let mut sessions = TcpSessions::default();
            let mut journal = R2oFlowJournal::with_capacity(4).unwrap();
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!("r2o-rst-cut-{nonce}"));
            std::fs::create_dir(&directory).unwrap();
            let control_path = directory.join("datapath.sock");
            let mut control = Some(ControlServer::open(&control_path, u16::MAX as u32).unwrap());
            let mut controller = UnixStream::connect(&control_path).unwrap();
            let origin = Instant::now();
            control.as_mut().unwrap().poll().unwrap();
            assert_eq!(
                r2k_core::control::decode_greeting(
                    &r2k_core::control::read_frame(&mut controller).unwrap()
                )
                .unwrap()
                .version,
                r2k_core::control::PROTOCOL_VERSION
            );
            for packet in [
                пакет_tcp(клиент, сервер, 0x02, 64, 700, &[]),
                пакет_tcp(сервер, клиент, 0x12, 124, 900, &[]),
                пакет_tcp(клиент, сервер, 0x18, 64, 700, &client_hello),
            ] {
                super::decide_with_tcp_session(
                    &mut sessions,
                    &план,
                    &packet,
                    &mut control,
                    &mut journal,
                    &origin,
                );
            }
            let mut ключ = [0; r2k_core::control::KEY_LEN];
            ключ[0] = 4;
            ключ[1..5].copy_from_slice(&клиент.0);
            ключ[17..21].copy_from_slice(&сервер.0);
            ключ[33..35].copy_from_slice(&клиент.1.to_be_bytes());
            ключ[35..37].copy_from_slice(&сервер.1.to_be_bytes());
            ключ[37] = 6;
            sessions.mark_plan_done(&ключ);

            let сброс = пакет_tcp(сервер, клиент, 0x14, 127, 900, &[]);
            assert_eq!(
                super::decide_with_tcp_session(
                    &mut sessions,
                    &план,
                    &сброс,
                    &mut control,
                    &mut journal,
                    &origin,
                ),
                super::PacketDecision::Drop,
            );
            let signal = loop {
                let frame = r2k_core::control::read_frame(&mut controller).unwrap();
                if frame.kind == r2k_core::control::EVENT_R2O_TCP_RST_CUT {
                    break frame;
                }
            };
            assert_eq!(
                r2k_core::control::decode_r2o_tcp_rst_cut_signal(&signal).unwrap(),
                R2oTcpRstCutSignalEvent {
                    key: ключ,
                    client_is_low: true,
                }
            );
            assert_eq!(journal.count(), 1);
            let запись = journal.get(0).unwrap();
            assert_eq!(
                запись.kind,
                r2o_datapath::flow_journal::R2oFlowJournalKind::R2oTcpRstCut
            );
            assert_eq!(запись.code, 4);
            assert_eq!(запись.ttl, 127);
            assert_eq!(запись.reference_ttl, 124);
            assert_eq!(запись.planned, 1);
            assert_eq!(запись.client_is_low, Some(true));
            assert_eq!(запись.kind.russian_name(), "чужой RST TCP снят защитой");
            let кадр = запись.to_event_frame().unwrap();
            assert_eq!(
                r2o_datapath::flow_journal::R2oFlowJournalEntry::from_event_frame(&кадр).unwrap(),
                *запись
            );

            super::decide_with_tcp_session(
                &mut sessions,
                &план,
                &сброс,
                &mut control,
                &mut journal,
                &origin,
            );
            assert_eq!(
                journal.count(),
                1,
                "повтор снятого RST не создаёт запись снова"
            );
            drop(control);
            drop(controller);
            std::fs::remove_dir_all(directory).unwrap();
        }

        #[test]
        fn r2o_передаёт_ранний_rst_в_общий_журнал() {
            fn пакет_tcp(
                source: ([u8; 4], u16),
                destination: ([u8; 4], u16),
                flags: u8,
                ttl: u8,
                sequence: u32,
                payload: &[u8],
            ) -> Vec<u8> {
                let mut packet = vec![0; 40 + payload.len()];
                let packet_len = packet.len() as u16;
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
                packet[8] = ttl;
                packet[9] = 6;
                packet[12..16].copy_from_slice(&source.0);
                packet[16..20].copy_from_slice(&destination.0);
                packet[20..22].copy_from_slice(&source.1.to_be_bytes());
                packet[22..24].copy_from_slice(&destination.1.to_be_bytes());
                packet[24..28].copy_from_slice(&sequence.to_be_bytes());
                packet[32] = 0x50;
                packet[33] = flags;
                packet[34..36].copy_from_slice(&4096_u16.to_be_bytes());
                packet[40..].copy_from_slice(payload);
                packet
            }

            let клиент: ([u8; 4], u16) = ([192, 0, 2, 10], 41000);
            let сервер: ([u8; 4], u16) = ([198, 51, 100, 20], 443);
            let mut sni = Vec::new();
            sni.extend_from_slice(&15_u16.to_be_bytes());
            sni.push(0);
            sni.extend_from_slice(&12_u16.to_be_bytes());
            sni.extend_from_slice(b"example.test");
            let mut extensions = Vec::new();
            extensions.extend_from_slice(&0_u16.to_be_bytes());
            extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni);
            let mut body = vec![0x03, 0x03];
            body.extend_from_slice(&[0; 32]);
            body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);
            let mut handshake = vec![1];
            handshake.extend_from_slice(&[
                ((body.len() >> 16) & 0xff) as u8,
                ((body.len() >> 8) & 0xff) as u8,
                (body.len() & 0xff) as u8,
            ]);
            handshake.extend_from_slice(&body);
            let mut client_hello = vec![0x16, 0x03, 0x03];
            client_hello.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
            client_hello.extend_from_slice(&handshake);
            let mut sessions = TcpSessions::default();
            let mut journal = R2oFlowJournal::with_capacity(4).unwrap();
            let mut control = None;
            let origin = Instant::now();
            for packet in [
                пакет_tcp(клиент, сервер, 0x02, 64, 700, &[]),
                пакет_tcp(сервер, клиент, 0x12, 124, 900, &[]),
                пакет_tcp(клиент, сервер, 0x18, 64, 701, &client_hello),
            ] {
                super::decide_with_tcp_session(
                    &mut sessions,
                    &super::Plan::default(),
                    &packet,
                    &mut control,
                    &mut journal,
                    &origin,
                );
            }

            let mut сброс = пакет_tcp(сервер, клиент, 0x14, 127, 900, &[]);
            сброс[1] = 0x2e;
            сброс[4..6].copy_from_slice(&0x5a17_u16.to_be_bytes());
            assert_eq!(
                super::decide_with_tcp_session(
                    &mut sessions,
                    &super::Plan::default(),
                    &сброс,
                    &mut control,
                    &mut journal,
                    &origin,
                ),
                super::PacketDecision::Accept,
            );

            assert_eq!(journal.count(), 1);
            let entry = journal.get(0).unwrap();
            assert_eq!(
                entry.kind,
                r2o_datapath::flow_journal::R2oFlowJournalKind::R2oTcpRst
            );
            assert_eq!(entry.code, 1);
            assert_eq!(entry.ttl, 127);
            assert_eq!(entry.reference_ttl, 124);
            assert_eq!(entry.tos, 0x2e);
            assert_eq!(entry.ip_id, 0x5a17);
            assert!(!entry.server_hello);
            assert_eq!(entry.planned, 2);
            assert_eq!(entry.client_shape, r2k_core::control::SHAPE_LEGACY);
            assert_eq!(entry.client_is_low, Some(true));
            assert_eq!(
                r2o_datapath::flow_journal::R2oFlowJournalEntry::from_event_frame(
                    &entry.to_event_frame().unwrap()
                )
                .unwrap(),
                *entry
            );
            println!(
                "R2O_DIFF code={} ttl={} ref={} tos={} ipid={} planned={} shape={} client_is_low={}",
                entry.code,
                entry.ttl,
                entry.reference_ttl,
                entry.tos,
                entry.ip_id,
                entry.planned,
                entry.client_shape,
                u8::from(entry.client_is_low.unwrap_or_default()),
            );
        }

        #[test]
        fn r2o_передаёт_первый_udp_ответ_из_runtime_в_общий_журнал() {
            fn пакет_udp(
                source: ([u8; 4], u16),
                destination: ([u8; 4], u16),
                payload: &[u8],
            ) -> Vec<u8> {
                let mut packet = vec![0; 28 + payload.len()];
                let packet_len = packet.len() as u16;
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
                packet[8] = 64;
                packet[9] = 17;
                packet[12..16].copy_from_slice(&source.0);
                packet[16..20].copy_from_slice(&destination.0);
                packet[20..22].copy_from_slice(&source.1.to_be_bytes());
                packet[22..24].copy_from_slice(&destination.1.to_be_bytes());
                packet[24..26].copy_from_slice(&(8_u16 + payload.len() as u16).to_be_bytes());
                packet[28..].copy_from_slice(payload);
                packet
            }

            let initial = include_bytes!("../../r2k-core/tests/fixtures/quic_v1_initial.bin");
            let client: ([u8; 4], u16) = ([192, 0, 2, 10], 53_123);
            let server: ([u8; 4], u16) = ([198, 51, 100, 20], 443);
            let start = Instant::now();
            let mut sessions = R2oQuicSessions::default();
            let mut journal = R2oFlowJournal::with_capacity(4).unwrap();
            let mut initial_packet = пакет_udp(client, server, initial);

            observe_quic_packet(
                &mut sessions,
                &initial_packet,
                start,
                None,
                &mut journal,
                &start,
            );
            assert_eq!(journal.count(), 0);

            let reply = пакет_udp(server, client, b"reply");
            observe_quic_packet(
                &mut sessions,
                &reply,
                start + std::time::Duration::from_millis(100),
                None,
                &mut journal,
                &start,
            );
            assert_eq!(journal.count(), 1);
            let first_reply = journal.get(0).unwrap();
            assert_eq!(first_reply.key[37], 17);
            assert_eq!(&first_reply.key[1..5], &client.0);
            assert_eq!(&first_reply.key[17..21], &server.0);
            assert_eq!(
                first_reply.kind,
                r2o_datapath::flow_journal::R2oFlowJournalKind::Exchange
            );
            assert_eq!(first_reply.code, 0);
            assert_eq!(first_reply.num, 5);

            let later_reply = пакет_udp(server, client, b"later");
            observe_quic_packet(
                &mut sessions,
                &later_reply,
                start + std::time::Duration::from_millis(200),
                None,
                &mut journal,
                &start,
            );
            assert_eq!(journal.count(), 1);

            let second_client: ([u8; 4], u16) = ([192, 0, 2, 11], 53_124);
            initial_packet = пакет_udp(second_client, server, initial);
            observe_quic_packet(
                &mut sessions,
                &initial_packet,
                start + std::time::Duration::from_millis(300),
                None,
                &mut journal,
                &start,
            );
            let empty_reply = пакет_udp(server, second_client, &[]);
            observe_quic_packet(
                &mut sessions,
                &empty_reply,
                start + std::time::Duration::from_millis(400),
                None,
                &mut journal,
                &start,
            );
            assert_eq!(journal.count(), 2);
            assert_eq!(journal.get(1).unwrap().num, 0);
        }

        #[test]
        fn r2o_передаёт_stun_подтверждение_transaction_id_в_общий_журнал() {
            fn пакет_udp(
                source: ([u8; 4], u16),
                destination: ([u8; 4], u16),
                payload: &[u8],
            ) -> Vec<u8> {
                let mut packet = vec![0; 28 + payload.len()];
                let packet_len = packet.len() as u16;
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
                packet[8] = 64;
                packet[9] = 17;
                packet[12..16].copy_from_slice(&source.0);
                packet[16..20].copy_from_slice(&destination.0);
                packet[20..22].copy_from_slice(&source.1.to_be_bytes());
                packet[22..24].copy_from_slice(&destination.1.to_be_bytes());
                packet[24..26].copy_from_slice(&(8_u16 + payload.len() as u16).to_be_bytes());
                packet[28..].copy_from_slice(payload);
                packet
            }

            let client = ([192, 0, 2, 10], 53_123);
            let server = ([198, 51, 100, 20], 3478);
            let transaction_id = [8; 12];
            let request = binding_request(transaction_id);
            let mut response = [0; 20];
            response[..8].copy_from_slice(&[0x01, 0x01, 0, 0, 0x21, 0x12, 0xa4, 0x42]);
            response[8..].copy_from_slice(&transaction_id);
            let start = Instant::now();
            let mut sessions = R2oUdpSessions::new().unwrap();
            let mut journal = R2oFlowJournal::with_capacity(4).unwrap();
            let request_packet = пакет_udp(client, server, &request);
            assert!(udp_packet_admitted(&mut sessions, &request_packet, start));
            observe_stun_packet(
                &mut sessions,
                &request_packet,
                start,
                Some(R2O_NF_INET_POST_ROUTING),
                &mut journal,
                &start,
            );

            let response_packet = пакет_udp(server, client, &response);
            assert!(udp_packet_admitted(
                &mut sessions,
                &response_packet,
                start + Duration::from_millis(20),
            ));
            observe_stun_packet(
                &mut sessions,
                &response_packet,
                start + Duration::from_millis(20),
                Some(R2O_NF_INET_FORWARD),
                &mut journal,
                &start,
            );

            let event = journal.get(0).unwrap();
            assert_eq!(
                event.kind,
                r2o_datapath::flow_journal::R2oFlowJournalKind::Exchange
            );
            assert_eq!(event.code, 2);
            assert_eq!(event.num, response.len() as u32);
            assert_eq!(&event.key[1..5], &client.0);
            assert_eq!(&event.key[17..21], &server.0);
        }

        #[test]
        fn observe_mode_is_explicit_and_rejects_unknown_values() {
            let options = parse_options(&[
                "--queue".into(),
                "2000".into(),
                "--mode".into(),
                "observe".into(),
            ])
            .unwrap();
            assert_eq!(options.mode, RuntimeMode::Observe);
            assert_eq!(load_plan(&options).unwrap(), super::Plan::default());

            assert!(
                parse_options(&[
                    "--queue".into(),
                    "2000".into(),
                    "--mode".into(),
                    "disabled".into(),
                ])
                .is_err()
            );
        }

        #[test]
        fn raw_socket_is_opened_only_for_transmit_plans_or_control() {
            let tcp_plan = super::Plan {
                transport: 6,
                ..super::Plan::default()
            };
            let fragment_plan = super::Plan {
                transport: 17,
                proto: r2k_core::plan::PROTO_QUIC,
                ipfrag: 1,
                ..super::Plan::default()
            };
            let clearance_plan = super::Plan {
                minexec: 10,
                transport: 17,
                proto: r2k_core::plan::PROTO_QUIC,
                payloads: vec![r2k_core::plan::Payload {
                    id: 1,
                    bytes: vec![0; 16],
                }],
                fakes: vec![r2k_core::plan::Fake {
                    payload_id: 1,
                    poison_id: 0,
                    repeats: 1,
                    placement: 0,
                    gap_us: 0,
                    tls_mod: 0,
                }],
                ..super::Plan::default()
            };
            let ttl_plan = super::Plan {
                minexec: 10,
                transport: 17,
                proto: r2k_core::plan::PROTO_QUIC,
                payloads: vec![r2k_core::plan::Payload {
                    id: 1,
                    bytes: r2k_core::plan::R2K_QUIC_TTL_PROBE_PAYLOAD.to_vec(),
                }],
                poisons: vec![r2k_core::plan::Poison {
                    id: 1,
                    ttl: 3,
                    flags: 0,
                    seq_shift: 0,
                }],
                fakes: vec![r2k_core::plan::Fake {
                    payload_id: 1,
                    poison_id: 1,
                    repeats: 2,
                    placement: 0,
                    gap_us: 0,
                    tls_mod: 0,
                }],
                ..super::Plan::default()
            };
            let fake_plan = super::Plan {
                minexec: 10,
                transport: 17,
                proto: r2k_core::plan::PROTO_QUIC,
                payloads: vec![r2k_core::plan::Payload {
                    id: 1,
                    bytes: vec![1],
                }],
                fakes: vec![r2k_core::plan::Fake {
                    payload_id: 1,
                    poison_id: 0,
                    repeats: 1,
                    placement: 0,
                    gap_us: 0,
                    tls_mod: 0,
                }],
                ..super::Plan::default()
            };
            for plan in [
                &tcp_plan,
                &fragment_plan,
                &clearance_plan,
                &ttl_plan,
                &fake_plan,
            ] {
                assert!(!needs_raw_socket(RuntimeMode::Observe, plan, false));
                assert!(needs_raw_socket(RuntimeMode::Apply, plan, false));
            }
            assert!(!needs_raw_socket(
                RuntimeMode::Observe,
                &super::Plan::default(),
                true
            ));
            assert!(needs_raw_socket(
                RuntimeMode::Apply,
                &super::Plan::default(),
                true
            ));
        }

        #[test]
        fn controller_only_mode_rejects_missing_control_and_explicit_plan() {
            assert!(
                parse_options(&["--controller-only".into(), "--queue".into(), "2000".into()])
                    .is_err()
            );
            assert!(
                parse_options(&[
                    "--controller-only".into(),
                    "--control".into(),
                    "/tmp/r2o-datapath.sock".into(),
                    "--queue".into(),
                    "2000".into(),
                    "--plan".into(),
                    "/tmp/plan.r2op".into(),
                ])
                .is_err()
            );
        }

        #[test]
        fn failed_drop_after_payload_send_never_accepts_original() {
            let mut verdicts = Vec::new();
            let result = release_with(17, OriginalFate::Drop, true, |_, action| {
                verdicts.push(action);
                Err(io::Error::other("netlink failure"))
            });

            assert!(result.is_err());
            assert_eq!(verdicts, [NF_DROP]);
        }

        #[test]
        fn failed_drop_before_payload_send_keeps_fail_open_fallback() {
            let mut verdicts = Vec::new();
            let result = release_with(17, OriginalFate::Drop, false, |_, action| {
                verdicts.push(action);
                if action == NF_DROP {
                    Err(io::Error::other("netlink failure"))
                } else {
                    Ok(())
                }
            });

            assert!(result.is_ok());
            assert_eq!(verdicts, [NF_DROP, NF_ACCEPT]);
        }

        #[test]
        fn grouped_release_attempts_every_id_and_falls_back_per_packet() {
            let mut verdicts = Vec::new();
            let result =
                release_many_with(&[17, 18, 19], OriginalFate::Drop, false, |id, action| {
                    verdicts.push((id, action));
                    if action == NF_DROP {
                        Err(io::Error::other("netlink failure"))
                    } else {
                        Ok(())
                    }
                });

            assert!(result.is_ok());
            assert_eq!(
                verdicts,
                [
                    (17, NF_DROP),
                    (17, NF_ACCEPT),
                    (18, NF_DROP),
                    (18, NF_ACCEPT),
                    (19, NF_DROP),
                    (19, NF_ACCEPT),
                ]
            );
        }

        #[test]
        fn grouped_release_never_accepts_after_payload_was_sent() {
            let mut verdicts = Vec::new();
            let result = release_many_with(&[21, 22], OriginalFate::Drop, true, |id, action| {
                verdicts.push((id, action));
                Err(io::Error::other("netlink failure"))
            });

            assert!(result.is_err());
            assert_eq!(verdicts, [(21, NF_DROP), (22, NF_DROP)]);
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = app::run() {
        eprintln!("r2o-datapath: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("r2o-datapath запускается только на Linux с NFQUEUE");
    std::process::exit(1);
}
