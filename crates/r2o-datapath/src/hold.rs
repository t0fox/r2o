//! Ограниченное удержание NFQUEUE-пакетов для сегментированных TLS ClientHello.

use crate::capture::{
    CaptureResult, CaptureStats, CaptureTable, TcpFlowKey, TcpHello, tcp_hello_from_bytes,
    tcp_http_hello_from_bytes, tcp_timestamp_option_present,
};
use r2k_core::addr::Address;
use r2k_core::control::{AppliedEvent, BindingContext, HttpPortalEvent, HttpResponseEvent};
use r2k_core::packet::{PacketView, TcpSegmentView};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub const HOLD_SLOTS: usize = 16;
pub const HOLD_PACKETS: usize = 8;
pub const HOLD_PACKET_BYTES: usize = 1600;
pub const HOLD_WAIT: Duration = Duration::from_millis(100);
const HOLD_EARLY_WINDOW: u32 = 16_384;
const SYN_TRACK_CAPACITY: usize = 1024;
const SYN_TRACK_TTL: Duration = Duration::from_secs(120);
/// C `D2K_HTTP80_IDLE_NS` (`datapath/include/d2k_http80.h:50`).
const HTTP_FLOW_IDLE: Duration = Duration::from_secs(60);
/// C `D2K_HTTP80_FLOWS=128` (`datapath/include/d2k_http80.h:40`).
pub const HTTP_FLOW_CAPACITY: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HoldOutcome {
    Pass,
    Waiting,
    /// The saved packet is now owned by raw-send; immediately DROP its NFQUEUE id.
    OwnedWaiting,
    Drop,
    Ready {
        ids: Vec<u32>,
        packet: Vec<u8>,
    },
    /// The held originals were already removed from NFQUEUE and may be replayed via raw-send.
    OwnedReady {
        ids: Vec<u32>,
        packet: Vec<u8>,
        originals: Vec<Vec<u8>>,
    },
    Observed {
        hello: TcpHello,
    },
    HttpResponse {
        event: Box<HttpResponseEvent>,
        portal: Option<HttpPortalEvent>,
        redirect: Option<Vec<u8>>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedResult {
    /// Идентификаторы пакетов для передачи без изменений при таймауте, смене плана или ошибке.
    pub released: Vec<u32>,
    pub outcome: HoldOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oIncompleteCaptureKind {
    Tls,
    Http,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oIncompleteCaptureDiagnostic {
    pub flow: TcpFlowKey,
    pub kind: R2oIncompleteCaptureKind,
    pub captured_bytes: usize,
    pub declared_record_bytes: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HoldOptions {
    pub revision: u64,
    pub allow_tls: bool,
    pub allow_http: bool,
    pub observe_tls: bool,
    pub observe_http: bool,
    /// Own eligible held non-HTTP originals through the raw socket, matching D2O.
    pub own_packets: bool,
}

/// Счётчики владения TCP-пакетами, соответствующие d2k_hold_stats в D2O.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct R2oHoldStats {
    pub started: u64,
    pub ready: u64,
    pub released: u64,
    pub full: u64,
    pub timed_out: u64,
    pub timed_out_packets: u64,
    pub plan_changed: u64,
    pub dropped_all: u64,
    pub joined: u64,
    pub mismatched: u64,
    pub sided: u64,
    pub pending: usize,
}

/// C `d2k_http80_stats` (`datapath/http80.c:100-115`): снимок счётчиков
/// HTTP/80, который C печатает в сводке (`d2kd.c:894-905`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct R2oHttp80Stats {
    pub requests: u64,
    pub injections: u64,
    pub answered: u64,
    pub swap_failed: u64,
    pub dropped: u64,
    pub evicted: u64,
    pub untracked: u64,
    pub unparsed: u64,
    pub later: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Endpoint {
    address: Address,
    port: u16,
}

#[derive(Clone, Copy)]
struct SynAnchor {
    key: TcpFlowKey,
    client: Endpoint,
    sequence: u32,
    generation: u64,
    seen: Instant,
    syn_seen: Instant,
    rtt: Option<Duration>,
    server_sequence: Option<u32>,
    attempted: bool,
    saw_hello: bool,
    unassembled_reported: bool,
    controller_probe: bool,
    r2o_http_requests: r2k_core::httpup::R2oHttpRequestSequence,
}

struct HttpRequestFlow {
    key: TcpFlowKey,
    client: Endpoint,
    generation: u64,
    host: Vec<u8>,
    path: Vec<u8>,
    target: Vec<u8>,
    request_sequence: u32,
    request_end: u32,
    request_stream: r2k_core::httpup::R2oHttpRequestStream,
    client_next: u32,
    next_known: bool,
    request_ms: u64,
    request_no: u64,
    applied: Option<AppliedEvent>,
    response: r2k_core::http_response::HttpResponseParser,
    response_next: Option<u32>,
    acked_response: u32,
    body_start: Option<u32>,
    response_progress: Instant,
    response_started: Option<Instant>,
    response_segments: u8,
    rtt: Duration,
    response_reported: bool,
    answered: bool,
    ready_for_next: bool,
    seen: Instant,
}

impl HttpRequestFlow {
    fn feed_request(&mut self, sequence: u32, bytes: &[u8]) {
        let (next, known) = self.request_stream.feed_and_next_known(sequence, bytes);
        self.client_next = next;
        self.next_known = known;
    }
}

struct HttpRequestObservation<'a> {
    sequence: u32,
    request: &'a [u8],
    host: Vec<u8>,
    target: Vec<u8>,
    response_anchor: Option<u32>,
    rtt: Duration,
    now: Instant,
}

struct HeldPacket {
    id: u32,
    sequence: u32,
    bytes: Vec<u8>,
    owned: bool,
}

struct HeldFlow {
    key: TcpFlowKey,
    client: Endpoint,
    acknowledgment: u32,
    generation: u64,
    revision: u64,
    deadline: Instant,
    anchor: u32,
    kind: HoldKind,
    packets: Vec<HeldPacket>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HoldKind {
    Tls,
    Http,
}

#[derive(Default)]
pub struct HoldTable {
    syns: Vec<SynAnchor>,
    http_requests: Vec<HttpRequestFlow>,
    slots: Vec<HeldFlow>,
    capture: CaptureTable,
    incomplete_diagnostics: VecDeque<R2oIncompleteCaptureDiagnostic>,
    next_generation: u64,
    stats: R2oHoldStats,
    http80: R2oHttp80Stats,
    owned_releases: Vec<Vec<u8>>,
}

impl HoldTable {
    /// Возвращает накопленные счётчики сборки TCP-приветствий и HTTP-запросов.
    pub fn r2o_capture_stats(&self) -> CaptureStats {
        self.capture.stats()
    }

    pub fn r2o_hold_stats(&self) -> R2oHoldStats {
        self.stats
    }

    /// C `d2k_http80_get_stats`: снимок счётчиков HTTP/80.
    pub fn r2o_http80_stats(&self) -> R2oHttp80Stats {
        self.http80
    }

    /// Take held originals that must be replayed through the raw socket on release.
    pub fn r2o_take_owned_releases(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.owned_releases)
    }

    pub fn note_http_execution(&mut self, sequence: u32, event: &AppliedEvent) {
        let Some(flow) = self.http_requests.iter_mut().find(|flow| {
            flow.key.wire_key() == event.key
                && flow.request_sequence == sequence
                && !flow.response_reported
        }) else {
            return;
        };
        flow.applied = Some(event.clone());
    }

    pub fn reject_http_response(
        &mut self,
        key: &[u8; r2k_core::control::KEY_LEN],
        request_no: u64,
    ) {
        if let Some(flow) = self
            .http_requests
            .iter_mut()
            .find(|flow| flow.key.wire_key() == *key && flow.request_no == request_no)
        {
            flow.ready_for_next = false;
        }
    }

    /// C `d2k_http80_delivered` с `accepted=0` (`http80.c:267-276`): замена
    /// не дошла, ответ помечается неизвестным (код 2), поток — DONE.
    pub fn r2o_http_delivery_rejected(&mut self, event: &mut HttpResponseEvent) -> bool {
        let Some(flow) = self
            .http_requests
            .iter_mut()
            .find(|flow| flow.key.wire_key() == event.key && flow.request_no == event.request_no)
        else {
            return false;
        };
        flow.ready_for_next = false;
        event.code = 2;
        true
    }

    /// Забрать диагностику TLS/HTTP-заголовков, которые истекли до сборки.
    pub fn r2o_take_incomplete_diagnostics(&mut self) -> Vec<R2oIncompleteCaptureDiagnostic> {
        self.incomplete_diagnostics.drain(..).collect()
    }

    pub fn mark_http_response_answered(
        &mut self,
        key: &[u8; r2k_core::control::KEY_LEN],
        request_no: u64,
    ) -> bool {
        let Some(flow) = self
            .http_requests
            .iter_mut()
            .find(|flow| flow.key.wire_key() == *key && flow.request_no == request_no)
        else {
            return false;
        };
        flow.answered = true;
        self.http80.answered = self.http80.answered.saturating_add(1);
        true
    }

    /// C `d2k_http80_swap` (`http80.c:527-545`): успешная замена помечает
    /// ответ и portal answered; отказ — `swap_failed`, поток остаётся
    /// INJECTED и получает обычный ACCEPT.
    pub fn r2o_apply_http_swap_result(
        &mut self,
        event: Option<&HttpResponseEvent>,
        portal: Option<&mut HttpPortalEvent>,
        swapped: bool,
    ) -> bool {
        if !swapped {
            self.note_http_swap_failed();
            return false;
        }
        if let Some(event) = event {
            self.mark_http_response_answered(&event.key, event.request_no);
        }
        if let Some(portal) = portal {
            portal.answered = true;
        }
        true
    }

    /// C `d2k_http80_swap`: вердикт с заменой не принят — вставка ушла как есть.
    pub fn note_http_swap_failed(&mut self) {
        self.http80.swap_failed = self.http80.swap_failed.saturating_add(1);
    }

    pub fn sweep_http_responses(&mut self, now: Instant) -> Vec<HttpResponseEvent> {
        let mut events = Vec::new();
        if events.try_reserve(self.http_requests.len()).is_err() {
            return events;
        }
        for flow in &mut self.http_requests {
            if flow.response_reported || flow.response.is_invalid() {
                continue;
            }
            let Some(remaining) = flow.response.fixed_body_remaining() else {
                continue;
            };
            if remaining == 0 {
                continue;
            }
            let Some(body_start) = flow.body_start else {
                continue;
            };
            let body_end = body_start
                .wrapping_add(flow.response.body_bytes().saturating_add(remaining) as u32);
            let response_next = flow.response_next.unwrap_or(body_start);
            let delivered = if seq_after(flow.acked_response, response_next) {
                flow.acked_response
            } else {
                response_next
            };
            if !seq_after(body_end, delivered)
                || now.saturating_duration_since(flow.response_progress)
                    <= flow.rtt.saturating_mul(3).max(Duration::from_secs(2))
            {
                continue;
            }
            let delivered_body = if seq_after(delivered, body_start) {
                u64::from(delivered.wrapping_sub(body_start))
            } else {
                0
            };
            let body_bytes = flow.response.body_bytes().max(delivered_body);
            events.push(finish_http_response(flow, 4, Some(body_bytes)).0);
        }
        events
    }

    pub fn feed(
        &mut self,
        id: u32,
        packet: &[u8],
        now: Instant,
        revision: u64,
        allow_tls: bool,
        allow_http: bool,
    ) -> FeedResult {
        self.feed_observing(
            id,
            packet,
            now,
            HoldOptions {
                revision,
                allow_tls,
                allow_http,
                observe_tls: false,
                observe_http: false,
                own_packets: false,
            },
        )
    }

    pub fn feed_observing(
        &mut self,
        id: u32,
        packet: &[u8],
        now: Instant,
        options: HoldOptions,
    ) -> FeedResult {
        self.feed_observing_mode(id, packet, now, options, false)
    }

    /// Обработать пакет зонда, сохранив удержание и применение плана без диагностики потока.
    pub fn feed_controller_probe(
        &mut self,
        id: u32,
        packet: &[u8],
        now: Instant,
        options: HoldOptions,
    ) -> FeedResult {
        self.feed_observing_mode(id, packet, now, options, true)
    }

    /// Отпустить ранее удержанные пакеты потока после отказа исполнения.
    pub fn r2o_release_damaged_flow(&mut self, packet: &[u8]) -> Vec<u32> {
        let Some((_, _, key, _, _)) = parse_tcp(packet) else {
            return Vec::new();
        };
        let Some(index) = self.slot_index(&key) else {
            return Vec::new();
        };
        let released = self.remove_slot(index);
        self.capture.forget(&key);
        released
    }

    fn feed_observing_mode(
        &mut self,
        id: u32,
        packet: &[u8],
        now: Instant,
        options: HoldOptions,
        controller_probe: bool,
    ) -> FeedResult {
        let HoldOptions {
            revision,
            allow_tls,
            allow_http,
            observe_tls,
            observe_http,
            own_packets,
        } = options;
        let mut released = self.flush(now, revision, false);
        self.syns
            .retain(|anchor| now.saturating_duration_since(anchor.seen) < SYN_TRACK_TTL);
        self.http_requests
            .retain(|flow| now.saturating_duration_since(flow.seen) <= HTTP_FLOW_IDLE);
        let Some((view, tcp, key, source, destination)) = parse_tcp(packet) else {
            return FeedResult {
                released,
                outcome: HoldOutcome::Pass,
            };
        };

        if tcp.flags & 0x02 != 0 && tcp.flags & 0x10 == 0 {
            if let Some(index) = self.slot_index(&key) {
                released.extend(self.remove_slot(index));
            }
            self.capture.forget(&key);
            self.http_requests.retain(|flow| flow.key != key);
            self.remember_syn(key, source, tcp.sequence, now, controller_probe);
            return FeedResult {
                released,
                outcome: HoldOutcome::Pass,
            };
        }

        if let Some(anchor_index) = self.syn_index(&key) {
            self.syns[anchor_index].seen = now;
            self.syns[anchor_index].controller_probe |= controller_probe;
            if source != self.syns[anchor_index].client && tcp.flags & 0x12 == 0x12 {
                self.syns[anchor_index].server_sequence = Some(tcp.sequence);
                self.syns[anchor_index].rtt =
                    now.checked_duration_since(self.syns[anchor_index].syn_seen);
            }
        }
        let slot_index = self.slot_index(&key);
        if let Some(index) = slot_index {
            let opposite_side = source != self.slots[index].client;
            if tcp.flags & 0x07 != 0 || (opposite_side && !tcp.payload.is_empty()) {
                if opposite_side {
                    self.stats.sided = self.stats.sided.saturating_add(1);
                }
                released.extend(self.remove_slot(index));
                self.capture.forget(&key);
                return FeedResult {
                    released,
                    outcome: HoldOutcome::Pass,
                };
            }
        }
        let payload = &packet[tcp.payload.clone()];
        if observe_http
            && source.port != 80
            && tcp.flags & 0x10 != 0
            && let Some(anchor_index) = self.syn_index(&key)
            && self.syns[anchor_index].client == source
        {
            self.observe_http_ack(
                key,
                self.syns[anchor_index].generation,
                tcp.acknowledgment,
                now,
            );
        }
        if payload.is_empty() && tcp.flags & 0x05 == 0 {
            if slot_index.is_some_and(|index| self.slots[index].client != source) {
                self.stats.sided = self.stats.sided.saturating_add(1);
            }
            return FeedResult {
                released,
                outcome: HoldOutcome::Pass,
            };
        }

        let mut anchor_index = self.syn_index(&key);
        if anchor_index.is_none()
            && observe_http
            && destination.port == 80
            && (payload.starts_with(b"GET ") || payload.starts_with(b"HEAD "))
        {
            self.remember_syn(
                key,
                source,
                tcp.sequence.wrapping_sub(1),
                now,
                controller_probe,
            );
            anchor_index = self.syn_index(&key);
        }
        if anchor_index.is_none() && observe_tls && tls_record_head(payload) {
            self.remember_syn(
                key,
                source,
                tcp.sequence.wrapping_sub(1),
                now,
                controller_probe,
            );
            anchor_index = self.syn_index(&key);
            if let Some(index) = anchor_index {
                self.syns[index].attempted = true;
            }
        }
        let Some(anchor_index) = anchor_index else {
            if destination.port == 80 && !payload.is_empty() {
                // C `d2k_http80_packet`: нагрузка клиента к :80 без потока.
                self.http80.untracked = self.http80.untracked.saturating_add(1);
            }
            if let Some(index) = slot_index {
                released.extend(self.remove_slot(index));
                self.capture.forget(&key);
            }
            return FeedResult {
                released,
                outcome: HoldOutcome::Pass,
            };
        };
        let anchor = self.syns[anchor_index];
        if source != anchor.client {
            if self.http_requests.iter().any(|flow| {
                flow.key == key
                    && flow.client == destination
                    && flow.generation == anchor.generation
                    && flow.answered
            }) {
                self.http80.dropped = self.http80.dropped.saturating_add(1);
                return FeedResult {
                    released,
                    outcome: HoldOutcome::Drop,
                };
            }
            if observe_http
                && source.port == 80
                && destination == anchor.client
                && let Some((event, portal, redirect)) =
                    self.observe_http_response(key, anchor, destination, &tcp, payload, now)
            {
                return FeedResult {
                    released,
                    outcome: HoldOutcome::HttpResponse {
                        event: Box::new(event),
                        portal,
                        redirect,
                    },
                };
            }
            if let Some(index) = slot_index {
                released.extend(self.remove_slot(index));
                self.capture.forget(&key);
            }
            return FeedResult {
                released,
                outcome: HoldOutcome::Pass,
            };
        }
        if observe_http
            && tcp.flags & 0x05 != 0
            && let Some(event) = self.observe_http_client_close(key, anchor, source, &tcp, now)
        {
            return FeedResult {
                released,
                outcome: HoldOutcome::HttpResponse {
                    event: Box::new(event),
                    portal: None,
                    redirect: None,
                },
            };
        }
        if payload.is_empty() {
            return FeedResult {
                released,
                outcome: HoldOutcome::Pass,
            };
        }
        let mut http_later = false;
        if destination.port == 80
            && source == anchor.client
            && let Some(flow) = self.http_requests.iter_mut().find(|flow| {
                flow.key == key && flow.client == source && flow.generation == anchor.generation
            })
        {
            http_later = flow.request_stream.header_done || tcp.sequence != flow.request_sequence;
            flow.feed_request(tcp.sequence, payload);
        }
        if http_later {
            self.http80.later = self.http80.later.saturating_add(1);
        }
        let offset = tcp.sequence.wrapping_sub(anchor.sequence.wrapping_add(1));
        let r2o_http_followup = anchor.r2o_http_requests.is_checked();
        let r2o_http_capture_active = self.capture.r2o_http_capture_active(key, anchor.generation);
        let r2o_http_request_candidate = if destination.port == 80
            && source == anchor.client
            && slot_index.is_none()
            && !r2o_http_capture_active
        {
            self.syns[anchor_index]
                .r2o_http_requests
                .candidate(tcp.sequence, payload.len())
        } else {
            false
        };
        if r2o_http_request_candidate {
            let complete = r2k_core::httpup::r2o_http_plan_request(payload).is_some();
            if complete || !(allow_http || observe_http) || !incomplete_http_head(payload) {
                self.syns[anchor_index]
                    .r2o_http_requests
                    .observe(tcp.sequence, payload);
            }
            if !complete && !incomplete_http_head(payload) {
                // C `d2k_http80_packet`: request_prefix не разобрал запрос.
                self.http80.unparsed = self.http80.unparsed.saturating_add(1);
            }
            if !complete && payload.windows(4).any(|window| window == b"\r\n\r\n") {
                // Заголовок уже целиком пришёл, но request-line негоден:
                // C сразу ставит DONE и считает unparsed.
                self.http80.unparsed = self.http80.unparsed.saturating_add(1);
            }
        }
        let r2o_next_http_request =
            (r2o_http_request_candidate || r2o_http_capture_active) && r2o_http_followup;
        if offset >= HOLD_EARLY_WINDOW
            && slot_index.is_none()
            && !r2o_http_request_candidate
            && !r2o_http_capture_active
        {
            return FeedResult {
                released,
                outcome: HoldOutcome::Pass,
            };
        }

        if observe_tls
            && (!allow_tls || !incomplete_tls_head(payload))
            && !anchor.attempted
            && !anchor.saw_hello
            && offset == 0
            && tls_record_head(payload)
        {
            self.syns[anchor_index].attempted = true;
        }
        let anchor = self.syns[anchor_index];
        let tls_head = offset == 0 && incomplete_tls_head(payload);
        let http_head = r2o_http_request_candidate && allow_http && incomplete_http_head(payload);
        let start_allowed = slot_index.is_some()
            || !anchor.attempted && !anchor.saw_hello && allow_tls && (offset != 0 || tls_head)
            || http_head;
        let index = if let Some(index) = slot_index {
            index
        } else {
            if !start_allowed || tcp.flags & !0x18 != 0 || tcp.flags & 0x10 == 0 {
                if observe_tls
                    && anchor.attempted
                    && !anchor.saw_hello
                    && tcp.flags & 0x05 == 0
                    && let CaptureResult::Complete { bytes, .. } =
                        self.capture.feed_with_visibility(
                            key,
                            anchor.generation,
                            now,
                            tcp.sequence,
                            Some(anchor.sequence.wrapping_add(1)),
                            payload,
                            true,
                        )
                {
                    self.syns[anchor_index].saw_hello = true;
                    self.capture.forget(&key);
                    if let Some(mut hello) = tcp_hello_from_bytes(key, &bytes) {
                        hello.tcp_has_timestamp = Some(tcp_timestamp_option_present(
                            packet.get(tcp.options.clone()).unwrap_or_default(),
                        ));
                        return FeedResult {
                            released,
                            outcome: HoldOutcome::Observed { hello },
                        };
                    }
                }
                if observe_http
                    && destination.port == 80
                    && (!anchor.saw_hello || r2o_next_http_request)
                    && tcp.flags & 0x05 == 0
                    && let CaptureResult::Complete { sequence, bytes } =
                        self.capture.feed_http_with_visibility(
                            key,
                            anchor.generation,
                            now,
                            tcp.sequence,
                            (!r2o_next_http_request).then_some(anchor.sequence.wrapping_add(1)),
                            payload,
                            !anchor.controller_probe,
                        )
                {
                    self.syns[anchor_index]
                        .r2o_http_requests
                        .observe(sequence, &bytes);
                    if let Some((host, path)) = r2k_core::httpup::request_target(&bytes) {
                        self.remember_http_request(
                            key,
                            source,
                            anchor.generation,
                            HttpRequestObservation {
                                sequence,
                                request: &bytes,
                                host,
                                target: path,
                                response_anchor: anchor
                                    .server_sequence
                                    .map(|value| value.wrapping_add(1)),
                                rtt: anchor.rtt.unwrap_or_default(),
                                now,
                            },
                        );
                    } else {
                        // C `request_prefix`: не GET/HEAD или негодная
                        // request-line — `unparsed++`, поток не ведётся.
                        self.http80.unparsed = self.http80.unparsed.saturating_add(1);
                    }
                    self.syns[anchor_index].saw_hello = true;
                    self.capture.forget(&key);
                    if let Some(hello) = tcp_http_hello_from_bytes(key, &bytes) {
                        return FeedResult {
                            released,
                            outcome: HoldOutcome::Observed { hello },
                        };
                    }
                }
                return FeedResult {
                    released,
                    outcome: HoldOutcome::Pass,
                };
            }
            if offset == 0 {
                self.syns[anchor_index].attempted = true;
            }
            if self.slots.len() == HOLD_SLOTS {
                self.stats.full = self.stats.full.saturating_add(1);
                return FeedResult {
                    released,
                    outcome: HoldOutcome::Pass,
                };
            }
            let Some(deadline) = now.checked_add(HOLD_WAIT) else {
                return FeedResult {
                    released,
                    outcome: HoldOutcome::Pass,
                };
            };
            let kind = if http_head {
                HoldKind::Http
            } else {
                HoldKind::Tls
            };
            self.slots.push(HeldFlow {
                key,
                client: source,
                acknowledgment: tcp.acknowledgment,
                generation: anchor.generation,
                revision,
                deadline,
                anchor: if r2o_http_followup {
                    tcp.sequence
                } else {
                    anchor.sequence.wrapping_add(1)
                },
                kind,
                packets: Vec::with_capacity(HOLD_PACKETS),
            });
            self.stats.started = self.stats.started.saturating_add(1);
            self.slots.len() - 1
        };

        let current_owned = own_packets && destination.port != 80;
        let slot = &self.slots[index];
        let slot_full = slot.packets.len() >= HOLD_PACKETS;
        let mismatched = slot.generation != anchor.generation
            || slot.revision != revision
            || slot.client != source
            || slot.acknowledgment != tcp.acknowledgment
            || tcp.flags & !0x18 != 0
            || tcp.flags & 0x10 == 0
            || view.total_len > HOLD_PACKET_BYTES
            || slot_full;
        if mismatched {
            if slot_full {
                self.stats.full = self.stats.full.saturating_add(1);
            }
            self.stats.mismatched = self.stats.mismatched.saturating_add(1);
            released.extend(self.remove_slot(index));
            if current_owned {
                self.owned_releases.push(packet[..view.total_len].to_vec());
            } else {
                released.push(id);
            }
            self.stats.released = self.stats.released.saturating_add(1);
            self.capture.forget(&key);
            return FeedResult {
                released,
                outcome: if current_owned {
                    HoldOutcome::OwnedWaiting
                } else {
                    HoldOutcome::Waiting
                },
            };
        }

        if self.slots[index].packets.try_reserve(1).is_err() {
            released.extend(self.remove_slot(index));
            released.push(id);
            self.stats.released = self.stats.released.saturating_add(1);
            self.capture.forget(&key);
            return FeedResult {
                released,
                outcome: HoldOutcome::Waiting,
            };
        }
        if !self.slots[index].packets.is_empty() {
            self.stats.joined = self.stats.joined.saturating_add(1);
        }
        self.slots[index].packets.push(HeldPacket {
            id,
            sequence: tcp.sequence,
            bytes: packet[..view.total_len].to_vec(),
            owned: current_owned,
        });
        self.stats.pending = self.stats.pending.saturating_add(1);

        let capture = match self.slots[index].kind {
            HoldKind::Tls => self.capture.feed_with_visibility(
                key,
                anchor.generation,
                now,
                tcp.sequence,
                Some(self.slots[index].anchor),
                payload,
                true,
            ),
            HoldKind::Http => self.capture.feed_http_with_visibility(
                key,
                anchor.generation,
                now,
                tcp.sequence,
                Some(self.slots[index].anchor),
                payload,
                !anchor.controller_probe,
            ),
        };
        match capture {
            CaptureResult::Complete { sequence, bytes } => {
                if self.slots[index].kind == HoldKind::Http
                    && observe_http
                    && let Some((host, path)) = r2k_core::httpup::request_target(&bytes)
                {
                    self.remember_http_request(
                        key,
                        source,
                        anchor.generation,
                        HttpRequestObservation {
                            sequence,
                            request: &bytes,
                            host,
                            target: path,
                            response_anchor: anchor
                                .server_sequence
                                .map(|value| value.wrapping_add(1)),
                            rtt: anchor.rtt.unwrap_or_default(),
                            now,
                        },
                    );
                }
                self.syns[anchor_index].saw_hello = true;
                let held = self.slots.remove(index);
                self.stats.pending = self.stats.pending.saturating_sub(held.packets.len());
                self.capture.forget(&key);
                let head = held
                    .packets
                    .iter()
                    .find(|held_packet| held_packet.sequence == sequence)
                    .and_then(|held_packet| synthetic_packet(&held_packet.bytes, &bytes));
                let Some(packet) = head else {
                    self.stats.released = self
                        .stats
                        .released
                        .saturating_add(held.packets.len() as u64);
                    released.extend(self.release_held_packets(held.packets));
                    return FeedResult {
                        released,
                        outcome: if current_owned {
                            HoldOutcome::OwnedWaiting
                        } else {
                            HoldOutcome::Waiting
                        },
                    };
                };
                if held.kind == HoldKind::Http {
                    self.syns[anchor_index]
                        .r2o_http_requests
                        .observe(sequence, &bytes);
                }
                self.stats.ready = self.stats.ready.saturating_add(1);
                let ids = held
                    .packets
                    .iter()
                    .map(|held_packet| held_packet.id)
                    .collect();
                // Пустой список не должен попадать в OwnedReady: иначе
                // NFQUEUE-вердикты удержанных пакетов теряются, а raw-send
                // получает пустой набор. Это же отличает «нечего возвращать».
                let all_owned = !held.packets.is_empty()
                    && held.packets.iter().all(|held_packet| held_packet.owned);
                let outcome = if all_owned {
                    let mut originals = held.packets;
                    originals
                        .sort_by_key(|held_packet| held_packet.sequence.wrapping_sub(sequence));
                    HoldOutcome::OwnedReady {
                        ids,
                        packet,
                        originals: originals
                            .into_iter()
                            .map(|held_packet| held_packet.bytes)
                            .collect(),
                    }
                } else {
                    HoldOutcome::Ready { ids, packet }
                };
                FeedResult { released, outcome }
            }
            CaptureResult::Rejected | CaptureResult::Full => {
                released.extend(self.remove_slot(index));
                self.capture.forget(&key);
                FeedResult {
                    released,
                    outcome: if current_owned {
                        HoldOutcome::OwnedWaiting
                    } else {
                        HoldOutcome::Waiting
                    },
                }
            }
            CaptureResult::Ignored | CaptureResult::Incomplete => FeedResult {
                released,
                outcome: if current_owned {
                    HoldOutcome::OwnedWaiting
                } else {
                    HoldOutcome::Waiting
                },
            },
        }
    }

    pub fn flush(&mut self, now: Instant, revision: u64, all: bool) -> Vec<u32> {
        let mut released = Vec::new();
        let mut index = 0;
        while index < self.slots.len() {
            let (key, generation, kind, deadline, slot_revision) = {
                let slot = &self.slots[index];
                (
                    slot.key,
                    slot.generation,
                    slot.kind,
                    slot.deadline,
                    slot.revision,
                )
            };
            if all || now >= deadline || revision != slot_revision {
                let pending_packets = self.slots[index].packets.len();
                if all {
                    self.stats.dropped_all = self.stats.dropped_all.saturating_add(1);
                } else if now < deadline {
                    self.stats.plan_changed = self.stats.plan_changed.saturating_add(1);
                }
                if now >= deadline {
                    self.stats.timed_out = self.stats.timed_out.saturating_add(1);
                    self.stats.timed_out_packets = self
                        .stats
                        .timed_out_packets
                        .saturating_add(pending_packets as u64);
                }
                let timed_out = !all && now >= deadline;
                if timed_out && self.incomplete_diagnostics.len() < HOLD_SLOTS {
                    let should_report = self
                        .syns
                        .iter_mut()
                        .find(|anchor| anchor.key == key && anchor.generation == generation)
                        .is_some_and(|anchor| {
                            if anchor.controller_probe {
                                return false;
                            }
                            if anchor.unassembled_reported {
                                false
                            } else {
                                anchor.unassembled_reported = true;
                                true
                            }
                        });
                    if should_report
                        && let Some((captured_bytes, declared_record_bytes)) =
                            self.capture.r2o_incomplete_summary(key, generation)
                    {
                        self.incomplete_diagnostics
                            .push_back(R2oIncompleteCaptureDiagnostic {
                                flow: key,
                                kind: match kind {
                                    HoldKind::Tls => R2oIncompleteCaptureKind::Tls,
                                    HoldKind::Http => R2oIncompleteCaptureKind::Http,
                                },
                                captured_bytes,
                                declared_record_bytes,
                            });
                    }
                }
                released.extend(self.remove_slot(index));
                self.capture.forget(&key);
            } else {
                index += 1;
            }
        }
        released
    }

    pub fn timeout_ms(&self, now: Instant, max_ms: i32) -> i32 {
        let Some(deadline) = self.slots.iter().map(|slot| slot.deadline).min() else {
            return max_ms.max(0);
        };
        if deadline <= now || max_ms <= 0 {
            return 0;
        }
        let millis = deadline.duration_since(now).as_nanos().div_ceil(1_000_000);
        max_ms.min(millis.min(i32::MAX as u128) as i32)
    }

    fn remember_syn(
        &mut self,
        key: TcpFlowKey,
        client: Endpoint,
        sequence: u32,
        now: Instant,
        controller_probe: bool,
    ) {
        self.syns
            .retain(|anchor| now.saturating_duration_since(anchor.seen) < SYN_TRACK_TTL);
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        let anchor = SynAnchor {
            key,
            client,
            sequence,
            generation: self.next_generation,
            seen: now,
            syn_seen: now,
            rtt: None,
            server_sequence: None,
            attempted: false,
            saw_hello: false,
            unassembled_reported: false,
            controller_probe,
            r2o_http_requests: r2k_core::httpup::R2oHttpRequestSequence::new(
                sequence.wrapping_add(1),
            ),
        };
        if let Some(existing) = self.syn_index(&key) {
            self.syns[existing] = anchor;
        } else if self.syns.len() < SYN_TRACK_CAPACITY {
            self.syns.push(anchor);
        }
    }

    fn remember_http_request(
        &mut self,
        key: TcpFlowKey,
        client: Endpoint,
        generation: u64,
        observation: HttpRequestObservation<'_>,
    ) {
        let HttpRequestObservation {
            sequence,
            request,
            host,
            target,
            response_anchor,
            rtt,
            now,
        } = observation;
        // C `request_prefix` принимает только `GET `/`HEAD `: остальные
        // методы в HTTP/80 не ведутся и попадают в `unparsed`.
        if !(request.starts_with(b"GET ") || request.starts_with(b"HEAD ")) {
            self.http80.unparsed = self.http80.unparsed.saturating_add(1);
            return;
        }
        self.http80.requests = self.http80.requests.saturating_add(1);
        self.http_requests
            .retain(|flow| now.saturating_duration_since(flow.seen) <= HTTP_FLOW_IDLE);
        let previous = self
            .http_requests
            .iter()
            .find(|flow| flow.key == key)
            .map(|flow| (flow.request_no.saturating_add(1), flow.response_next));
        let request_no = previous.map_or(1, |(request_no, _)| request_no);
        let target = if (request.starts_with(b"GET ") || request.starts_with(b"HEAD "))
            && target.len() < 1024
        {
            target
        } else {
            Vec::new()
        };
        let path = if request.starts_with(b"GET ")
            && !target
                .iter()
                .any(|byte| matches!(byte, b'?' | b'#' | b'\\'))
        {
            target.clone()
        } else {
            Vec::new()
        };
        let mut request_stream = r2k_core::httpup::R2oHttpRequestStream::new(sequence);
        let (client_next, next_known) = request_stream.feed_and_next_known(sequence, request);
        let replacement = HttpRequestFlow {
            key,
            client,
            generation,
            host,
            path,
            target,
            request_sequence: sequence,
            request_end: sequence.wrapping_add(request.len() as u32),
            request_stream,
            client_next,
            next_known,
            request_ms: monotonic_ms(),
            request_no,
            applied: None,
            response: r2k_core::http_response::HttpResponseParser::new(
                request.starts_with(b"HEAD "),
            ),
            response_next: previous
                .and_then(|(_, response_next)| response_next)
                .or(response_anchor),
            acked_response: previous
                .and_then(|(_, response_next)| response_next)
                .or(response_anchor)
                .unwrap_or_default(),
            body_start: None,
            response_progress: now,
            response_started: None,
            response_segments: 0,
            rtt,
            response_reported: false,
            answered: false,
            ready_for_next: false,
            seen: now,
        };
        if let Some(flow) = self.http_requests.iter_mut().find(|flow| flow.key == key) {
            *flow = replacement;
            return;
        }
        // C `make` (`datapath/http80.c:217-236`): при заполнении таблицы
        // вытесняется самый старый поток (`touched`), а не отвергается новый.
        if self.http_requests.len() >= HTTP_FLOW_CAPACITY
            && let Some((oldest, _)) = self
                .http_requests
                .iter()
                .enumerate()
                .min_by_key(|(_, flow)| flow.seen)
        {
            self.http_requests.remove(oldest);
            self.http80.evicted = self.http80.evicted.saturating_add(1);
        }
        if self.http_requests.try_reserve(1).is_err() {
            return;
        }
        self.http_requests.push(replacement);
    }

    fn observe_http_response(
        &mut self,
        key: TcpFlowKey,
        anchor: SynAnchor,
        client: Endpoint,
        tcp: &TcpSegmentView,
        payload: &[u8],
        now: Instant,
    ) -> Option<(HttpResponseEvent, Option<HttpPortalEvent>, Option<Vec<u8>>)> {
        let index = self.http_requests.iter().position(|flow| flow.key == key)?;
        let flow = &mut self.http_requests[index];
        if flow.client != client
            || flow.generation != anchor.generation
            || now.saturating_duration_since(flow.seen) > HTTP_FLOW_IDLE
            || flow.response_reported
        {
            return None;
        }
        let server_sequence = anchor.server_sequence?;
        let expected = flow
            .response_next
            .get_or_insert_with(|| server_sequence.wrapping_add(1));
        if tcp.acknowledgment != flow.request_end || tcp.flags & 0x04 != 0 {
            let (event, portal) = finish_http_response(flow, 2, None);
            return Some((event, portal, None));
        }
        if tcp.sequence != *expected {
            let end = tcp.sequence.wrapping_add(payload.len() as u32);
            if !seq_after(tcp.sequence, *expected)
                && !seq_after(end, *expected)
                && tcp.flags & 0x01 == 0
            {
                return None;
            }
            let (event, portal) = finish_http_response(flow, 2, None);
            return Some((event, portal, None));
        }
        if !payload.is_empty() {
            flow.response_progress = now;
            flow.response_started.get_or_insert(now);
            flow.response_segments = flow.response_segments.saturating_add(1);
        }
        let had_headers = flow.response.headers_complete();
        flow.response.feed(payload, tcp.flags & 0x01 != 0);
        *expected = tcp.sequence.wrapping_add(payload.len() as u32);
        if !had_headers
            && flow.response.headers_complete()
            && r2k_core::httpup::portal_location(&flow.host, flow.response.headers()).is_some()
        {
            let portal = flow
                .response_started
                .is_some_and(|started| {
                    flow.rtt > Duration::ZERO
                        && started.saturating_duration_since(flow.seen) < flow.rtt / 2
                })
                .then(|| HttpPortalEvent {
                    key: key.wire_key(),
                    answered: false,
                    host: flow.host.clone(),
                });
            let redirect = portal.as_ref().and_then(|_| {
                (flow.response_segments == 1)
                    .then(|| r2k_core::httpup::redirect_https(&flow.host, &flow.target))
                    .flatten()
            });
            let (event, _) = finish_http_response(flow, 3, Some(flow.response.body_bytes()));
            if portal.is_some() {
                self.http80.injections = self.http80.injections.saturating_add(1);
            }
            return Some((event, portal, redirect));
        }
        if flow.response.fixed_body_remaining().is_some() {
            flow.body_start = Some(expected.wrapping_sub(flow.response.body_bytes() as u32));
        }
        if flow.response.is_invalid() {
            let (event, portal) = finish_http_response(flow, 2, None);
            Some((event, portal, None))
        } else if flow.response.is_complete() {
            let event = finish_http_response(flow, 1, None);
            flow.ready_for_next = tcp.flags & 0x05 == 0;
            Some((event.0, event.1, None))
        } else {
            None
        }
    }

    fn observe_http_ack(
        &mut self,
        key: TcpFlowKey,
        generation: u64,
        acknowledgment: u32,
        now: Instant,
    ) {
        let Some(flow) = self.http_requests.iter_mut().find(|flow| {
            flow.key == key && flow.generation == generation && !flow.response_reported
        }) else {
            return;
        };
        if seq_after(acknowledgment, flow.acked_response) {
            flow.acked_response = acknowledgment;
            flow.response_progress = now;
        }
    }

    fn observe_http_client_close(
        &mut self,
        key: TcpFlowKey,
        anchor: SynAnchor,
        client: Endpoint,
        tcp: &TcpSegmentView,
        now: Instant,
    ) -> Option<HttpResponseEvent> {
        let flow = self.http_requests.iter_mut().find(|flow| {
            flow.key == key
                && flow.client == client
                && flow.generation == anchor.generation
                && !flow.response_reported
                && now.saturating_duration_since(flow.seen) <= HTTP_FLOW_IDLE
        })?;
        let remaining = flow.response.fixed_body_remaining()?;
        if remaining == 0 {
            return None;
        }
        // C `cut_pending`: обрыв фиксируется, только пока клиент не
        // подтвердил весь `Content-Length` (body_end > delivered).
        let body_start = flow.body_start?;
        let body_end =
            body_start.wrapping_add(flow.response.body_bytes().saturating_add(remaining) as u32);
        let response_next = flow.response_next.unwrap_or(body_start);
        let delivered = if seq_after(flow.acked_response, response_next) {
            flow.acked_response
        } else {
            response_next
        };
        if !seq_after(body_end, delivered) {
            return None;
        }
        let mut body_bytes = flow.response.body_bytes();
        if seq_after(tcp.acknowledgment, body_start) {
            body_bytes = body_bytes.max(u64::from(tcp.acknowledgment.wrapping_sub(body_start)));
        }
        Some(finish_http_response(flow, 4, Some(body_bytes)).0)
    }

    fn syn_index(&self, key: &TcpFlowKey) -> Option<usize> {
        self.syns.iter().position(|anchor| anchor.key == *key)
    }

    fn slot_index(&self, key: &TcpFlowKey) -> Option<usize> {
        self.slots.iter().position(|slot| slot.key == *key)
    }

    fn remove_slot(&mut self, index: usize) -> Vec<u32> {
        let packets = self.slots.remove(index).packets;
        self.stats.pending = self.stats.pending.saturating_sub(packets.len());
        self.stats.released = self.stats.released.saturating_add(packets.len() as u64);
        self.release_held_packets(packets)
    }

    fn release_held_packets(&mut self, packets: Vec<HeldPacket>) -> Vec<u32> {
        let mut released = Vec::new();
        for packet in packets {
            if packet.owned {
                self.owned_releases.push(packet.bytes);
            } else {
                released.push(packet.id);
            }
        }
        released
    }
}

fn parse_tcp(
    packet: &[u8],
) -> Option<(PacketView, TcpSegmentView, TcpFlowKey, Endpoint, Endpoint)> {
    let view = PacketView::parse(packet)?;
    if view.protocol != 6 || view.fragment & 0x3fff != 0 {
        return None;
    }
    let tcp = view.tcp_segment(packet)?;
    let key = TcpFlowKey::from_packet(packet)?;
    let source = Endpoint {
        address: view.src,
        port: tcp.source_port,
    };
    let destination = Endpoint {
        address: view.dst,
        port: tcp.destination_port,
    };
    Some((view, tcp, key, source, destination))
}

fn finish_http_response(
    flow: &mut HttpRequestFlow,
    code: u8,
    body_bytes: Option<u64>,
) -> (HttpResponseEvent, Option<HttpPortalEvent>) {
    flow.response_reported = true;
    flow.ready_for_next = false;
    let applied = flow.applied.as_ref();
    let event = HttpResponseEvent {
        key: flow.key.wire_key(),
        code,
        host: flow.host.clone(),
        execution_id: applied.map_or(0, |event| event.execution_id),
        plan_id: applied.map_or([0; 16], |event| event.plan_id),
        trial_id: applied.map_or([0; 16], |event| event.trial_id),
        request_ms: flow.request_ms,
        path: flow.path.clone(),
        binding: applied.map_or(
            BindingContext {
                generation: 0,
                kind: 0,
                family: 0,
                shape: 0,
                temporary: false,
                epoch: [0; 16],
            },
            |event| event.binding,
        ),
        status: flow.response.status(),
        body_bytes: body_bytes.unwrap_or_else(|| flow.response.body_bytes()),
        request_no: flow.request_no,
    };
    (event, None)
}

fn monotonic_ms() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return 0;
    }
    u64::try_from(time.tv_sec)
        .unwrap_or_default()
        .saturating_mul(1000)
        .saturating_add(u64::try_from(time.tv_nsec).unwrap_or_default() / 1_000_000)
}

fn seq_after(left: u32, right: u32) -> bool {
    left.wrapping_sub(right) as i32 > 0
}

fn tls_record_head(payload: &[u8]) -> bool {
    if payload.first() != Some(&22) {
        return false;
    }
    if payload.len() >= 2 && payload[1] != 3 {
        return false;
    }
    if payload.len() >= 6 && payload[5] != 1 {
        return false;
    }
    true
}

fn incomplete_tls_head(payload: &[u8]) -> bool {
    if !tls_record_head(payload) {
        return false;
    }
    payload.len() < 5
        || payload.len() < 5 + usize::from(u16::from_be_bytes([payload[3], payload[4]]))
}

fn incomplete_http_head(payload: &[u8]) -> bool {
    payload.first().is_some_and(u8::is_ascii_uppercase)
        && r2k_core::httpup::request_host_range(payload).is_none()
}

fn synthetic_packet(head: &[u8], hello: &[u8]) -> Option<Vec<u8>> {
    let view = PacketView::parse(head)?;
    let tcp = view.tcp_segment(head)?;
    let total_len = tcp.payload.start.checked_add(hello.len())?;
    if total_len > u16::MAX as usize {
        return None;
    }
    let mut packet = head.get(..tcp.payload.start)?.to_vec();
    packet.extend_from_slice(hello);
    match view.family {
        4 => packet
            .get_mut(2..4)?
            .copy_from_slice(&(total_len as u16).to_be_bytes()),
        6 => {
            let payload_len = total_len.checked_sub(40)?;
            packet
                .get_mut(4..6)?
                .copy_from_slice(&u16::try_from(payload_len).ok()?.to_be_bytes());
        }
        _ => return None,
    }
    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::{
        Endpoint, HOLD_WAIT, HTTP_FLOW_CAPACITY, HoldOptions, HoldOutcome, HoldTable,
        HttpRequestObservation,
    };
    use crate::capture::TcpFlowKey;
    use r2k_core::addr::Address;
    use std::time::{Duration, Instant};

    fn tcp_packet(sequence: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 40 + payload.len()];
        packet[0] = 0x45;
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 20]);
        packet[20..22].copy_from_slice(&50000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[24..28].copy_from_slice(&sequence.to_be_bytes());
        packet[28..32].copy_from_slice(&3000_u32.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = flags;
        packet[40..].copy_from_slice(payload);
        packet
    }

    fn hello() -> Vec<u8> {
        vec![22, 3, 3, 0, 4, 1, 0, 0, 0]
    }

    #[test]
    fn http_flow_table_evicts_oldest_at_128_like_c() {
        const REQUEST: &[u8] = b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n";
        let mut table = HoldTable::default();
        let base = Instant::now();
        let client = Address::parse("192.0.2.10").unwrap();
        let mut keys = Vec::new();
        for index in 0..HTTP_FLOW_CAPACITY as u16 {
            let mut packet = tcp_packet(1000, 0x18, REQUEST);
            packet[22..24].copy_from_slice(&(50_000_u16 + index).to_be_bytes());
            let key = TcpFlowKey::from_packet(&packet).unwrap();
            keys.push(key);
            table.remember_http_request(
                key,
                Endpoint {
                    address: client,
                    port: 50_000 + index,
                },
                1,
                HttpRequestObservation {
                    sequence: 1000,
                    request: REQUEST,
                    host: b"h".to_vec(),
                    target: b"/x".to_vec(),
                    response_anchor: None,
                    rtt: Duration::ZERO,
                    now: base + Duration::from_millis(u64::from(index)),
                },
            );
        }
        assert_eq!(table.http_requests.len(), HTTP_FLOW_CAPACITY);

        let mut packet = tcp_packet(1000, 0x18, REQUEST);
        packet[22..24].copy_from_slice(&60_000_u16.to_be_bytes());
        let fresh = TcpFlowKey::from_packet(&packet).unwrap();
        table.remember_http_request(
            fresh,
            Endpoint {
                address: client,
                port: 60_000,
            },
            1,
            HttpRequestObservation {
                sequence: 1000,
                request: REQUEST,
                host: b"h".to_vec(),
                target: b"/x".to_vec(),
                response_anchor: None,
                rtt: Duration::ZERO,
                now: base + Duration::from_secs(1),
            },
        );
        assert_eq!(table.http_requests.len(), HTTP_FLOW_CAPACITY);
        assert!(!table.http_requests.iter().any(|flow| flow.key == keys[0]));
        assert!(table.http_requests.iter().any(|flow| flow.key == fresh));
        let stats = table.r2o_http80_stats();
        assert_eq!(stats.requests as usize, HTTP_FLOW_CAPACITY + 1);
        assert_eq!(stats.evicted, 1);
        if let Ok(path) = std::env::var("R2O_HTTP80_MAKE_DIFF_OUTPUT") {
            std::fs::write(
                path,
                format!(
                    "make evicted={} requests={}\n",
                    stats.evicted, stats.requests
                ),
            )
            .unwrap();
        }
    }

    #[test]
    fn http80_stats_count_untracked_and_swap_failures_like_c() {
        let start = Instant::now();
        let options = HoldOptions {
            observe_http: true,
            ..HoldOptions::default()
        };
        let mut table = HoldTable::default();
        // Нагрузка к :80 без SYN — C `untracked++`.
        let mut packet = tcp_packet(5000, 0x18, b"later-data");
        packet[22..24].copy_from_slice(&80_u16.to_be_bytes());
        table.feed_observing(1, &packet, start, options);
        let stats = table.r2o_http80_stats();
        assert_eq!(stats.untracked, 1);
        assert_eq!(stats.requests, 0);

        table.note_http_swap_failed();
        assert_eq!(table.r2o_http80_stats().swap_failed, 1);
    }

    #[test]
    fn http80_swap_result_marks_answered_or_failed_like_c() {
        let start = Instant::now();
        let options = HoldOptions {
            observe_http: true,
            ..HoldOptions::default()
        };
        let request = b"GET /path?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let request_end = 2001 + request.len() as u32;
        let response = b"HTTP/1.1 302 Found\r\nLocation: http://lawfilter.example/blocked\r\nContent-Length: 0\r\n\r\n";

        let mut hold = d17_start(start, options, request);
        let result = hold.feed_observing(
            4,
            &http_response_packet(9001, request_end, 0x18, response),
            start + Duration::from_millis(12),
            options,
        );
        let (event, mut portal) = match result.outcome {
            HoldOutcome::HttpResponse { event, portal, .. } => (event, portal),
            _ => panic!("HTTPS injection must be recognized"),
        };
        assert!(hold.r2o_apply_http_swap_result(Some(&event), portal.as_mut(), true));
        let stats = hold.r2o_http80_stats();
        assert_eq!(stats.answered, 1);
        assert_eq!(stats.swap_failed, 0);
        let late = hold.feed_observing(
            5,
            &http_response_packet(9001 + response.len() as u32, request_end, 0x18, b"late"),
            start + Duration::from_millis(13),
            options,
        );
        assert!(matches!(late.outcome, HoldOutcome::Drop));

        let mut fail = d17_start(start, options, request);
        let result = fail.feed_observing(
            4,
            &http_response_packet(9001, request_end, 0x18, response),
            start + Duration::from_millis(12),
            options,
        );
        let (event, mut portal) = match result.outcome {
            HoldOutcome::HttpResponse { event, portal, .. } => (event, portal),
            _ => panic!("HTTPS injection must be recognized"),
        };
        assert!(!fail.r2o_apply_http_swap_result(Some(&event), portal.as_mut(), false));
        let stats = fail.r2o_http80_stats();
        assert_eq!(stats.answered, 0);
        assert_eq!(stats.swap_failed, 1);
        let late = fail.feed_observing(
            5,
            &http_response_packet(9001 + response.len() as u32, request_end, 0x18, b"late"),
            start + Duration::from_millis(13),
            options,
        );
        assert!(!matches!(late.outcome, HoldOutcome::Drop));
    }

    fn client_hello(host: &[u8]) -> Vec<u8> {
        let mut server_name = Vec::new();
        server_name.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        server_name.push(0);
        server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
        server_name.extend_from_slice(host);

        let mut extensions = vec![0, 0];
        extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&server_name);

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

    fn http_packet(sequence: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = tcp_packet(sequence, flags, payload);
        packet[22..24].copy_from_slice(&80_u16.to_be_bytes());
        packet
    }

    fn http_response_packet(
        sequence: u32,
        acknowledgment: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0; 40 + payload.len()];
        packet[0] = 0x45;
        let total_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[198, 51, 100, 20]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 10]);
        packet[20..22].copy_from_slice(&80_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&50000_u16.to_be_bytes());
        packet[24..28].copy_from_slice(&sequence.to_be_bytes());
        packet[28..32].copy_from_slice(&acknowledgment.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = flags;
        packet[40..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn hold_parse_tcp_matches_c_fields() {
        use super::parse_tcp;
        let packet = tcp_packet(1234, 0x18, b"hello");
        let (view, tcp, _key, source, destination) = parse_tcp(&packet).unwrap();
        assert_eq!(view.protocol, 6);
        assert_eq!(view.total_len, packet.len());
        assert_eq!(tcp.payload.start, 40);
        assert_eq!(tcp.payload.len(), 5);
        assert_eq!(tcp.sequence, 1234);
        assert_eq!(tcp.acknowledgment, 3000);
        assert_eq!(tcp.flags, 0x18);
        assert_eq!(source.port, 50000);
        assert_eq!(destination.port, 443);
        // C отвергает IPv4-фрагменты (`fragment & 0x3fff`).
        let mut fragment = packet.clone();
        fragment[6] = 0x20;
        assert!(parse_tcp(&fragment).is_none());
    }

    #[test]
    fn split_hello_returns_synthetic_head_and_all_original_ids() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let syn = tcp_packet(1000, 0x02, &[]);
        assert_eq!(
            hold.feed(1, &syn, now, 0, true, false).outcome,
            HoldOutcome::Pass
        );
        let hello = hello();
        let first = tcp_packet(1001, 0x18, &hello[..5]);
        assert_eq!(
            hold.feed(2, &first, now, 0, true, false).outcome,
            HoldOutcome::Waiting
        );
        let second = tcp_packet(1006, 0x18, &hello[5..]);
        let result = hold.feed(3, &second, now, 0, true, false);
        let HoldOutcome::Ready { ids, packet } = result.outcome else {
            panic!("split ClientHello should be assembled");
        };
        assert!(result.released.is_empty());
        assert_eq!(ids, [2, 3]);
        assert_eq!(&packet[40..], hello);
        assert_eq!(
            u16::from_be_bytes([packet[2], packet[3]]) as usize,
            packet.len()
        );
        assert_eq!(hold.r2o_capture_stats().completed, 1);
        assert_eq!(hold.r2o_capture_stats().tls_completed, 1);
        let stats = hold.r2o_hold_stats();
        assert_eq!(stats.started, 1);
        assert_eq!(stats.ready, 1);
        assert_eq!(stats.joined, 1);
        assert_eq!(stats.pending, 0);
    }

    #[test]
    fn hold_get_stats_returns_counter_snapshot_like_c() {
        // C `d2k_hold_get_stats` копирует структуру: снимок не меняется
        // последующими операциями таблицы.
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let before = hold.r2o_hold_stats();
        assert_eq!(before.started, 0);
        assert_eq!(before.pending, 0);

        let syn = tcp_packet(1000, 0x02, &[]);
        assert_eq!(
            hold.feed(1, &syn, now, 0, true, false).outcome,
            HoldOutcome::Pass
        );
        let hello = hello();
        let first = tcp_packet(1001, 0x18, &hello[..5]);
        assert_eq!(
            hold.feed(2, &first, now, 0, true, false).outcome,
            HoldOutcome::Waiting
        );
        let second = tcp_packet(1006, 0x18, &hello[5..]);
        assert!(matches!(
            hold.feed(3, &second, now, 0, true, false).outcome,
            HoldOutcome::Ready { .. }
        ));

        let after = hold.r2o_hold_stats();
        assert_eq!(after.started, 1);
        assert_eq!(after.ready, 1);
        assert_eq!(after.joined, 1);
        assert_eq!(after.pending, 0);
        // Снимок до операций не изменился.
        assert_eq!(before.started, 0);
        assert_eq!(before.ready, 0);
        assert_eq!(before.pending, 0);
    }

    #[test]
    fn повреждённый_tcp_поток_отпускает_накопленные_пакеты() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let syn = tcp_packet(1000, 0x02, &[]);
        assert_eq!(
            hold.feed(1, &syn, now, 0, true, false).outcome,
            HoldOutcome::Pass
        );
        let hello = hello();
        let first = tcp_packet(1001, 0x18, &hello[..5]);
        assert_eq!(
            hold.feed(2, &first, now, 0, true, false).outcome,
            HoldOutcome::Waiting
        );

        assert_eq!(hold.r2o_release_damaged_flow(&first), vec![2]);
        let tail = tcp_packet(1006, 0x18, &hello[5..]);
        assert_eq!(
            hold.feed_observing(3, &tail, now, HoldOptions::default(),)
                .outcome,
            HoldOutcome::Pass
        );
    }

    #[test]
    fn passive_client_hello_observation_never_holds_original_packets() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let syn = tcp_packet(1000, 0x02, &[]);
        assert_eq!(
            hold.feed_observing(
                1,
                &syn,
                now,
                HoldOptions {
                    observe_tls: true,
                    ..HoldOptions::default()
                },
            )
            .outcome,
            HoldOutcome::Pass
        );

        let hello = client_hello(b"example.test");
        let split = 24;
        assert_eq!(
            hold.feed_observing(
                2,
                &tcp_packet(1001, 0x18, &hello[..split]),
                now,
                HoldOptions {
                    observe_tls: true,
                    ..HoldOptions::default()
                }
            )
            .outcome,
            HoldOutcome::Pass
        );
        let result = hold.feed_observing(
            3,
            &tcp_packet(1001 + split as u32, 0x18, &hello[split..]),
            now,
            HoldOptions {
                observe_tls: true,
                ..HoldOptions::default()
            },
        );
        let HoldOutcome::Observed { hello: observed } = result.outcome else {
            panic!("complete ClientHello should be observed without holding its packets");
        };
        assert!(result.released.is_empty());
        assert_eq!(observed.host.as_deref(), Some(b"example.test".as_slice()));
        assert_eq!(
            hold.feed_observing(
                4,
                &tcp_packet(1001 + split as u32, 0x18, &hello[split..]),
                now,
                HoldOptions {
                    observe_tls: true,
                    ..HoldOptions::default()
                },
            )
            .outcome,
            HoldOutcome::Pass,
            "retransmitted handshake must not emit a duplicate observation"
        );
    }

    #[test]
    fn passive_http_request_observation_never_holds_original_packets() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let syn = http_packet(1000, 0x02, &[]);
        assert_eq!(
            hold.feed_observing(
                1,
                &syn,
                now,
                HoldOptions {
                    observe_http: true,
                    ..HoldOptions::default()
                },
            )
            .outcome,
            HoldOutcome::Pass
        );

        let request = b"GET /path HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n";
        let split = 17;
        assert_eq!(
            hold.feed_observing(
                2,
                &http_packet(1001, 0x18, &request[..split]),
                now,
                HoldOptions {
                    observe_http: true,
                    ..HoldOptions::default()
                },
            )
            .outcome,
            HoldOutcome::Pass
        );
        let result = hold.feed_observing(
            3,
            &http_packet(1001 + split as u32, 0x18, &request[split..]),
            now,
            HoldOptions {
                observe_http: true,
                ..HoldOptions::default()
            },
        );
        let HoldOutcome::Observed { hello } = result.outcome else {
            panic!("complete HTTP request should be observed without holding its packets");
        };
        assert!(result.released.is_empty());
        assert_eq!(hello.host.as_deref(), Some(b"example.test".as_slice()));
        assert_eq!(hello.shape, r2k_core::control::SHAPE_HTTP);
        assert_eq!(hold.r2o_capture_stats().tls_completed, 0);
        assert_eq!(
            hold.feed_observing(
                4,
                &http_packet(1001 + split as u32, 0x18, &request[split..]),
                now,
                HoldOptions {
                    observe_http: true,
                    ..HoldOptions::default()
                },
            )
            .outcome,
            HoldOutcome::Pass,
            "retransmitted request must not emit a duplicate observation"
        );
    }

    #[test]
    fn r2o_http_keepalive_собирает_разделённый_запрос_после_тела_post() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let options = HoldOptions {
            allow_http: true,
            ..HoldOptions::default()
        };
        assert_eq!(
            hold.feed_observing(1, &http_packet(1000, 0x02, &[]), now, options)
                .outcome,
            HoldOutcome::Pass,
        );
        let first = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        assert_eq!(
            hold.feed_observing(2, &http_packet(1001, 0x18, first), now, options)
                .outcome,
            HoldOutcome::Pass,
        );
        let post = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 70000\r\n\r\n";
        let post_sequence = 1001 + first.len() as u32;
        assert_eq!(
            hold.feed_observing(3, &http_packet(post_sequence, 0x18, post), now, options)
                .outcome,
            HoldOutcome::Pass,
        );
        let body_start = post_sequence + post.len() as u32;
        let body = vec![b'x'; 70000];
        for (index, chunk) in body.chunks(1400).enumerate() {
            assert_eq!(
                hold.feed_observing(
                    4 + index as u32,
                    &http_packet(body_start + (index * 1400) as u32, 0x18, chunk),
                    now,
                    options,
                )
                .outcome,
                HoldOutcome::Pass,
            );
        }

        let request = b"GET /after-upload HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let sequence = body_start + 70000;
        let split = 19;
        assert_eq!(
            hold.feed_observing(
                60,
                &http_packet(sequence, 0x18, &request[..split]),
                now,
                options,
            )
            .outcome,
            HoldOutcome::Waiting,
        );
        let result = hold.feed_observing(
            61,
            &http_packet(sequence + split as u32, 0x18, &request[split..]),
            now,
            options,
        );
        let HoldOutcome::Ready { ids, packet } = result.outcome else {
            panic!("разделённый keep-alive-запрос после тела должен быть собран");
        };
        assert_eq!(ids, [60, 61]);
        let view = r2k_core::packet::PacketView::parse(&packet).unwrap();
        let tcp = view.tcp_segment(&packet).unwrap();
        assert_eq!(tcp.sequence, sequence);
        assert_eq!(&packet[tcp.payload], request);
    }

    #[test]
    fn observed_http_response_emits_body_and_request_context() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let options = HoldOptions {
            observe_http: true,
            ..HoldOptions::default()
        };
        let request = b"GET /path HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n";
        let _ = hold.feed_observing(1, &http_packet(1000, 0x02, &[]), now, options);
        let server_syn_ack = http_response_packet(9000, 1001, 0x12, &[]);
        let _ = hold.feed_observing(2, &server_syn_ack, now, options);
        let request_packet = http_packet(1001, 0x18, request);
        let _ = hold.feed_observing(3, &request_packet, now, options);

        let request_end = 1001 + request.len() as u32;
        let applied = r2k_core::control::AppliedEvent {
            key: super::TcpFlowKey::from_packet(&request_packet)
                .unwrap()
                .wire_key(),
            plan_id: [0x11; 16],
            trial_id: [0x22; 16],
            execution_id: 7,
            binding: r2k_core::control::BindingContext {
                generation: 9,
                kind: 1,
                family: 4,
                shape: r2k_core::control::SHAPE_HTTP,
                temporary: true,
                epoch: [0x33; 16],
            },
        };
        hold.note_http_execution(1001, &applied);

        let ordinary = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd";
        let split = ordinary.len() - 2;
        assert_eq!(
            hold.feed_observing(
                4,
                &http_response_packet(9001, request_end, 0x18, &ordinary[..split]),
                now,
                options,
            )
            .outcome,
            HoldOutcome::Pass,
            "a partial response must not be reported as complete"
        );
        let result = hold.feed_observing(
            5,
            &http_response_packet(9001 + split as u32, request_end, 0x18, &ordinary[split..]),
            now,
            options,
        );
        let HoldOutcome::HttpResponse {
            event,
            portal: None,
            redirect: None,
        } = result.outcome
        else {
            panic!("complete ordinary response should emit HTTP_RESPONSE");
        };
        assert_eq!(event.code, 1);
        assert_eq!(event.status, 200);
        assert_eq!(event.body_bytes, 4);
        assert_eq!(event.host, b"example.test");
        assert_eq!(event.path, b"/path");
        assert_eq!(event.execution_id, 7);
        assert_eq!(event.plan_id, [0x11; 16]);
        assert_eq!(event.trial_id, [0x22; 16]);
        assert_eq!(event.binding.generation, 9);

        let portal = b"HTTP/1.1 302 Found\r\nLocation: http://lawfilter.example/blocked\r\nContent-Length: 0\r\n\r\n";
        let portal_split = 29;
        let mut portal_hold = HoldTable::default();
        let _ = portal_hold.feed_observing(5, &http_packet(2000, 0x02, &[]), now, options);
        let portal_syn_ack = http_response_packet(9000, 2001, 0x12, &[]);
        let _ = portal_hold.feed_observing(
            6,
            &portal_syn_ack,
            now + Duration::from_millis(10),
            options,
        );
        let portal_request =
            b"GET /path HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n";
        let _ = portal_hold.feed_observing(
            7,
            &http_packet(2001, 0x18, portal_request),
            now + Duration::from_millis(11),
            options,
        );
        let portal_ack = 2001 + portal_request.len() as u32;
        assert_eq!(
            portal_hold
                .feed_observing(
                    8,
                    &http_response_packet(9001, portal_ack, 0x18, &portal[..portal_split]),
                    now + Duration::from_millis(12),
                    options,
                )
                .outcome,
            HoldOutcome::Pass,
            "a partial response header must remain unclassified"
        );
        let result = portal_hold.feed_observing(
            9,
            &http_response_packet(
                9001 + portal_split as u32,
                portal_ack,
                0x18,
                &portal[portal_split..],
            ),
            now + Duration::from_millis(13),
            options,
        );
        let HoldOutcome::HttpResponse {
            event,
            portal: Some(portal_event),
            redirect: None,
        } = result.outcome
        else {
            panic!("recognized portal response should produce a response and portal event");
        };
        assert!(result.released.is_empty());
        assert_eq!(event.code, 3);
        assert_eq!(event.host, b"example.test");
        assert_eq!(event.path, b"/path");
        assert_eq!(portal_event.host, b"example.test");
        assert!(!portal_event.answered);
        assert_eq!(event.key[37], 6);
    }

    #[test]
    fn late_portal_response_is_not_reported_as_injected() {
        let start = Instant::now();
        let mut hold = HoldTable::default();
        let options = HoldOptions {
            observe_http: true,
            ..HoldOptions::default()
        };
        let _ = hold.feed_observing(1, &http_packet(2000, 0x02, &[]), start, options);
        let _ = hold.feed_observing(
            2,
            &http_response_packet(9000, 2001, 0x12, &[]),
            start + Duration::from_millis(10),
            options,
        );
        let request = b"GET /path HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let request_at = start + Duration::from_millis(11);
        let _ = hold.feed_observing(3, &http_packet(2001, 0x18, request), request_at, options);

        let portal = b"HTTP/1.1 302 Found\r\nLocation: http://lawfilter.example/blocked\r\nContent-Length: 0\r\n\r\n";
        let result = hold.feed_observing(
            4,
            &http_response_packet(9001, 2001 + request.len() as u32, 0x18, portal),
            start + Duration::from_millis(17),
            options,
        );

        let HoldOutcome::HttpResponse { event, portal, .. } = result.outcome else {
            panic!("портальный ответ должен быть классифицирован как HTTP_RESPONSE");
        };
        assert_eq!(event.code, 3);
        assert!(portal.is_none(), "поздний ответ не является внедрённым");
    }

    #[test]
    fn fast_single_segment_portal_offers_a_https_redirect() {
        let start = Instant::now();
        let mut hold = HoldTable::default();
        let options = HoldOptions {
            observe_http: true,
            ..HoldOptions::default()
        };
        let request = b"GET /path?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let request_end = 2001 + request.len() as u32;
        let _ = hold.feed_observing(1, &http_packet(2000, 0x02, &[]), start, options);
        let _ = hold.feed_observing(
            2,
            &http_response_packet(9000, 2001, 0x12, &[]),
            start + Duration::from_millis(10),
            options,
        );
        let _ = hold.feed_observing(
            3,
            &http_packet(2001, 0x18, request),
            start + Duration::from_millis(11),
            options,
        );
        let response = b"HTTP/1.1 302 Found\r\nLocation: http://lawfilter.example/blocked\r\nContent-Length: 0\r\n\r\n";
        let result = hold.feed_observing(
            4,
            &http_response_packet(9001, request_end, 0x18, response),
            start + Duration::from_millis(12),
            options,
        );

        let HoldOutcome::HttpResponse {
            event,
            portal: Some(_),
            redirect: Some(redirect),
        } = result.outcome
        else {
            panic!("быстрый односегментный портал должен предложить 307");
        };
        assert_eq!(event.code, 3);
        assert_eq!(
            redirect,
            r2k_core::httpup::redirect_https(b"example.test", b"/path?q=1").unwrap()
        );
        assert!(hold.mark_http_response_answered(&event.key, event.request_no));
        assert_eq!(
            hold.feed_observing(
                5,
                &http_response_packet(
                    9001 + response.len() as u32,
                    request_end,
                    0x18,
                    b"late server bytes",
                ),
                start + Duration::from_millis(13),
                options,
            )
            .outcome,
            HoldOutcome::Drop,
            "ответы сервера после успешного 307 должны отсекаться"
        );
    }

    #[test]
    fn server_fin_completes_close_delimited_response_and_client_fin_reports_cut() {
        let now = Instant::now();
        let options = HoldOptions {
            observe_http: true,
            ..HoldOptions::default()
        };
        let request = b"GET /path HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let request_end = 1001 + request.len() as u32;

        let mut close_delimited = HoldTable::default();
        let _ = close_delimited.feed_observing(1, &http_packet(1000, 0x02, &[]), now, options);
        let _ = close_delimited.feed_observing(
            2,
            &http_response_packet(5000, 1001, 0x12, &[]),
            now,
            options,
        );
        let _ = close_delimited.feed_observing(3, &http_packet(1001, 0x18, request), now, options);
        let close_body = b"HTTP/1.1 200 OK\r\n\r\nhello";
        let result = close_delimited.feed_observing(
            4,
            &http_response_packet(5001, request_end, 0x19, close_body),
            now,
            options,
        );
        let HoldOutcome::HttpResponse {
            event,
            portal: None,
            redirect: None,
        } = result.outcome
        else {
            panic!("server FIN should complete a close-delimited body");
        };
        assert_eq!(event.code, 1);
        assert_eq!(event.body_bytes, 5);

        let mut cut = HoldTable::default();
        let _ = cut.feed_observing(5, &http_packet(1000, 0x02, &[]), now, options);
        let _ = cut.feed_observing(
            6,
            &http_response_packet(5000, 1001, 0x12, &[]),
            now,
            options,
        );
        let _ = cut.feed_observing(7, &http_packet(1001, 0x18, request), now, options);
        let response_head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab";
        assert_eq!(
            cut.feed_observing(
                8,
                &http_response_packet(5001, request_end, 0x18, response_head),
                now,
                options,
            )
            .outcome,
            HoldOutcome::Pass
        );
        let body_start = 5001 + (response_head.len() - 2) as u32;
        let mut client_fin = http_packet(request_end, 0x11, &[]);
        client_fin[28..32].copy_from_slice(&(body_start + 2).to_be_bytes());
        let result = cut.feed_observing(9, &client_fin, now, options);
        let HoldOutcome::HttpResponse {
            event,
            portal: None,
            redirect: None,
        } = result.outcome
        else {
            panic!("client FIN before Content-Length should report an interrupted response");
        };
        assert_eq!(event.code, 4);
        assert_eq!(event.body_bytes, 2);
        assert_eq!(event.status, 200);
    }

    #[test]
    fn keep_alive_request_increments_response_request_number() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let options = HoldOptions {
            observe_http: true,
            ..HoldOptions::default()
        };
        let request = b"GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let request_end = 1001 + request.len() as u32;
        let _ = hold.feed_observing(1, &http_packet(1000, 0x02, &[]), now, options);
        let _ = hold.feed_observing(
            2,
            &http_response_packet(5000, 1001, 0x12, &[]),
            now,
            options,
        );
        let _ = hold.feed_observing(3, &http_packet(1001, 0x18, request), now, options);
        let first_reply = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let first = hold.feed_observing(
            4,
            &http_response_packet(5001, request_end, 0x18, first_reply),
            now,
            options,
        );
        let HoldOutcome::HttpResponse { event, .. } = first.outcome else {
            panic!("first response should be reported");
        };
        assert_eq!(event.request_no, 1);

        let second_request = b"GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let second_request_end = request_end + second_request.len() as u32;
        assert!(matches!(
            hold.feed_observing(
                5,
                &http_packet(request_end, 0x18, second_request),
                now,
                options,
            )
            .outcome,
            HoldOutcome::Observed { .. }
        ));
        let second_reply = b"HTTP/1.1 204 No Content\r\n\r\n";
        let second = hold.feed_observing(
            6,
            &http_response_packet(
                5001 + first_reply.len() as u32,
                second_request_end,
                0x18,
                second_reply,
            ),
            now,
            options,
        );
        let HoldOutcome::HttpResponse { event, .. } = second.outcome else {
            panic!("second response should be reported");
        };
        assert_eq!(event.request_no, 2);
        assert_eq!(event.path, b"/two");
    }

    #[test]
    fn incomplete_fixed_length_response_is_reported_after_quiet_period() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let options = HoldOptions {
            observe_http: true,
            ..HoldOptions::default()
        };
        let request = b"GET /path HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let request_end = 1001 + request.len() as u32;
        let _ = hold.feed_observing(1, &http_packet(1000, 0x02, &[]), now, options);
        let _ = hold.feed_observing(
            2,
            &http_response_packet(5000, 1001, 0x12, &[]),
            now,
            options,
        );
        let _ = hold.feed_observing(3, &http_packet(1001, 0x18, request), now, options);
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab";
        assert_eq!(
            hold.feed_observing(
                4,
                &http_response_packet(5001, request_end, 0x18, partial),
                now,
                options,
            )
            .outcome,
            HoldOutcome::Pass
        );
        assert!(
            hold.sweep_http_responses(now + Duration::from_millis(2_000))
                .is_empty()
        );
        let events = hold.sweep_http_responses(now + Duration::from_millis(2_001));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].code, 4);
        assert_eq!(events[0].status, 200);
        assert_eq!(events[0].body_bytes, 2);
        assert!(
            hold.sweep_http_responses(now + Duration::from_secs(10))
                .is_empty()
        );
    }

    #[test]
    fn out_of_order_tail_uses_syn_anchor_and_real_head_header() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let _ = hold.feed(1, &tcp_packet(9000, 0x02, &[]), now, 0, true, false);
        let hello = hello();
        assert_eq!(
            hold.feed(2, &tcp_packet(9006, 0x18, &hello[5..]), now, 0, true, false)
                .outcome,
            HoldOutcome::Waiting
        );
        let result = hold.feed(3, &tcp_packet(9001, 0x18, &hello[..5]), now, 0, true, false);
        let HoldOutcome::Ready { ids, packet } = result.outcome else {
            panic!("out-of-order ClientHello should be assembled");
        };
        assert_eq!(ids, [2, 3]);
        assert_eq!(&packet[40..], hello);
        assert_eq!(u32::from_be_bytes(packet[24..28].try_into().unwrap()), 9001);
    }

    #[test]
    fn owned_tls_timeout_replays_saved_bytes_without_accepting_queue_ids() {
        let now = Instant::now();
        let options = HoldOptions {
            allow_tls: true,
            own_packets: true,
            ..HoldOptions::default()
        };
        let mut hold = HoldTable::default();
        let _ = hold.feed(1, &tcp_packet(1000, 0x02, &[]), now, 0, true, false);
        let partial = tcp_packet(1001, 0x18, &hello()[..5]);

        let result = hold.feed_observing(2, &partial, now, options);
        assert_eq!(result.outcome, HoldOutcome::OwnedWaiting);
        assert!(result.released.is_empty());
        assert!(hold.r2o_take_owned_releases().is_empty());

        assert!(hold.flush(now + HOLD_WAIT, 0, false).is_empty());
        assert_eq!(hold.r2o_take_owned_releases(), [partial]);
    }

    #[test]
    fn owned_tls_ready_batch_returns_originals_in_stream_order() {
        let now = Instant::now();
        let options = HoldOptions {
            allow_tls: true,
            own_packets: true,
            ..HoldOptions::default()
        };
        let hello = hello();
        let first = tcp_packet(2001, 0x18, &hello[..5]);
        let second = tcp_packet(2006, 0x18, &hello[5..]);
        let mut hold = HoldTable::default();
        let _ = hold.feed(1, &tcp_packet(2000, 0x02, &[]), now, 0, true, false);

        assert_eq!(
            hold.feed_observing(2, &first, now, options).outcome,
            HoldOutcome::OwnedWaiting
        );
        let result = hold.feed_observing(3, &second, now, options);
        let HoldOutcome::OwnedReady {
            ids,
            packet,
            originals,
        } = result.outcome
        else {
            panic!("complete owned ClientHello should return its raw originals");
        };
        assert_eq!(ids, [2, 3]);
        assert_eq!(originals, [first, second]);
        assert_eq!(&packet[40..], hello);
        assert!(result.released.is_empty());
    }

    #[test]
    fn timeout_and_revision_change_fail_open_all_held_ids() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let _ = hold.feed(1, &tcp_packet(1000, 0x02, &[]), now, 0, true, false);
        let first = tcp_packet(1001, 0x18, &hello()[..5]);
        assert_eq!(
            hold.feed(2, &first, now, 0, true, false).outcome,
            HoldOutcome::Waiting
        );
        assert!(hold.flush(now + HOLD_WAIT, 0, false).contains(&2));

        let _ = hold.feed(3, &tcp_packet(2000, 0x02, &[]), now, 4, true, false);
        let second = tcp_packet(2001, 0x18, &hello()[..5]);
        assert_eq!(
            hold.feed(4, &second, now, 4, true, false).outcome,
            HoldOutcome::Waiting
        );
        assert!(
            hold.flush(now + Duration::from_millis(1), 5, false)
                .contains(&4)
        );
        let stats = hold.r2o_hold_stats();
        assert_eq!(stats.started, 2);
        assert_eq!(stats.released, 2);
        assert_eq!(stats.timed_out, 1);
        assert_eq!(stats.timed_out_packets, 1);
        assert_eq!(stats.plan_changed, 1);
        assert_eq!(stats.pending, 0);
    }

    #[test]
    fn timeout_diagnostic_survives_deadline_and_revision_change_together() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let _ = hold.feed(1, &tcp_packet(3000, 0x02, &[]), now, 4, true, false);
        let partial = tcp_packet(3001, 0x18, &hello()[..5]);
        assert_eq!(
            hold.feed(2, &partial, now, 4, true, false).outcome,
            HoldOutcome::Waiting
        );

        assert_eq!(hold.flush(now + HOLD_WAIT, 5, false), [2]);
        let diagnostics = hold.r2o_take_incomplete_diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].kind, super::R2oIncompleteCaptureKind::Tls);
        assert_eq!(diagnostics[0].captured_bytes, 5);
    }

    #[test]
    fn timeout_reports_unassembled_tls_record_once_per_flow() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let hello = hello();
        let _ = hold.feed(1, &tcp_packet(3000, 0x02, &[]), now, 0, true, false);
        assert_eq!(
            hold.feed(2, &tcp_packet(3001, 0x18, &hello[..5]), now, 0, true, false)
                .outcome,
            HoldOutcome::Waiting
        );

        assert_eq!(hold.flush(now + HOLD_WAIT, 0, false), [2]);
        let diagnostics = hold.r2o_take_incomplete_diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].kind, super::R2oIncompleteCaptureKind::Tls);
        assert_eq!(diagnostics[0].captured_bytes, 5);
        assert_eq!(diagnostics[0].declared_record_bytes, Some(hello.len()));
        assert!(hold.r2o_take_incomplete_diagnostics().is_empty());

        assert_eq!(
            hold.feed(
                3,
                &tcp_packet(3001, 0x18, &hello[..5]),
                now + HOLD_WAIT,
                0,
                true,
                false
            )
            .outcome,
            HoldOutcome::Pass
        );
        let _ = hold.flush(now + HOLD_WAIT * 2, 0, false);
        assert!(hold.r2o_take_incomplete_diagnostics().is_empty());
    }

    #[test]
    fn controller_probe_capture_counts_like_d2o_without_incomplete_diagnostics() {
        let now = Instant::now();
        let options = HoldOptions {
            revision: 0,
            allow_tls: true,
            ..HoldOptions::default()
        };
        let hello = client_hello(b"hetzner.com");

        let mut timed_out = HoldTable::default();
        let _ = timed_out.feed_controller_probe(1, &tcp_packet(3000, 0x02, &[]), now, options);
        assert_eq!(
            timed_out
                .feed_controller_probe(2, &tcp_packet(3001, 0x18, &hello[..5]), now, options)
                .outcome,
            HoldOutcome::Waiting
        );
        assert_eq!(timed_out.flush(now + HOLD_WAIT, 0, false), [2]);
        assert!(timed_out.r2o_take_incomplete_diagnostics().is_empty());

        let mut held = HoldTable::default();
        let _ = held.feed_controller_probe(3, &tcp_packet(4000, 0x02, &[]), now, options);
        assert_eq!(
            held.feed_controller_probe(4, &tcp_packet(4001, 0x18, &hello[..5]), now, options)
                .outcome,
            HoldOutcome::Waiting
        );
        assert!(matches!(
            held.feed_controller_probe(5, &tcp_packet(4006, 0x18, &hello[5..]), now, options)
                .outcome,
            HoldOutcome::Ready { .. }
        ));
        let stats = held.r2o_capture_stats();
        assert_eq!(
            (stats.completed, stats.rejected, stats.expired, stats.full),
            (1, 0, 0, 0)
        );
        assert_eq!(
            (
                stats.tls_completed,
                stats.tls_rejected,
                stats.tls_expired,
                stats.tls_full
            ),
            (1, 0, 0, 0)
        );

        let observed_options = HoldOptions {
            observe_tls: true,
            ..options
        };
        let mut observed = HoldTable::default();
        let _ =
            observed.feed_controller_probe(6, &tcp_packet(5000, 0x02, &[]), now, observed_options);
        assert!(matches!(
            observed
                .feed_controller_probe(7, &tcp_packet(5001, 0x18, &hello), now, observed_options)
                .outcome,
            HoldOutcome::Observed { .. }
        ));
        let observed_stats = observed.r2o_capture_stats();
        assert_eq!(observed_stats.tls_completed, 1);
        assert_eq!(observed_stats.tls_rejected, 0);
        assert_eq!(observed_stats.tls_expired, 0);
        assert_eq!(observed_stats.tls_full, 0);

        if let Some(output) = std::env::var_os("R2O_CAPTURE_PROBE_DIFF_OUTPUT") {
            let hello_hash = hello
                .iter()
                .fold(14_695_981_039_346_656_037_u64, |hash, byte| {
                    (hash ^ u64::from(*byte)).wrapping_mul(1_099_511_628_211)
                });
            let trace = format!(
                "split hello={hello_hash:016x} complete={} rejected={} expired={} full={}\nsingle hello={hello_hash:016x} complete={} rejected={} expired={} full={}\n",
                stats.tls_completed,
                stats.tls_rejected,
                stats.tls_expired,
                stats.tls_full,
                observed_stats.tls_completed,
                observed_stats.tls_rejected,
                observed_stats.tls_expired,
                observed_stats.tls_full,
            );
            std::fs::write(output, trace)
                .expect("write controller-probe capture differential trace");
        }
    }

    #[test]
    fn timeout_reports_unassembled_http_headers() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let request = b"GET /page HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let _ = hold.feed(1, &http_packet(4000, 0x02, &[]), now, 0, false, true);
        assert_eq!(
            hold.feed(
                2,
                &http_packet(4001, 0x18, &request[..8]),
                now,
                0,
                false,
                true,
            )
            .outcome,
            HoldOutcome::Waiting
        );

        assert_eq!(hold.flush(now + HOLD_WAIT, 0, false), [2]);
        let diagnostics = hold.r2o_take_incomplete_diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].kind, super::R2oIncompleteCaptureKind::Http);
        assert_eq!(diagnostics[0].captured_bytes, 8);
        assert_eq!(diagnostics[0].declared_record_bytes, None);
    }

    #[test]
    fn split_http_request_assembles_before_selecting_its_host_plan() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let request = b"GET /page HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let split = 27;
        assert_eq!(
            hold.feed(1, &http_packet(4000, 0x02, &[]), now, 0, false, true)
                .outcome,
            HoldOutcome::Pass
        );
        assert_eq!(
            hold.feed(
                2,
                &http_packet(4001, 0x18, &request[..split]),
                now,
                0,
                false,
                true,
            )
            .outcome,
            HoldOutcome::Waiting
        );
        let result = hold.feed(
            3,
            &http_packet(4001 + split as u32, 0x18, &request[split..]),
            now,
            0,
            false,
            true,
        );
        let HoldOutcome::Ready { ids, packet } = result.outcome else {
            panic!("split HTTP request should be assembled");
        };
        assert_eq!(ids, [2, 3]);
        assert_eq!(&packet[40..], request);
        assert!(r2k_core::httpup::request_host_range(&packet[40..]).is_some());
    }

    fn trace_outcome(label: &str, result: &super::FeedResult) {
        let name = match result.outcome {
            HoldOutcome::Pass => "pass",
            HoldOutcome::Waiting | HoldOutcome::OwnedWaiting => "wait",
            HoldOutcome::Ready { .. } | HoldOutcome::OwnedReady { .. } => "ready",
            HoldOutcome::Drop => "drop",
            _ => "other",
        };
        println!(
            "{label} {name} released={}",
            result
                .released
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
    }

    #[test]
    #[ignore]
    fn d6_hold_trace() {
        let now = Instant::now();
        let hello = hello();
        let options = HoldOptions {
            allow_tls: true,
            own_packets: true,
            ..HoldOptions::default()
        };

        let mut hold = HoldTable::default();
        trace_outcome(
            "A syn",
            &hold.feed_observing(1, &tcp_packet(1000, 0x02, &[]), now, options),
        );
        let first = tcp_packet(1001, 0x18, &hello[..5]);
        trace_outcome("A first", &hold.feed_observing(2, &first, now, options));
        let second = tcp_packet(1006, 0x18, &hello[5..]);
        let result = hold.feed_observing(3, &second, now, options);
        if let HoldOutcome::OwnedReady {
            ids,
            packet,
            originals,
        } = &result.outcome
        {
            println!(
                "A second ready ids={} body={} originals={} lens={}",
                ids.iter().map(u32::to_string).collect::<Vec<_>>().join(","),
                u8::from(packet.get(40..) == Some(hello.as_slice())),
                originals.len(),
                originals
                    .iter()
                    .map(|packet| packet.len().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
        } else {
            trace_outcome("A second", &result);
        }

        let mut hold = HoldTable::default();
        trace_outcome(
            "B syn",
            &hold.feed(1, &tcp_packet(9000, 0x02, &[]), now, 0, true, false),
        );
        trace_outcome(
            "B tail",
            &hold.feed(2, &tcp_packet(9006, 0x18, &hello[5..]), now, 0, true, false),
        );
        let result = hold.feed(3, &tcp_packet(9001, 0x18, &hello[..5]), now, 0, true, false);
        if let HoldOutcome::Ready { ids, packet } = &result.outcome {
            println!(
                "B head ready ids={} seq={}",
                ids.iter().map(u32::to_string).collect::<Vec<_>>().join(","),
                u32::from_be_bytes(packet[24..28].try_into().unwrap())
            );
        } else {
            trace_outcome("B head", &result);
        }

        let mut hold = HoldTable::default();
        trace_outcome(
            "C syn",
            &hold.feed(1, &tcp_packet(1000, 0x02, &[]), now, 0, true, false),
        );
        trace_outcome(
            "C first",
            &hold.feed(2, &tcp_packet(1001, 0x18, &hello[..5]), now, 0, true, false),
        );
        println!(
            "C flush released={}",
            hold.flush(now + HOLD_WAIT, 0, false)
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        let stats = hold.r2o_hold_stats();
        println!(
            "C stats timed_out={} timed_out_packets={} pending={}",
            stats.timed_out, stats.timed_out_packets, stats.pending
        );

        let mut hold = HoldTable::default();
        trace_outcome(
            "D syn",
            &hold.feed(3, &tcp_packet(2000, 0x02, &[]), now, 4, true, false),
        );
        trace_outcome(
            "D first",
            &hold.feed(4, &tcp_packet(2001, 0x18, &hello[..5]), now, 4, true, false),
        );
        println!(
            "D revision released={}",
            hold.flush(now, 5, false)
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        let stats = hold.r2o_hold_stats();
        println!(
            "D stats plan_changed={} released={} pending={}",
            stats.plan_changed, stats.released, stats.pending
        );

        let mut hold = HoldTable::default();
        let _ = hold.feed(1, &tcp_packet(3000, 0x02, &[]), now, 0, true, false);
        for id in 2..=9 {
            let _ = hold.feed(
                id,
                &tcp_packet(3001, 0x18, &hello[..5]),
                now,
                0,
                true,
                false,
            );
        }
        let result = hold.feed(
            10,
            &tcp_packet(3001, 0x18, &hello[..5]),
            now,
            0,
            false,
            false,
        );
        println!(
            "E ninth released={} outcome={}",
            result
                .released
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
            match result.outcome {
                HoldOutcome::Pass => "pass",
                HoldOutcome::Waiting | HoldOutcome::OwnedWaiting => "wait",
                HoldOutcome::Ready { .. } | HoldOutcome::OwnedReady { .. } => "ready",
                _ => "other",
            }
        );
    }

    fn d17_action(result: &super::FeedResult, https: bool) -> (&'static str, bool) {
        match &result.outcome {
            HoldOutcome::HttpResponse {
                portal, redirect, ..
            } => {
                let action = if redirect.is_some() && https {
                    "replace"
                } else {
                    "pass"
                };
                (action, portal.is_some())
            }
            HoldOutcome::Drop => ("drop", false),
            _ => ("pass", false),
        }
    }

    fn d17_start(start: Instant, options: HoldOptions, request: &[u8]) -> HoldTable {
        let mut hold = HoldTable::default();
        let _ = hold.feed_observing(1, &http_packet(2000, 0x02, &[]), start, options);
        let _ = hold.feed_observing(
            2,
            &http_response_packet(9000, 2001, 0x12, &[]),
            start + Duration::from_millis(10),
            options,
        );
        let _ = hold.feed_observing(
            3,
            &http_packet(2001, 0x18, request),
            start + Duration::from_millis(11),
            options,
        );
        hold
    }

    fn d17_stats(label: &str, hold: &HoldTable) {
        let stats = hold.r2o_http80_stats();
        println!(
            "D17 {label} stats requests={} injections={} answered={} swap_failed={} \
             dropped={} evicted={} untracked={} unparsed={} later={}",
            stats.requests,
            stats.injections,
            stats.answered,
            stats.swap_failed,
            stats.dropped,
            stats.evicted,
            stats.untracked,
            stats.unparsed,
            stats.later,
        );
    }

    fn http_response_packet6(
        sequence: u32,
        acknowledgment: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = vec![0; 40 + 20 + payload.len()];
        packet[0] = 0x60;
        let payload_len = (20 + payload.len()) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        let mut server = [0_u8; 16];
        server[0] = 0x20;
        server[1] = 0x01;
        server[15] = 0xd6;
        let mut client = [0_u8; 16];
        client[0] = 0x20;
        client[1] = 0x01;
        client[15] = 0x17;
        packet[8..24].copy_from_slice(&server);
        packet[24..40].copy_from_slice(&client);
        let tcp = 40;
        packet[tcp..tcp + 2].copy_from_slice(&80_u16.to_be_bytes());
        packet[tcp + 2..tcp + 4].copy_from_slice(&50000_u16.to_be_bytes());
        packet[tcp + 4..tcp + 8].copy_from_slice(&sequence.to_be_bytes());
        packet[tcp + 8..tcp + 12].copy_from_slice(&acknowledgment.to_be_bytes());
        packet[tcp + 12] = 0x50;
        packet[tcp + 13] = flags;
        packet[tcp + 20..].copy_from_slice(payload);
        packet
    }

    fn http_packet6(sequence: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 40 + 20 + payload.len()];
        packet[0] = 0x60;
        let payload_len = (20 + payload.len()) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        let mut server = [0_u8; 16];
        server[0] = 0x20;
        server[1] = 0x01;
        server[15] = 0xd6;
        let mut client = [0_u8; 16];
        client[0] = 0x20;
        client[1] = 0x01;
        client[15] = 0x17;
        packet[8..24].copy_from_slice(&client);
        packet[24..40].copy_from_slice(&server);
        let tcp = 40;
        packet[tcp..tcp + 2].copy_from_slice(&50000_u16.to_be_bytes());
        packet[tcp + 2..tcp + 4].copy_from_slice(&80_u16.to_be_bytes());
        packet[tcp + 4..tcp + 8].copy_from_slice(&sequence.to_be_bytes());
        packet[tcp + 8..tcp + 12].copy_from_slice(&3000_u32.to_be_bytes());
        packet[tcp + 12] = 0x50;
        packet[tcp + 13] = flags;
        packet[tcp + 20..].copy_from_slice(payload);
        packet
    }

    fn d17_start6(start: Instant, options: HoldOptions, request: &[u8]) -> HoldTable {
        let mut hold = HoldTable::default();
        let _ = hold.feed_observing(1, &http_packet6(2000, 0x02, &[]), start, options);
        let _ = hold.feed_observing(
            2,
            &http_response_packet6(9000, 2001, 0x12, &[]),
            start + Duration::from_millis(10),
            options,
        );
        let _ = hold.feed_observing(
            3,
            &http_packet6(2001, 0x18, request),
            start + Duration::from_millis(11),
            options,
        );
        hold
    }

    #[test]
    #[ignore]
    fn d17_http80_trace() {
        let start = Instant::now();
        let options = HoldOptions {
            observe_http: true,
            ..HoldOptions::default()
        };
        let request = b"GET /path?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let request_end = 2001 + request.len() as u32;
        let response = b"HTTP/1.1 302 Found\r\nLocation: http://lawfilter.example/blocked\r\nContent-Length: 0\r\n\r\n";

        let mut no_https = d17_start(start, options, request);
        let result = no_https.feed_observing(
            4,
            &http_response_packet(9001, request_end, 0x18, response),
            start + Duration::from_millis(12),
            options,
        );
        let (action, portal) = d17_action(&result, false);
        println!("D17 no-https action={action} portal={}", u8::from(portal));
        d17_stats("no-https", &no_https);

        let mut https = d17_start(start, options, request);
        let result = https.feed_observing(
            4,
            &http_response_packet(9001, request_end, 0x18, response),
            start + Duration::from_millis(12),
            options,
        );
        let (action, portal) = d17_action(&result, true);
        println!("D17 https action={action} portal={}", u8::from(portal));
        d17_stats("https", &https);
        let answered = match &result.outcome {
            HoldOutcome::HttpResponse { event, .. } => Some((event.key, event.request_no)),
            _ => None,
        };

        let mut slow = d17_start(start, options, request);
        let result = slow.feed_observing(
            4,
            &http_response_packet(9001, request_end, 0x18, response),
            start + Duration::from_millis(200),
            options,
        );
        let (action, portal) = d17_action(&result, false);
        println!("D17 slow action={action} portal={}", u8::from(portal));
        d17_stats("slow", &slow);

        let mut duplicate = d17_start(start, options, request);
        let _ = duplicate.feed_observing(
            4,
            &http_response_packet(9001, request_end, 0x18, response),
            start + Duration::from_millis(12),
            options,
        );
        let result = duplicate.feed_observing(
            5,
            &http_response_packet(9001, request_end, 0x18, response),
            start + Duration::from_millis(13),
            options,
        );
        let (action, portal) = d17_action(&result, false);
        println!("D17 duplicate action={action} portal={}", u8::from(portal));
        d17_stats("duplicate", &duplicate);

        {
            let mut cut = d17_start(start, options, request);
            let partial: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789";
            let _ = cut.feed_observing(
                4,
                &http_response_packet(9001, request_end, 0x18, partial),
                start + Duration::from_millis(12),
                options,
            );
            let mut fin = http_packet(request_end, 0x11, &[]);
            fin[28..32].copy_from_slice(&(9001 + partial.len() as u32).to_be_bytes());
            let result = cut.feed_observing(5, &fin, start + Duration::from_millis(13), options);
            let (action, _) = d17_action(&result, true);
            if let HoldOutcome::HttpResponse { event, .. } = &result.outcome {
                println!(
                    "D17 cut action={action} response={} status={} body={}",
                    event.code, event.status, event.body_bytes
                );
            } else {
                println!("D17 cut action={action} response=- status=0 body=0");
            }
            d17_stats("cut", &cut);
        }

        {
            let mut acked = d17_start(start, options, request);
            let partial: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789";
            let _ = acked.feed_observing(
                4,
                &http_response_packet(9001, request_end, 0x18, partial),
                start + Duration::from_millis(12),
                options,
            );
            let mut fin = http_packet(request_end, 0x11, &[]);
            fin[28..32].copy_from_slice(&(9001 + partial.len() as u32 + 90).to_be_bytes());
            let result = acked.feed_observing(5, &fin, start + Duration::from_millis(13), options);
            let (action, _) = d17_action(&result, false);
            let response = match &result.outcome {
                HoldOutcome::HttpResponse { event, .. } => event.code,
                _ => 0,
            };
            println!("D17 cut-acked-ahead action={action} response={response}");
        }

        {
            let mut stale = d17_start(start, options, request);
            let full: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            let result = stale.feed_observing(
                4,
                &http_response_packet(9001, request_end, 0x18, full),
                start + Duration::from_millis(11) + Duration::from_secs(61),
                options,
            );
            let (action, _) = d17_action(&result, false);
            let response = match &result.outcome {
                HoldOutcome::HttpResponse { event, .. } => event.code,
                _ => 0,
            };
            println!("D17 stale action={action} response={response}");

            let mut edge = d17_start(start, options, request);
            let result = edge.feed_observing(
                4,
                &http_response_packet(9001, request_end, 0x18, full),
                start + Duration::from_millis(11) + Duration::from_secs(60),
                options,
            );
            let (action, _) = d17_action(&result, false);
            let response = match &result.outcome {
                HoldOutcome::HttpResponse { event, .. } => event.code,
                _ => 0,
            };
            println!("D17 stale-edge action={action} response={response}");
        }

        {
            let mut find = d17_start(start, options, request);
            let full: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            let mut spoof = http_response_packet(9001, request_end, 0x18, full);
            spoof[22..24].copy_from_slice(&50_001_u16.to_be_bytes());
            let result = find.feed_observing(4, &spoof, start + Duration::from_millis(12), options);
            let (action, _) = d17_action(&result, false);
            let response = match &result.outcome {
                HoldOutcome::HttpResponse { event, .. } => event.code,
                _ => 0,
            };
            println!("D17 find-miss action={action} response={response}");
        }

        {
            let post_request: &[u8] =
                b"POST /login HTTP/1.1\r\nHost: RuTracker.org\r\nContent-Length: 0\r\n\r\n";
            let mut post = d17_start(start, options, post_request);
            let post_end = 2001 + post_request.len() as u32;
            let result = post.feed_observing(
                4,
                &http_response_packet(9001, post_end, 0x18, response),
                start + Duration::from_millis(12),
                options,
            );
            let (action, portal) = d17_action(&result, false);
            let response_code = match &result.outcome {
                HoldOutcome::HttpResponse { event, .. } => event.code,
                _ => 0,
            };
            println!(
                "D17 post action={action} response={response_code} portal={}",
                u8::from(portal)
            );
            d17_stats("post", &post);
        }

        {
            let bad_request: &[u8] = b"GET /a#b HTTP/1.1\r\nHost: RuTracker.org\r\n\r\n";
            let bad = d17_start(start, options, bad_request);
            d17_stats("bad-target", &bad);
        }

        {
            let mut v6 = d17_start6(start, options, request);
            let result = v6.feed_observing(
                4,
                &http_response_packet6(9001, request_end, 0x18, response),
                start + Duration::from_millis(12),
                options,
            );
            let (action, portal) = d17_action(&result, false);
            println!("D17 ipv6 action={action} portal={}", u8::from(portal));
            d17_stats("ipv6", &v6);
        }

        {
            let mut complete = d17_start(start, options, request);
            let full: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            let result = complete.feed_observing(
                4,
                &http_response_packet(9001, request_end, 0x18, full),
                start + Duration::from_millis(12),
                options,
            );
            let (action, _) = d17_action(&result, false);
            if let HoldOutcome::HttpResponse { event, .. } = &result.outcome {
                println!(
                    "D17 complete action={action} response={} status={} body={}",
                    event.code, event.status, event.body_bytes
                );
            } else {
                println!("D17 complete action={action} response=- status=0 body=0");
            }
            d17_stats("complete", &complete);
        }

        {
            let mut invalid = d17_start(start, options, request);
            let bad: &[u8] = b"HTTP/1.1 200 OK\r\nMalformed Header\r\n\r\n";
            let result = invalid.feed_observing(
                4,
                &http_response_packet(9001, request_end, 0x18, bad),
                start + Duration::from_millis(12),
                options,
            );
            let (action, _) = d17_action(&result, false);
            if let HoldOutcome::HttpResponse { event, .. } = &result.outcome {
                println!(
                    "D17 invalid action={action} response={} status={} body={}",
                    event.code, event.status, event.body_bytes
                );
            } else {
                println!("D17 invalid action={action} response=- status=0 body=0");
            }
            d17_stats("invalid", &invalid);
        }

        {
            let request_packet = http_packet(2001, 0x18, request);
            let key = crate::capture::TcpFlowKey::from_packet(&request_packet)
                .unwrap()
                .wire_key();
            let applied = r2k_core::control::AppliedEvent {
                key,
                plan_id: std::array::from_fn(|index| index as u8),
                trial_id: std::array::from_fn(|index| 16 + index as u8),
                execution_id: 777,
                binding: r2k_core::control::BindingContext {
                    generation: 9,
                    kind: 1,
                    family: 4,
                    shape: 2,
                    temporary: true,
                    epoch: [0x3c; 16],
                },
            };
            let c_get: &[u8] = b"GET /forum/index.php HTTP/1.1\r\nHost: RuTracker.org:80\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n";
            let c_request_end = 2001 + c_get.len() as u32;
            let mut executed = d17_start(start, options, c_get);
            executed.note_http_execution(2001, &applied);
            let result = executed.feed_observing(
                4,
                &http_response_packet(9001, c_request_end, 0x18, response),
                start + Duration::from_millis(12),
                options,
            );
            let (action, portal) = d17_action(&result, false);
            if let HoldOutcome::HttpResponse { event, .. } = &result.outcome {
                println!(
                    "D17 executed action={action} portal={} execution={} plan={} trial={} binding={}/{}/{} host={} path={} request_no={}",
                    u8::from(portal),
                    event.execution_id,
                    event
                        .plan_id
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    event
                        .trial_id
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    event.binding.generation,
                    event.binding.kind,
                    event.binding.shape,
                    String::from_utf8_lossy(&event.host),
                    String::from_utf8_lossy(&event.path),
                    event.request_no
                );
            } else {
                println!(
                    "D17 executed action={action} portal={} execution=0 plan= trial= binding=0/0/0",
                    u8::from(portal)
                );
            }

            let mut wrong = d17_start(start, options, request);
            wrong.note_http_execution(2002, &applied);
            let result = wrong.feed_observing(
                4,
                &http_response_packet(9001, request_end, 0x18, response),
                start + Duration::from_millis(12),
                options,
            );
            let (action, portal) = d17_action(&result, false);
            if let HoldOutcome::HttpResponse { event, .. } = &result.outcome {
                println!(
                    "D17 executed-wrong action={action} portal={} execution={} plan={} trial={} binding={}/{}/{}",
                    u8::from(portal),
                    event.execution_id,
                    event
                        .plan_id
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    event
                        .trial_id
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    event.binding.generation,
                    event.binding.kind,
                    event.binding.shape
                );
            } else {
                println!(
                    "D17 executed-wrong action={action} portal={} execution=0 plan= trial= binding=0/0/0",
                    u8::from(portal)
                );
            }
        }

        {
            let mut rejected = d17_start(start, options, request);
            let result = rejected.feed_observing(
                4,
                &http_response_packet(
                    9001,
                    request_end,
                    0x18,
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                ),
                start + Duration::from_millis(12),
                options,
            );
            let HoldOutcome::HttpResponse { event, .. } = result.outcome else {
                panic!("HTTPS injection must be recognized");
            };
            let mut event = *event;
            assert!(rejected.r2o_http_delivery_rejected(&mut event));
            println!("D17 delivered-reject code={}", event.code);
            let late = rejected.feed_observing(
                5,
                &http_response_packet(
                    9001 + b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".len() as u32,
                    request_end,
                    0x18,
                    b"late",
                ),
                start + Duration::from_millis(13),
                options,
            );
            let (action, _) = d17_action(&late, false);
            println!("D17 delivered-reject-late action={action}");
        }

        if let Some((key, request_no)) = answered {
            assert!(https.mark_http_response_answered(&key, request_no));
            d17_stats("https-swap", &https);
            let server = https.feed_observing(
                5,
                &http_response_packet(9001 + response.len() as u32, request_end, 0x18, b"late"),
                start + Duration::from_millis(13),
                options,
            );
            let (action, _) = d17_action(&server, true);
            println!("D17 post-server action={action}");
            d17_stats("post-server", &https);
            let mut client = http_packet(request_end, 0x10, &[]);
            client[28..32].copy_from_slice(&(9001 + response.len() as u32).to_be_bytes());
            let client =
                https.feed_observing(6, &client, start + Duration::from_millis(14), options);
            let (action, _) = d17_action(&client, true);
            println!("D17 post-client action={action}");
            d17_stats("post-client", &https);
        }

        {
            let mut fail = d17_start(start, options, request);
            let result = fail.feed_observing(
                4,
                &http_response_packet(9001, request_end, 0x18, response),
                start + Duration::from_millis(12),
                options,
            );
            let (event, mut portal) = match result.outcome {
                HoldOutcome::HttpResponse { event, portal, .. } => (event, portal),
                _ => panic!("HTTPS injection must be recognized"),
            };
            let swapped = fail.r2o_apply_http_swap_result(Some(&event), portal.as_mut(), false);
            let stats = fail.r2o_http80_stats();
            println!(
                "D17 https-fail result={} answered={} swap_failed={}",
                u8::from(swapped),
                stats.answered,
                stats.swap_failed
            );
            let late = fail.feed_observing(
                5,
                &http_response_packet(9001 + response.len() as u32, request_end, 0x18, b"late"),
                start + Duration::from_millis(13),
                options,
            );
            let (action, _) = d17_action(&late, true);
            println!("D17 https-fail-late action={action}");
            d17_stats("https-fail", &fail);
        }
    }
}
