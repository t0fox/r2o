//! Ограниченное удержание NFQUEUE-пакетов для сегментированных TLS ClientHello.

use crate::capture::{
    CaptureResult, CaptureStats, CaptureTable, TcpFlowKey, TcpHello, tcp_hello_from_bytes,
    tcp_http_hello_from_bytes,
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
const HTTP_FLOW_CAPACITY: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HoldOutcome {
    Pass,
    Waiting,
    Drop,
    Ready {
        ids: Vec<u32>,
        packet: Vec<u8>,
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
}

impl HoldTable {
    /// Возвращает накопленные счётчики сборки TCP-приветствий и HTTP-запросов.
    pub fn r2o_capture_stats(&self) -> CaptureStats {
        self.capture.stats()
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
        true
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
        } = options;
        let mut released = self.flush(now, revision, false);
        self.syns
            .retain(|anchor| now.saturating_duration_since(anchor.seen) < SYN_TRACK_TTL);
        self.http_requests
            .retain(|flow| now.saturating_duration_since(flow.seen) < SYN_TRACK_TTL);
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
            let slot = &self.slots[index];
            if tcp.flags & 0x07 != 0 || (source != slot.client && !tcp.payload.is_empty()) {
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
                            !anchor.controller_probe,
                        )
                {
                    self.syns[anchor_index].saw_hello = true;
                    self.capture.forget(&key);
                    if let Some(hello) = tcp_hello_from_bytes(key, &bytes) {
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
            self.slots.len() - 1
        };

        let slot = &self.slots[index];
        if slot.generation != anchor.generation
            || slot.revision != revision
            || slot.client != source
            || slot.acknowledgment != tcp.acknowledgment
            || tcp.flags & !0x18 != 0
            || tcp.flags & 0x10 == 0
            || view.total_len > HOLD_PACKET_BYTES
            || slot.packets.len() >= HOLD_PACKETS
        {
            released.extend(self.remove_slot(index));
            released.push(id);
            self.capture.forget(&key);
            return FeedResult {
                released,
                outcome: HoldOutcome::Waiting,
            };
        }

        if self.slots[index].packets.try_reserve(1).is_err() {
            released.extend(self.remove_slot(index));
            released.push(id);
            self.capture.forget(&key);
            return FeedResult {
                released,
                outcome: HoldOutcome::Waiting,
            };
        }
        self.slots[index].packets.push(HeldPacket {
            id,
            sequence: tcp.sequence,
            bytes: packet[..view.total_len].to_vec(),
        });

        let capture = match self.slots[index].kind {
            HoldKind::Tls => self.capture.feed_with_visibility(
                key,
                anchor.generation,
                now,
                tcp.sequence,
                Some(self.slots[index].anchor),
                payload,
                !anchor.controller_probe,
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
                self.capture.forget(&key);
                let head = held
                    .packets
                    .iter()
                    .find(|held_packet| held_packet.sequence == sequence)
                    .and_then(|held_packet| synthetic_packet(&held_packet.bytes, &bytes));
                let Some(packet) = head else {
                    released.extend(held.packets.into_iter().map(|held_packet| held_packet.id));
                    return FeedResult {
                        released,
                        outcome: HoldOutcome::Waiting,
                    };
                };
                if held.kind == HoldKind::Http {
                    self.syns[anchor_index]
                        .r2o_http_requests
                        .observe(sequence, &bytes);
                }
                FeedResult {
                    released,
                    outcome: HoldOutcome::Ready {
                        ids: held
                            .packets
                            .into_iter()
                            .map(|held_packet| held_packet.id)
                            .collect(),
                        packet,
                    },
                }
            }
            CaptureResult::Rejected | CaptureResult::Full => {
                released.extend(self.remove_slot(index));
                self.capture.forget(&key);
                FeedResult {
                    released,
                    outcome: HoldOutcome::Waiting,
                }
            }
            CaptureResult::Ignored | CaptureResult::Incomplete => FeedResult {
                released,
                outcome: HoldOutcome::Waiting,
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
                let timed_out = !all && now >= deadline && revision == slot_revision;
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
        self.http_requests
            .retain(|flow| now.saturating_duration_since(flow.seen) < SYN_TRACK_TTL);
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
        let replacement = HttpRequestFlow {
            key,
            client,
            generation,
            host,
            path,
            target,
            request_sequence: sequence,
            request_end: sequence.wrapping_add(request.len() as u32),
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
        if self.http_requests.len() >= HTTP_FLOW_CAPACITY
            || self.http_requests.try_reserve(1).is_err()
        {
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
            || now.saturating_duration_since(flow.seen) >= SYN_TRACK_TTL
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
                && now.saturating_duration_since(flow.seen) < SYN_TRACK_TTL
        })?;
        if flow
            .response
            .fixed_body_remaining()
            .is_none_or(|remaining| remaining == 0)
        {
            return None;
        }
        let mut body_bytes = flow.response.body_bytes();
        if let Some(body_start) = flow.body_start {
            let delivered = tcp.acknowledgment.wrapping_sub(body_start);
            if seq_after(tcp.acknowledgment, body_start) {
                body_bytes = body_bytes.max(u64::from(delivered));
            }
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
        self.slots
            .remove(index)
            .packets
            .into_iter()
            .map(|packet| packet.id)
            .collect()
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
    use super::{HOLD_WAIT, HoldOptions, HoldOutcome, HoldTable};
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
    fn timeout_keeps_controller_probe_capture_out_of_diagnostics() {
        let now = Instant::now();
        let mut hold = HoldTable::default();
        let options = HoldOptions {
            revision: 0,
            allow_tls: true,
            ..HoldOptions::default()
        };
        let hello = hello();
        let _ = hold.feed_controller_probe(1, &tcp_packet(3000, 0x02, &[]), now, options);
        assert_eq!(
            hold.feed_controller_probe(2, &tcp_packet(3001, 0x18, &hello[..5]), now, options,)
                .outcome,
            HoldOutcome::Waiting
        );

        assert_eq!(hold.flush(now + HOLD_WAIT, 0, false), [2]);
        assert!(hold.r2o_take_incomplete_diagnostics().is_empty());

        let mut complete = HoldTable::default();
        let _ = complete.feed_controller_probe(3, &tcp_packet(4000, 0x02, &[]), now, options);
        assert_eq!(
            complete
                .feed_controller_probe(4, &tcp_packet(4001, 0x18, &hello[..5]), now, options,)
                .outcome,
            HoldOutcome::Waiting
        );
        assert!(matches!(
            complete
                .feed_controller_probe(5, &tcp_packet(4006, 0x18, &hello[5..]), now, options,)
                .outcome,
            HoldOutcome::Ready { .. }
        ));
        assert_eq!(complete.r2o_capture_stats(), super::CaptureStats::default());
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
}
