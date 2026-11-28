use crate::engine::RawTcpContext;
use r2k_core::control::KEY_LEN;
use r2k_core::packet::PacketView;
use r2k_core::raw_flow::{
    LEASE, MAX_ACTIVE, Profile, REPEAT_MIN, RETRY, Report, ResultKind, Sample, Trial,
};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub enum Observation {
    Measured(Sample),
    Attempt(Trial),
    Confirmed(Report),
    TimingUnavailable(std::net::SocketAddr),
}

pub struct RawUdpContext {
    pub key: [u8; KEY_LEN],
    pub generation: u64,
    pub client_is_low: bool,
    pub reverse: bool,
    pub recognized: bool,
}

struct UdpObservation {
    sample: Sample,
    first: Instant,
    expires: Instant,
    prior_reply: bool,
    reported: bool,
}

#[derive(Clone, Copy)]
enum Stage {
    Observing,
    Rebase(u32),
    Measured,
    Armed(Trial, u64),
    Sending(Trial),
    Executed(Trial, u64, u64),
}

struct Candidate {
    sample: Sample,
    server_seq: u32,
    first_capture_ns: u64,
    expires: Instant,
    rebased: bool,
    stage: Stage,
}

pub struct RawDiscovery {
    epoch: [u8; 16],
    next_measurement: u64,
    active: Vec<Candidate>,
    udp: Vec<UdpObservation>,
    recent: VecDeque<(std::net::SocketAddr, u8, Profile, Instant)>,
    timing_reported: bool,
}

impl RawDiscovery {
    pub fn new(epoch: [u8; 16]) -> Option<Self> {
        (epoch != [0; 16]).then(|| Self {
            epoch,
            next_measurement: 0,
            active: Vec::with_capacity(MAX_ACTIVE),
            udp: Vec::new(),
            recent: VecDeque::new(),
            timing_reported: false,
        })
    }

    pub fn expire(&mut self, now: Instant) {
        self.active.retain(|entry| now < entry.expires);
        self.udp.retain(|entry| now < entry.expires);
    }

    pub fn disconnect(&mut self) {
        self.active.clear();
        self.udp.clear();
    }

    fn forget(&mut self, key: [u8; KEY_LEN]) {
        self.active.retain(|entry| entry.sample.key != key);
    }

    pub fn arm(&mut self, trial: Trial, now: Instant, at_ns: u64) -> bool {
        self.expire(now);
        let Some(entry) = self
            .active
            .iter_mut()
            .find(|entry| entry.sample == trial.sample)
        else {
            return false;
        };
        if at_ns == 0 {
            return false;
        }
        match entry.stage {
            Stage::Measured => {
                entry.stage = Stage::Armed(trial, at_ns);
                true
            }
            Stage::Armed(old, _) | Stage::Sending(old) | Stage::Executed(old, _, _) => old == trial,
            Stage::Observing | Stage::Rebase(_) => false,
        }
    }

    pub fn finish(
        &mut self,
        trial: Trial,
        execution: Option<u64>,
        now: Instant,
        at_ns: u64,
    ) -> Option<Report> {
        self.expire(now);
        let index = self.active.iter().position(|entry| {
            entry.sample == trial.sample
                && matches!(entry.stage, Stage::Sending(sent) if sent == trial)
        })?;
        let Some(execution) = execution.filter(|_| at_ns != 0) else {
            self.active.swap_remove(index);
            return None;
        };
        self.active[index].stage = Stage::Executed(trial, execution, at_ns);
        Some(Report {
            trial,
            execution,
            kind: ResultKind::Executed,
        })
    }

    pub fn tcp(
        &mut self,
        packet: &[u8],
        context: Option<RawTcpContext>,
        now: Instant,
        captured_ns: Option<u64>,
    ) -> Option<Observation> {
        self.expire(now);
        let view = PacketView::parse(packet).filter(|view| view.fragment & 0x3fff == 0)?;
        let tcp = view.tcp_segment(packet)?;
        let payload = packet.get(tcp.payload)?;
        let Some(context) = context else {
            if tcp.flags & 0x07 != 0
                && let Some(key) = crate::control::flow_journal_key_for_packet(packet)
            {
                self.forget(key);
            }
            return None;
        };
        let key = context.key;
        self.active.retain(|entry| {
            entry.sample.key != key || entry.sample.generation == context.generation
        });
        if tcp.flags & 0x07 != 0 || context.recognized {
            self.forget(key);
            return None;
        }
        let index = self.active.iter().position(|entry| entry.sample.key == key);
        if context.reverse {
            let index = index?;
            let entry = &mut self.active[index];
            if tcp.flags & 0x17 != 0x10 || tcp.sequence != entry.server_seq {
                self.active.swap_remove(index);
                return None;
            }
            let acked = tcp.acknowledgment.wrapping_sub(entry.sample.seq) as i32;
            if acked <= 0 {
                if !payload.is_empty() {
                    self.active.swap_remove(index);
                }
                return None;
            }
            let end = i32::from(entry.sample.profile.length);
            if acked < end && !entry.rebased && payload.is_empty() {
                entry.rebased = true;
                entry.stage = Stage::Rebase(tcp.acknowledgment);
                return None;
            }
            // Every positive ACK retires the old identity. A single partial
            // ACK can start a new sample within the original range.
            let entry = self.active.swap_remove(index);
            if acked == end
                && let Stage::Executed(trial, execution, executed_ns) = entry.stage
                && captured_ns.is_some_and(|captured| captured > executed_ns)
            {
                let endpoint = trial.sample.server();
                self.recent.retain(|(address, transport, profile, _)| {
                    *address != endpoint || *transport != 6 || *profile != trial.sample.profile
                });
                return Some(Observation::Confirmed(Report {
                    trial,
                    execution,
                    kind: ResultKind::TransportAck,
                }));
            }
            return None;
        }
        if context.planned || tcp.flags & 0x17 != 0x10 || payload.is_empty() {
            return None;
        }
        if let Some(index) = index {
            let entry = &mut self.active[index];
            if let Stage::Rebase(next_seq) = entry.stage {
                let end = entry
                    .sample
                    .seq
                    .wrapping_add(u32::from(entry.sample.profile.length));
                let length = end.wrapping_sub(next_seq);
                if tcp.sequence == next_seq
                    && tcp.acknowledgment == entry.server_seq
                    && payload.len() <= length as usize
                    && let Some(captured_ns) = captured_ns
                    && let Some(profile) = Profile::of(payload, context.tcp_profile)
                {
                    self.next_measurement = self.next_measurement.wrapping_add(1).max(1);
                    entry.sample.measurement = self.next_measurement;
                    entry.sample.seq = next_seq;
                    entry.sample.profile = profile;
                    entry.first_capture_ns = captured_ns;
                    entry.stage = Stage::Observing;
                }
                return None;
            }
            if tcp.sequence != entry.sample.seq
                || tcp.acknowledgment != entry.server_seq
                || Profile::of(payload, context.tcp_profile) != Some(entry.sample.profile)
            {
                self.active.swap_remove(index);
                return None;
            }
            return match entry.stage {
                Stage::Observing
                    if captured_ns.is_some_and(|captured| {
                        Duration::from_nanos(captured.saturating_sub(entry.first_capture_ns))
                            >= REPEAT_MIN
                    }) =>
                {
                    let sample = entry.sample;
                    entry.stage = Stage::Measured;
                    if self.remember(sample, now) {
                        Some(Observation::Measured(sample))
                    } else {
                        self.active.swap_remove(index);
                        None
                    }
                }
                Stage::Armed(trial, armed_ns)
                    if captured_ns.is_some_and(|captured| captured > armed_ns) =>
                {
                    entry.stage = Stage::Sending(trial);
                    Some(Observation::Attempt(trial))
                }
                _ => None,
            };
        }
        if context.forward_seen != 1
            || context.first_seq != tcp.sequence
            || context.server_seq != tcp.acknowledgment
            || self.active.len() + self.udp.len() >= MAX_ACTIVE
            || !opaque_tcp(payload, tcp.destination_port)
        {
            return None;
        }
        if !(r2k_core::raw_flow::SAMPLE_MIN..=r2k_core::raw_flow::SAMPLE_MAX)
            .contains(&payload.len())
        {
            return None;
        }
        let Some(first_capture_ns) = captured_ns else {
            return (!std::mem::replace(&mut self.timing_reported, true)).then_some(
                Observation::TimingUnavailable(std::net::SocketAddr::new(
                    view.dst.as_ip_addr(),
                    tcp.destination_port,
                )),
            );
        };
        let profile = Profile::of(payload, context.tcp_profile)?;
        self.next_measurement = self.next_measurement.wrapping_add(1).max(1);
        let sample = Sample {
            key,
            client_is_low: context.client_is_low,
            epoch: self.epoch,
            generation: context.generation,
            measurement: self.next_measurement,
            seq: tcp.sequence,
            profile,
        };
        self.active.push(Candidate {
            sample,
            server_seq: tcp.acknowledgment,
            first_capture_ns,
            expires: now + LEASE,
            rebased: false,
            stage: Stage::Observing,
        });
        None
    }

    fn remember(&mut self, sample: Sample, now: Instant) -> bool {
        let endpoint = sample.server();
        let transport = sample.key[37];
        self.recent.retain(|(_, _, _, until)| now < *until);
        if self.recent.iter().any(|(seen, tr, profile, _)| {
            *seen == endpoint && *tr == transport && *profile == sample.profile
        }) {
            return false;
        }
        if self.recent.len() == 32 {
            self.recent.pop_front();
        }
        self.recent
            .push_back((endpoint, transport, sample.profile, now + RETRY));
        true
    }

    pub fn udp(
        &mut self,
        packet: &[u8],
        context: RawUdpContext,
        now: Instant,
    ) -> Option<(Sample, bool)> {
        self.expire(now);
        let view = PacketView::parse(packet).filter(|view| view.fragment & 0x3fff == 0)?;
        let payload = packet.get(view.udp_payload_range(packet)?)?;
        let key = context.key;
        self.udp.retain(|entry| {
            entry.sample.key != key
                || entry.sample.generation == context.generation && !context.recognized
        });
        if context.recognized {
            return None;
        }
        let index = self.udp.iter().position(|entry| entry.sample.key == key);
        if context.reverse {
            if let Some(index) = index {
                self.udp[index].prior_reply |= !payload.is_empty();
            }
            return None;
        }
        let server_port = u16::from_be_bytes(
            key[if context.client_is_low {
                35..37
            } else {
                33..35
            }]
            .try_into()
            .ok()?,
        );
        if !opaque_udp(payload, server_port) {
            return None;
        }
        let profile = Profile::of(payload, 0)?;
        if let Some(index) = index {
            let entry = &mut self.udp[index];
            if entry.sample.profile != profile {
                self.next_measurement = self.next_measurement.wrapping_add(1).max(1);
                entry.sample.measurement = self.next_measurement;
                entry.sample.profile = profile;
                entry.first = now;
                entry.reported = false;
                return None;
            }
            if entry.reported || now.saturating_duration_since(entry.first) < REPEAT_MIN {
                return None;
            }
            entry.reported = true;
            let result = (entry.sample, entry.prior_reply);
            return self.remember(result.0, now).then_some(result);
        }
        if self.active.len() + self.udp.len() >= MAX_ACTIVE {
            return None;
        }
        self.next_measurement = self.next_measurement.wrapping_add(1).max(1);
        self.udp.push(UdpObservation {
            sample: Sample {
                key,
                client_is_low: context.client_is_low,
                epoch: self.epoch,
                generation: context.generation,
                measurement: self.next_measurement,
                seq: 0,
                profile,
            },
            first: now,
            expires: now + LEASE,
            prior_reply: false,
            reported: false,
        });
        None
    }
}

fn opaque_udp(payload: &[u8], port: u16) -> bool {
    !matches!(port, 53 | 67 | 68 | 443 | 5353)
        && payload.first().is_some_and(|first| first & 0xc0 == 0)
        && payload.get(4..8) != Some(&[0x21, 0x12, 0xa4, 0x42])
        && !r2k_core::dns_probe::is_dns_probe_query(payload)
}

fn opaque_tcp(payload: &[u8], port: u16) -> bool {
    if port == 53
        || r2k_core::dns_probe::is_dns_tcp_probe_frame(payload)
        || payload
            .first()
            .is_none_or(|first| (0x14..=0x18).contains(first))
    {
        return false;
    }
    const KNOWN: [&[u8]; 13] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"DELETE ",
        b"CONNECT ",
        b"TRACE ",
        b"PRI * HTTP/2.0",
        b"HTTP/",
        b"SSH-",
        b"PROXY ",
    ];
    !KNOWN
        .iter()
        .any(|prefix| payload.starts_with(prefix) || prefix.starts_with(payload))
        && r2k_core::httpup::request_host_range(payload).is_none()
}
