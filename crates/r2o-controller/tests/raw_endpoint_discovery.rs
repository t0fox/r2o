use r2k_core::control::{ACK_OK, decode_ack, encode_ack_for_trial, read_frame};
use r2k_core::packet::PacketView;
use r2k_core::raw_flow::{COMMAND_RAW_TRIAL, LEASE, Report, ResultKind, Sample, Trial};
use r2o_controller::catalog::Catalog;
use r2o_controller::r2o_resource_limit::R2oMeasurementGate;
use r2o_controller::raw_discovery::{Trials, candidate, save_confirmed};
use r2o_datapath::engine::{PacketDecision, TcpSessions, decide_raw_tcp_packet};
use r2o_datapath::raw_discovery::{Observation, RawDiscovery};
use std::time::{Duration, Instant};

const DATA: &[u8] = b"\x01opaque sample, faithfully retransmitted";
const TICK: Duration = Duration::from_millis(300);
const WALL: u64 = 1_800_000_000_000_000_000;

fn captured(step: u32) -> u64 {
    WALL + (TICK * step).as_nanos() as u64
}

#[derive(Clone, Copy)]
struct Flow {
    client: [u8; 4],
    port: u16,
    source_port: u16,
}

impl Default for Flow {
    fn default() -> Self {
        Self {
            client: [192, 0, 2, 1],
            port: 7755,
            source_port: 40_000,
        }
    }
}

impl Flow {
    fn tcp(self, from_client: bool, seq: u32, ack: u32, flags: u8, text: &[u8]) -> Vec<u8> {
        let server = [198, 51, 100, 2];
        let (src, dst, sport, dport) = if from_client {
            (self.client, server, self.source_port, self.port)
        } else {
            (server, self.client, self.port, self.source_port)
        };
        let len = 40 + text.len();
        let mut p = vec![0; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        p[28..32].copy_from_slice(&ack.to_be_bytes());
        p[32] = 0x50;
        p[33] = flags;
        p[34..36].copy_from_slice(&32768_u16.to_be_bytes());
        p[40..].copy_from_slice(text);
        p
    }

    fn udp(self, from_client: bool, text: &[u8]) -> Vec<u8> {
        let mut p = self.tcp(from_client, 0, 0, 0, &[]);
        p.truncate(28);
        p.extend_from_slice(text);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p[9] = 17;
        p[24..26].copy_from_slice(&(len - 20).to_be_bytes());
        p[26..28].fill(0);
        p
    }

    fn open(self, sessions: &mut TcpSessions, client_isn: u32) {
        sessions.r2o_observe_tcp_packet(&self.tcp(true, client_isn, 0, 2, b""));
        sessions.r2o_observe_tcp_packet(&self.tcp(false, 2000, client_isn + 1, 0x12, b""));
    }
}

struct Harness {
    sessions: TcpSessions,
    raw: RawDiscovery,
    controller: Trials,
    start: Instant,
}

impl Harness {
    fn new() -> Self {
        Self {
            sessions: TcpSessions::default(),
            raw: RawDiscovery::new([0x73; 16]).unwrap(),
            controller: Trials::default(),
            start: Instant::now(),
        }
    }

    fn feed(&mut self, p: &[u8], step: u32) -> Option<Observation> {
        self.feed_captured(p, step, Some(captured(step)))
    }

    fn feed_captured(&mut self, p: &[u8], step: u32, stamp: Option<u64>) -> Option<Observation> {
        self.sessions.r2o_observe_tcp_packet(p);
        self.raw.tcp(
            p,
            self.sessions.raw_context(p),
            self.start + TICK * step,
            stamp,
        )
    }

    fn measure(&mut self, flow: Flow, seq: u32, step: u32, text: &[u8]) -> Sample {
        let p = flow.tcp(true, seq, 2001, 0x18, text);
        assert!(self.feed(&p, step).is_none());
        let Some(Observation::Measured(sample)) = self.feed(&p, step + 1) else {
            panic!("expected a measurement from the exact retransmission");
        };
        Sample::decode(&sample.encode()).unwrap()
    }

    fn install(&mut self, sample: Sample, plan: [u8; 16], step: u32) -> Trial {
        let trial = Trial {
            sample,
            token: [0x42; 16],
            plan,
        };
        let wire = trial.frame().unwrap();
        let wire = read_frame(&mut wire.as_slice()).unwrap();
        let command = Trial::from_frame(&wire).unwrap();
        let now = self.start + TICK * step;
        assert!(self.raw.arm(command, now, captured(step) + 1));
        assert!(self.raw.arm(command, now, captured(step) + 2));
        let ack = encode_ack_for_trial(COMMAND_RAW_TRIAL, true, ACK_OK, Some(trial.token)).unwrap();
        let ack = decode_ack(&read_frame(&mut ack.as_slice()).unwrap()).unwrap();
        assert_eq!(ack.trial_id, Some(trial.token));
        let permit = R2oMeasurementGate::new(1).r2o_try_acquire().unwrap();
        self.controller.installed(trial, permit, now);
        trial
    }
}

#[test]
fn raw_tcp_measures_executes_and_reuses_an_atomic_endpoint_binding() {
    let mut h = Harness::new();
    let flow = Flow::default();
    flow.open(&mut h.sessions, 1000);
    let sample = h.measure(flow, 1001, 0, DATA);
    assert_eq!(sample.server().port(), flow.port);
    let mut catalog = Catalog::default();
    let (plan, own) = candidate(&catalog, sample).unwrap();
    assert!(!own);
    let trial = h.install(sample, plan, 1);
    let sent = flow.tcp(true, 1001, 2001, 0x18, DATA);
    assert!(h.feed_captured(&sent, 2, Some(captured(1))).is_none());
    let Some(Observation::Attempt(armed)) = h.feed(&sent, 2) else {
        panic!("trial did not apply")
    };
    assert_eq!(armed, trial);
    let PacketDecision::Transmit { packets, fate } =
        decide_raw_tcp_packet(plan, sample.profile, &sent, 1400)
    else {
        panic!("split did not produce wire packets")
    };
    assert_eq!(fate, r2k_core::plan::OriginalFate::Drop);
    assert_eq!(packets.len(), 2);
    let rebuilt = packets
        .iter()
        .flat_map(|packet| {
            let view = PacketView::parse(&packet.packet).unwrap();
            let tcp = view.tcp_segment(&packet.packet).unwrap();
            &packet.packet[tcp.payload]
        })
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(rebuilt, DATA);

    let id = 99;
    let bogus_proof = Report {
        trial,
        execution: id,
        kind: ResultKind::TransportAck,
    };
    assert!(
        h.controller
            .report(bogus_proof, h.start + 2 * TICK)
            .is_none()
    );
    let executed = h
        .raw
        .finish(trial, Some(id), h.start + 2 * TICK, captured(2) + 1)
        .unwrap();
    assert!(
        h.controller
            .report(
                Report::decode(&executed.encode()).unwrap(),
                h.start + 2 * TICK
            )
            .is_none()
    );

    let ack_end = 1001 + DATA.len() as u32;
    let foreign = Flow {
        client: [192, 0, 2, 3],
        ..flow
    };
    assert!(
        h.feed(&foreign.tcp(false, 2001, ack_end, 0x10, b""), 3)
            .is_none()
    );
    assert!(
        h.controller
            .report(
                Report {
                    execution: 15,
                    ..bogus_proof
                },
                h.start + 3 * TICK
            )
            .is_none()
    );
    let response = flow.tcp(false, 2001, ack_end, 0x10, b"");
    let Some(Observation::Confirmed(report)) = h.feed(&response, 3) else {
        panic!("exact transport ACK not accepted")
    };
    let report = Report::decode(&report.encode()).unwrap();
    assert_eq!(
        h.controller.report(report, h.start + 3 * TICK),
        Some(report)
    );
    assert!(h.controller.report(report, h.start + 3 * TICK).is_none());
    assert!(h.feed(&response, 3).is_none());

    save_confirmed(&mut catalog, report, 100).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "r2o-raw-catalog-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("catalog.json");
    let baseline = Catalog::default();
    baseline.save_atomic(&path, 90).unwrap();
    let baseline_bytes = std::fs::read(&path).unwrap();
    catalog.save_atomic(&path, 100).unwrap();
    let loaded = Catalog::load(&path).unwrap();
    let binding = &loaded.boxes[0].bindings[0];
    assert_eq!(binding.port, flow.port);
    assert_eq!(binding.kind, "raw");
    assert_eq!(candidate(&loaded, sample), Some((plan, true)));
    let mut other_port = sample;
    other_port.key[35..37].copy_from_slice(&8443_u16.to_be_bytes());
    assert!(!candidate(&loaded, other_port).unwrap().1);
    let mut other_profile = sample;
    other_profile.profile.tcp = 2;
    assert!(!candidate(&loaded, other_profile).unwrap().1);
    let mut udp = sample;
    udp.key[37] = 17;
    assert!(candidate(&loaded, udp).is_none());
    let mut ipv6 = sample;
    ipv6.key[0] = 6;
    ipv6.key[1..17].copy_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    ipv6.key[17..33].copy_from_slice(
        &"2001:db8::2"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    assert!(!candidate(&loaded, ipv6).unwrap().1);

    flow.open(&mut h.sessions, 3000);
    let next = h.measure(flow, 3001, 4, DATA);
    assert_ne!(next.generation, sample.generation);
    assert_eq!(candidate(&loaded, next), Some((plan, true)));
    let reused = h.install(next, plan, 5);
    let packet = flow.tcp(true, 3001, 2001, 0x18, DATA);
    assert!(matches!(h.feed(&packet, 6), Some(Observation::Attempt(armed)) if armed == reused));
    baseline.save_atomic(&path, 90).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), baseline_bytes);
    assert!(!candidate(&Catalog::load(&path).unwrap(), next).unwrap().1);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn raw_tcp_rejects_stale_range_rst_reused_tuple_and_expired_lease() {
    let flow = Flow::default();
    for close in [
        "partial",
        "rst",
        "generation",
        "deadline",
        "disconnect",
        "different-bytes",
        "queued-ack",
        "undated-ack",
        "pre-execution",
    ] {
        let mut h = Harness::new();
        flow.open(&mut h.sessions, 1000);
        let sample = h.measure(flow, 1001, 0, DATA);
        let trial = h.install(sample, [3; 16], 1);
        let mut old_epoch = trial;
        old_epoch.sample.epoch[0] ^= 1;
        assert!(!h.raw.arm(old_epoch, h.start + TICK, captured(1)));
        let sent = flow.tcp(true, 1001, 2001, 0x18, DATA);
        let end = 1001 + DATA.len() as u32;
        match close {
            "partial" => {
                assert!(h.feed(&flow.tcp(false, 2001, 1009, 0x10, b""), 2).is_none());
                assert!(!h.raw.arm(trial, h.start + 2 * TICK, captured(2)));
                let new_sample = h.measure(flow, 1009, 3, &DATA[8..]);
                assert_ne!(new_sample.measurement, sample.measurement);
                assert_eq!(new_sample.seq, 1009);
            }
            "rst" => {
                assert!(h.feed(&flow.tcp(false, 2001, end, 0x14, b""), 2).is_none());
            }
            "generation" => {
                flow.open(&mut h.sessions, 3000);
            }
            "deadline" => {
                h.raw.expire(h.start + LEASE);
            }
            "disconnect" => {
                h.raw.disconnect();
            }
            "different-bytes" => {
                let mut other = DATA.to_vec();
                other[1] ^= 1;
                assert!(
                    h.feed(&flow.tcp(true, 1001, 2001, 0x18, &other), 2)
                        .is_none()
                );
            }
            "queued-ack" | "undated-ack" => {
                assert!(matches!(h.feed(&sent, 2), Some(Observation::Attempt(_))));
                assert!(
                    h.raw
                        .finish(trial, Some(23), h.start + 2 * TICK, captured(2) + 1)
                        .is_some()
                );
                let ack = flow.tcp(false, 2001, end, 0x10, b"");
                assert!(
                    h.feed_captured(&ack, 3, (close == "queued-ack").then_some(captured(1)))
                        .is_none()
                );
            }
            _ => {
                assert!(h.feed(&flow.tcp(false, 2001, end, 0x10, b""), 2).is_none());
            }
        }
        assert!(h.feed(&sent, 6).is_none(), "{close}");
        assert!(
            h.raw
                .finish(trial, Some(23), h.start + 6 * TICK, captured(6))
                .is_none(),
            "{close}"
        );
        assert!(
            h.feed(&flow.tcp(false, 2001, end, 0x10, b""), 7).is_none(),
            "{close}"
        );
    }
}

#[test]
fn partial_tls_and_recognized_udp_keep_their_path() {
    let mut h = Harness::new();
    let flow = Flow::default();
    flow.open(&mut h.sessions, 1000);
    let partial = flow.tcp(
        true,
        1001,
        2001,
        0x18,
        b"\x16\x03\x01\x01\x00\x01\x00\x00\xfc\x03\x03",
    );
    for i in 0..3 {
        assert!(h.feed(&partial, i).is_none());
    }

    let mut udp = r2o_datapath::r2o_udp_sessions::R2oUdpSessions::new().unwrap();
    let udp_packet = flow.udp(true, DATA);
    let hook = Some(r2o_datapath::netlink::R2O_NF_INET_POST_ROUTING);
    udp.r2o_observe_packet_at_hook(&udp_packet, h.start, hook);
    assert!(
        h.raw
            .udp(&udp_packet, udp.raw_context(&udp_packet).unwrap(), h.start)
            .is_none()
    );
    udp.r2o_observe_packet_at_hook(&udp_packet, h.start + TICK, hook);
    assert!(matches!(
        h.raw.udp(&udp_packet, udp.raw_context(&udp_packet).unwrap(), h.start + TICK),
        Some((sample, false)) if sample.key[37] == 17 && sample.server().port() == flow.port
    ));
    let dns = Flow { port: 53, ..flow }.udp(true, DATA);
    for i in 0..2 {
        let now = h.start + TICK * i;
        udp.r2o_observe_packet_at_hook(&dns, now, hook);
        assert!(
            h.raw
                .udp(&dns, udp.raw_context(&dns).unwrap(), now)
                .is_none()
        );
    }
}
