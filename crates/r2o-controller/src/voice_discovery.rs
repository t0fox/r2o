//! Точная оценка серии Discord IP Discovery по измерениям UDP-зонда.

pub const R2O_DISCOVERY_EXCHANGES: u8 = 25;
pub const R2O_DISCOVERY_REPEATS: usize = 3;

pub fn r2o_voice_arm_plan_text(r2o_prefix: &[u8; 20]) -> String {
    let r2o_prefix_hex: String = r2o_prefix
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let r2o_id = crate::http_search::stable_id(&format!("r2o-voice-discovery:{r2o_prefix_hex}"));
    let r2o_id_hex: String = r2o_id.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "r2o-plan 1 1\nid {r2o_id_hex}\nproto udp voice\npayload 1 {r2o_prefix_hex}\npoison 1\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\norder forward\npace 15000\n"
    )
}

pub fn r2o_voice_arm_plan(r2o_prefix: &[u8; 20]) -> Result<r2k_core::plan::Plan, String> {
    let r2o_text = r2o_voice_arm_plan_text(r2o_prefix);
    let r2o_encoded = crate::plan_text::compile_text(&r2o_text)?;
    r2k_core::plan::Plan::parse(&r2o_encoded).map_err(|error| error.to_string())
}

pub fn r2o_voice_discovery_prefix_from_plan_text(r2o_text: &str) -> Option<[u8; 20]> {
    let r2o_encoded = crate::plan_text::compile_text(r2o_text).ok()?;
    let r2o_plan = r2k_core::plan::Plan::parse(&r2o_encoded).ok()?;
    let r2o_payload = r2o_plan.payloads.first()?;
    let r2o_prefix: [u8; 20] = r2o_payload.bytes.as_slice().try_into().ok()?;
    if r2o_plan.payloads.len() != 1 || !r2k_core::stun::is_binding_request(&r2o_prefix) {
        return None;
    }
    let mut r2o_expected = r2o_voice_arm_plan(&r2o_prefix).ok()?;
    r2o_expected.id = r2o_plan.id;
    (r2o_expected == r2o_plan).then_some(r2o_prefix)
}

pub fn r2o_save_confirmed_voice_binding(
    r2o_catalog: &mut crate::catalog::Catalog,
    r2o_server: std::net::Ipv4Addr,
    r2o_text: &str,
    r2o_now: i64,
) -> Result<String, String> {
    let Some(_r2o_prefix) = r2o_voice_discovery_prefix_from_plan_text(r2o_text) else {
        return Err("постоянная голосовая привязка требует подтверждённый Discovery-план".into());
    };
    let r2o_bytes = crate::plan_text::compile_text(r2o_text)?;
    let r2o_plan = r2k_core::plan::Plan::parse(&r2o_bytes).map_err(|error| error.to_string())?;
    let r2o_plan_id: String = r2o_plan
        .id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if r2o_plan_id.bytes().all(|byte| byte == b'0') {
        return Err("идентификатор Discovery-плана не может быть нулевым".into());
    }
    let r2o_target = r2o_server.to_string();
    let r2o_box_index = if let Some(r2o_index) = r2o_catalog
        .boxes
        .iter()
        .position(|r2o_box| r2o_box.plans.iter().any(|saved| saved.id == r2o_plan_id))
    {
        r2o_index
    } else {
        r2o_catalog.boxes.push(crate::catalog::BoxRecord {
            id: format!("auto-{r2o_plan_id}"),
            created: r2o_now,
            updated: r2o_now,
            ..crate::catalog::BoxRecord::default()
        });
        r2o_catalog.boxes.len() - 1
    };

    let mut r2o_prior_successes = 0_i32;
    for r2o_box in &mut r2o_catalog.boxes {
        for r2o_binding in &r2o_box.bindings {
            if r2o_binding.kind == "addr"
                && r2o_binding.target == r2o_target
                && r2o_binding.transport == 17
                && r2o_binding.family == 4
                && r2o_binding.shape == r2k_core::control::SHAPE_VOICE
                && r2o_binding.verified_by == 4
            {
                r2o_prior_successes = r2o_prior_successes.max(r2o_binding.successes);
            }
        }
        r2o_box.bindings.retain(|r2o_binding| {
            !(r2o_binding.kind == "addr"
                && r2o_binding.target == r2o_target
                && r2o_binding.transport == 17
                && r2o_binding.family == 4
                && r2o_binding.shape == r2k_core::control::SHAPE_VOICE
                && r2o_binding.verified_by == 4)
        });
    }

    let r2o_box = &mut r2o_catalog.boxes[r2o_box_index];
    if let Some(r2o_saved) = r2o_box
        .plans
        .iter_mut()
        .find(|r2o_saved| r2o_saved.id == r2o_plan_id)
    {
        r2o_saved.text = r2o_text.to_owned();
        r2o_saved.proto = "voice".into();
        r2o_saved.enabled = true;
        r2o_saved.added = r2o_now;
        r2o_saved.successes = r2o_saved.successes.saturating_add(1);
    } else {
        r2o_box.plans.push(crate::catalog::Plan {
            id: r2o_plan_id.clone(),
            proto: "voice".into(),
            text: r2o_text.to_owned(),
            added: r2o_now,
            successes: 1,
            enabled: true,
        });
    }
    r2o_box.updated = r2o_now;
    r2o_box.bindings.push(crate::catalog::Binding {
        kind: "addr".into(),
        target: r2o_target,
        plan_id: r2o_plan_id.clone(),
        level: 3,
        confirmed: r2o_now,
        successes: r2o_prior_successes.saturating_add(1),
        enabled: true,
        transport: 17,
        family: 4,
        shape: r2k_core::control::SHAPE_VOICE,
        verified_by: 4,
        input: 2,
        ..crate::catalog::Binding::default()
    });
    Ok(r2o_plan_id)
}

pub fn r2o_build_ipv4_udp_template(
    r2o_client: std::net::Ipv4Addr,
    r2o_client_port: u16,
    r2o_server: std::net::SocketAddrV4,
    r2o_ip_id: u16,
    r2o_ttl: u8,
    r2o_payload: &[u8],
) -> Option<Vec<u8>> {
    let r2o_udp_len = 8_usize.checked_add(r2o_payload.len())?;
    let r2o_packet_len = 20_usize.checked_add(r2o_udp_len)?;
    if r2o_client_port == 0
        || r2o_server.port() == 0
        || r2o_ip_id == 0
        || r2o_ttl == 0
        || r2o_udp_len > usize::from(u16::MAX)
        || r2o_packet_len > usize::from(u16::MAX)
    {
        return None;
    }

    let mut r2o_packet = vec![0; r2o_packet_len];
    r2o_packet[0] = 0x45;
    r2o_packet[2..4].copy_from_slice(&(r2o_packet_len as u16).to_be_bytes());
    r2o_packet[4..6].copy_from_slice(&r2o_ip_id.to_be_bytes());
    r2o_packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    r2o_packet[8] = r2o_ttl;
    r2o_packet[9] = 17;
    r2o_packet[12..16].copy_from_slice(&r2o_client.octets());
    r2o_packet[16..20].copy_from_slice(&r2o_server.ip().octets());
    r2o_packet[20..22].copy_from_slice(&r2o_client_port.to_be_bytes());
    r2o_packet[22..24].copy_from_slice(&r2o_server.port().to_be_bytes());
    r2o_packet[24..26].copy_from_slice(&(r2o_udp_len as u16).to_be_bytes());
    r2o_packet[28..].copy_from_slice(r2o_payload);
    Some(r2o_packet)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct R2oDiscoveryProbe {
    pub sent: u8,
    pub received: u8,
    pub local_error: bool,
    pub marked: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oDiscoveryProbeOutcome {
    pub probe: R2oDiscoveryProbe,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oDiscoverySearchResult {
    pub trace: R2oDiscoveryTrace,
    pub verdict: R2oDiscoveryVerdict,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct R2oVoiceTarget {
    pub client: std::net::Ipv4Addr,
    pub server: std::net::SocketAddrV4,
}

pub fn r2o_voice_target_from_event(
    r2o_event: &r2k_core::control::R2oVoiceSuspectEvent,
) -> Option<R2oVoiceTarget> {
    let r2o_key = &r2o_event.key;
    if r2o_key[0] != 4 || r2o_key[37] != 17 {
        return None;
    }
    let r2o_low_ip = std::net::Ipv4Addr::new(r2o_key[1], r2o_key[2], r2o_key[3], r2o_key[4]);
    let r2o_high_ip = std::net::Ipv4Addr::new(r2o_key[17], r2o_key[18], r2o_key[19], r2o_key[20]);
    let r2o_low_port = u16::from_be_bytes([r2o_key[33], r2o_key[34]]);
    let r2o_high_port = u16::from_be_bytes([r2o_key[35], r2o_key[36]]);
    if r2o_low_port == 0 || r2o_high_port == 0 {
        return None;
    }
    let (r2o_client, r2o_server_ip, r2o_server_port) = if r2o_event.client_is_low {
        (r2o_low_ip, r2o_high_ip, r2o_high_port)
    } else {
        (r2o_high_ip, r2o_low_ip, r2o_low_port)
    };
    Some(R2oVoiceTarget {
        client: r2o_client,
        server: std::net::SocketAddrV4::new(r2o_server_ip, r2o_server_port),
    })
}

#[cfg(target_os = "linux")]
fn r2o_search_discovery_with<F, P>(
    r2o_known_prefix: Option<[u8; 20]>,
    mut r2o_make_prefix: P,
    mut r2o_probe: F,
) -> R2oDiscoverySearchResult
where
    F: FnMut(Option<&[u8; 20]>) -> R2oDiscoveryProbeOutcome,
    P: FnMut() -> Result<[u8; 20], String>,
{
    let mut r2o_trace = R2oDiscoveryTrace {
        known_prefix: r2o_known_prefix,
        known_prefix_probe: None,
        direct_probes: Vec::new(),
        candidate_prefix: None,
        candidate_probes: Vec::new(),
    };

    if let Some(r2o_prefix) = r2o_known_prefix {
        let r2o_outcome = r2o_probe(Some(&r2o_prefix));
        r2o_trace.known_prefix_probe = Some(r2o_outcome.probe);
        if r2o_outcome.error.is_some() || r2o_outcome.probe.local_error {
            return R2oDiscoverySearchResult {
                trace: r2o_trace,
                verdict: R2oDiscoveryVerdict::Unmeasured,
                error: r2o_outcome.error,
            };
        }
        if !r2o_probe_shape_is_valid(r2o_outcome.probe) || !r2o_outcome.probe.marked {
            return R2oDiscoverySearchResult {
                trace: r2o_trace,
                verdict: R2oDiscoveryVerdict::Unmeasured,
                error: None,
            };
        }
        if r2o_outcome.probe.sent == R2O_DISCOVERY_EXCHANGES
            && r2o_outcome.probe.received == R2O_DISCOVERY_EXCHANGES
        {
            return R2oDiscoverySearchResult {
                trace: r2o_trace,
                verdict: R2oDiscoveryVerdict::Clear,
                error: None,
            };
        }
    }

    for _ in 0..R2O_DISCOVERY_REPEATS {
        let r2o_outcome = r2o_probe(None);
        r2o_trace.direct_probes.push(r2o_outcome.probe);
        if r2o_outcome.error.is_some() || r2o_outcome.probe.local_error {
            return R2oDiscoverySearchResult {
                trace: r2o_trace,
                verdict: R2oDiscoveryVerdict::Unmeasured,
                error: r2o_outcome.error,
            };
        }
        if !r2o_probe_shape_is_valid(r2o_outcome.probe) || !r2o_outcome.probe.marked {
            return R2oDiscoverySearchResult {
                trace: r2o_trace,
                verdict: R2oDiscoveryVerdict::Unmeasured,
                error: None,
            };
        }
        if r2o_outcome.probe.received == 0 {
            return R2oDiscoverySearchResult {
                trace: r2o_trace,
                verdict: R2oDiscoveryVerdict::Continue,
                error: None,
            };
        }
        if r2o_outcome.probe.sent == R2O_DISCOVERY_EXCHANGES
            && r2o_outcome.probe.received == R2O_DISCOVERY_EXCHANGES
        {
            return R2oDiscoverySearchResult {
                trace: r2o_trace,
                verdict: R2oDiscoveryVerdict::Clear,
                error: None,
            };
        }
    }

    let Some(r2o_first) = r2o_trace.direct_probes.first().copied() else {
        unreachable!("три прямых зонда уже выполнены")
    };
    let r2o_cutoff = r2o_first.received;
    if r2o_trace.direct_probes.iter().any(|r2o_probe| {
        r2o_probe.received != r2o_cutoff || r2o_cutoff.checked_add(1) != Some(r2o_probe.sent)
    }) {
        return R2oDiscoverySearchResult {
            trace: r2o_trace,
            verdict: R2oDiscoveryVerdict::Flaky,
            error: None,
        };
    }

    let r2o_prefix = match r2o_make_prefix() {
        Ok(r2o_prefix) if r2k_core::stun::is_binding_request(&r2o_prefix) => r2o_prefix,
        Ok(_) => {
            return R2oDiscoverySearchResult {
                trace: r2o_trace,
                verdict: R2oDiscoveryVerdict::Unmeasured,
                error: Some("генератор вернул неверный STUN Binding Request".into()),
            };
        }
        Err(r2o_error) => {
            return R2oDiscoverySearchResult {
                trace: r2o_trace,
                verdict: R2oDiscoveryVerdict::Unmeasured,
                error: Some(r2o_error),
            };
        }
    };
    r2o_trace.candidate_prefix = Some(r2o_prefix);
    for _ in 0..R2O_DISCOVERY_REPEATS {
        let r2o_outcome = r2o_probe(Some(&r2o_prefix));
        r2o_trace.candidate_probes.push(r2o_outcome.probe);
        if r2o_outcome.error.is_some() || r2o_outcome.probe.local_error {
            return R2oDiscoverySearchResult {
                trace: r2o_trace,
                verdict: R2oDiscoveryVerdict::Unmeasured,
                error: r2o_outcome.error,
            };
        }
        if !r2o_probe_shape_is_valid(r2o_outcome.probe) || !r2o_outcome.probe.marked {
            return R2oDiscoverySearchResult {
                trace: r2o_trace,
                verdict: R2oDiscoveryVerdict::Unmeasured,
                error: None,
            };
        }
        if r2o_outcome.probe.sent != R2O_DISCOVERY_EXCHANGES
            || r2o_outcome.probe.received != R2O_DISCOVERY_EXCHANGES
        {
            return R2oDiscoverySearchResult {
                trace: r2o_trace,
                verdict: R2oDiscoveryVerdict::Unmeasured,
                error: None,
            };
        }
    }

    R2oDiscoverySearchResult {
        verdict: evaluate_r2o_discovery(&r2o_trace),
        trace: r2o_trace,
        error: None,
    }
}

#[cfg(target_os = "linux")]
fn r2o_probe_shape_is_valid(r2o_probe: R2oDiscoveryProbe) -> bool {
    r2o_probe.sent != 0
        && r2o_probe.sent <= R2O_DISCOVERY_EXCHANGES
        && r2o_probe.received <= r2o_probe.sent
        && (r2o_probe.received == R2O_DISCOVERY_EXCHANGES
            || r2o_probe.sent == r2o_probe.received.saturating_add(1))
}

#[cfg(target_os = "linux")]
pub fn r2o_search_discovery_endpoint(
    r2o_server: std::net::SocketAddrV4,
    r2o_known_prefix: Option<[u8; 20]>,
    r2o_wait: std::time::Duration,
    r2o_mark: Option<u32>,
) -> R2oDiscoverySearchResult {
    if r2o_mark.is_none_or(|r2o_mark| r2o_mark == 0) {
        return R2oDiscoverySearchResult {
            trace: R2oDiscoveryTrace {
                known_prefix: r2o_known_prefix,
                known_prefix_probe: None,
                direct_probes: Vec::new(),
                candidate_prefix: None,
                candidate_probes: Vec::new(),
            },
            verdict: R2oDiscoveryVerdict::Unmeasured,
            error: Some("автоматический поиск требует ненулевую метку маршрутизации".into()),
        };
    }
    r2o_search_discovery_with(
        r2o_known_prefix,
        || {
            use std::io::Read;
            let mut r2o_txid = [0; 12];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut r2o_random| r2o_random.read_exact(&mut r2o_txid))
                .map_err(|error| format!("не получить случайный STUN ID: {error}"))?;
            Ok(r2k_core::stun::binding_request(r2o_txid))
        },
        |r2o_prefix| r2o_probe_discovery_endpoint(r2o_server, r2o_prefix, r2o_wait, r2o_mark),
    )
}

#[cfg(target_os = "linux")]
pub fn r2o_probe_discovery_endpoint(
    r2o_server: std::net::SocketAddrV4,
    r2o_prefix: Option<&[u8; 20]>,
    r2o_wait: std::time::Duration,
    r2o_mark: Option<u32>,
) -> R2oDiscoveryProbeOutcome {
    use std::io::Read;
    use std::net::{SocketAddr, UdpSocket};
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    let mut r2o_probe = R2oDiscoveryProbe {
        marked: r2o_mark.is_some_and(|mark| mark != 0),
        ..R2oDiscoveryProbe::default()
    };
    let r2o_result = (|| -> Result<(), String> {
        if r2o_server.port() == 0
            || r2o_server.ip().is_unspecified()
            || r2o_server.ip().is_multicast()
        {
            return Err("адрес Discord Discovery некорректен".into());
        }
        if r2o_prefix.is_some() && !r2o_probe.marked {
            return Err("кандидатный зонд требует подтверждённую ненулевую метку".into());
        }
        if let Some(r2o_mark) = r2o_mark
            && r2o_mark == 0
        {
            return Err("метка зонда должна быть ненулевой".into());
        }

        let r2o_socket = UdpSocket::bind(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        ))
        .map_err(|error| format!("не открыть UDP-сокет Discovery: {error}"))?;
        if let Some(r2o_mark) = r2o_mark {
            r2o_set_socket_mark(r2o_socket.as_raw_fd(), r2o_mark)
                .map_err(|error| format!("не подтвердить метку UDP-сокета: {error}"))?;
        }
        r2o_socket
            .connect(SocketAddr::V4(r2o_server))
            .map_err(|error| format!("не подключить UDP-сокет Discovery: {error}"))?;
        let r2o_local = match r2o_socket
            .local_addr()
            .map_err(|error| format!("не прочитать локальный UDP-адрес: {error}"))?
        {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => return Err("UDP-сокет Discovery выбрал не IPv4".into()),
        };
        let r2o_sender = match (r2o_prefix, r2o_mark) {
            (Some(_), Some(mark)) => Some(
                r2o_datapath::raw::RawSocket::open(libc::AF_INET, mark, None).map_err(|error| {
                    format!("не открыть отмеченный raw-сокет Discovery: {error}")
                })?,
            ),
            (Some(_), None) => return Err("кандидатный зонд требует ненулевую метку".into()),
            (None, _) => None,
        };
        let mut r2o_random = std::fs::File::open("/dev/urandom")
            .map_err(|error| format!("не открыть источник случайных ID: {error}"))?;
        let r2o_wait = if r2o_wait.is_zero() {
            Duration::from_secs(3)
        } else {
            r2o_wait
        };

        for r2o_index in 0..R2O_DISCOVERY_EXCHANGES {
            let mut r2o_txid = [0; 12];
            r2o_random
                .read_exact(&mut r2o_txid)
                .map_err(|error| format!("не получить случайный SSRC Discovery: {error}"))?;
            let mut r2o_request = [0; 74];
            r2o_request[..4].copy_from_slice(&[0, 1, 0, 70]);
            r2o_request[4..8].copy_from_slice(&r2o_txid[..4]);

            if r2o_index == 0
                && let (Some(r2o_prefix), Some(r2o_sender)) = (r2o_prefix, r2o_sender.as_ref())
            {
                let r2o_input = r2o_build_ipv4_udp_template(
                    *r2o_local.ip(),
                    r2o_local.port(),
                    r2o_server,
                    1,
                    64,
                    &r2o_request,
                )
                .ok_or_else(|| "не собрать UDP-пакет Discord Discovery".to_owned())?;
                let r2o_plan = r2o_voice_arm_plan(r2o_prefix)?;
                let r2o_packets = match r2o_datapath::engine::decide(&r2o_plan, &r2o_input) {
                    r2o_datapath::engine::PacketDecision::Transmit { packets, .. }
                        if packets.len() == 2 =>
                    {
                        packets
                    }
                    _ => return Err("R2O-движок не сформировал пару Discord Discovery".into()),
                };
                for r2o_packet in r2o_packets {
                    if r2o_packet.delay_us != 0 {
                        std::thread::sleep(Duration::from_micros(u64::from(r2o_packet.delay_us)));
                    }
                    r2o_sender
                        .send_packet(&r2o_packet.packet)
                        .map_err(|error| format!("не отправить Discord Discovery: {error}"))?;
                }
            } else {
                let r2o_sent = r2o_socket
                    .send(&r2o_request)
                    .map_err(|error| format!("не отправить UDP-запрос Discovery: {error}"))?;
                if r2o_sent != r2o_request.len() {
                    return Err("UDP-сокет Discovery отправил неполный запрос".into());
                }
            }
            r2o_probe.sent = r2o_probe.sent.saturating_add(1);

            let r2o_deadline = Instant::now() + r2o_wait;
            let mut r2o_answered = false;
            let mut r2o_reply = [0; 2048];
            while Instant::now() < r2o_deadline {
                let r2o_remaining = r2o_deadline.saturating_duration_since(Instant::now());
                let r2o_timeout = r2o_remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
                let mut r2o_pollfd = libc::pollfd {
                    fd: r2o_socket.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let r2o_ready = unsafe { libc::poll(&mut r2o_pollfd, 1, r2o_timeout) };
                if r2o_ready == 0 {
                    break;
                }
                if r2o_ready < 0 {
                    let r2o_error = std::io::Error::last_os_error();
                    if r2o_error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(format!("ошибка ожидания UDP-ответа Discovery: {r2o_error}"));
                }
                if r2o_pollfd.revents & libc::POLLIN == 0 {
                    return Err("UDP-сокет Discovery завершил ожидание с ошибкой".into());
                }
                let r2o_received = match r2o_socket.recv(&mut r2o_reply) {
                    Ok(length) => length,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(format!("не прочитать UDP-ответ Discovery: {error}")),
                };
                if r2k_core::stun::is_discord_ip_discovery_response(
                    &r2o_reply[..r2o_received],
                    &r2o_request[4..8]
                        .try_into()
                        .expect("SSRC Discovery имеет 4 байта"),
                ) {
                    r2o_answered = true;
                    break;
                }
            }
            if !r2o_answered {
                break;
            }
            r2o_probe.received = r2o_probe.received.saturating_add(1);
        }
        Ok(())
    })();

    let error = r2o_result.err();
    r2o_probe.local_error = error.is_some();
    R2oDiscoveryProbeOutcome {
        probe: r2o_probe,
        error,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn r2o_set_socket_mark(
    r2o_fd: std::os::fd::RawFd,
    r2o_mark: u32,
) -> std::io::Result<()> {
    let r2o_set = unsafe {
        libc::setsockopt(
            r2o_fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&r2o_mark as *const u32).cast(),
            std::mem::size_of_val(&r2o_mark) as libc::socklen_t,
        )
    };
    if r2o_set != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut r2o_confirmed = 0_u32;
    let mut r2o_length = std::mem::size_of_val(&r2o_confirmed) as libc::socklen_t;
    let r2o_get = unsafe {
        libc::getsockopt(
            r2o_fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mut r2o_confirmed as *mut u32).cast(),
            &mut r2o_length,
        )
    };
    if r2o_get != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if r2o_length as usize != std::mem::size_of_val(&r2o_confirmed) || r2o_confirmed != r2o_mark {
        return Err(std::io::Error::other(
            "прочитанная SO_MARK не совпадает с заданной",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oDiscoveryTrace {
    pub known_prefix: Option<[u8; 20]>,
    pub known_prefix_probe: Option<R2oDiscoveryProbe>,
    pub direct_probes: Vec<R2oDiscoveryProbe>,
    pub candidate_prefix: Option<[u8; 20]>,
    pub candidate_probes: Vec<R2oDiscoveryProbe>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum R2oDiscoveryVerdict {
    Continue,
    Clear,
    Flaky,
    Unmeasured,
    Blocked { prefix: [u8; 20], cutoff: u8 },
}

/// Оценить последовательность зондов по правилам исходного UDP Discovery.
pub fn evaluate_r2o_discovery(r2o_trace: &R2oDiscoveryTrace) -> R2oDiscoveryVerdict {
    if r2o_trace.known_prefix.is_some() {
        let Some(r2o_probe) = r2o_trace.known_prefix_probe else {
            return R2oDiscoveryVerdict::Unmeasured;
        };
        if r2o_probe.local_error || !r2o_probe.marked {
            return R2oDiscoveryVerdict::Unmeasured;
        }
        if r2o_probe.received == R2O_DISCOVERY_EXCHANGES {
            return R2oDiscoveryVerdict::Clear;
        }
    }

    let Some(r2o_first) = r2o_trace.direct_probes.first().copied() else {
        return R2oDiscoveryVerdict::Unmeasured;
    };
    if r2o_first.local_error || !r2o_first.marked {
        return R2oDiscoveryVerdict::Unmeasured;
    }
    if r2o_first.received == 0 {
        return R2oDiscoveryVerdict::Continue;
    }
    if r2o_first.received == R2O_DISCOVERY_EXCHANGES {
        return R2oDiscoveryVerdict::Clear;
    }

    let r2o_cutoff = r2o_first.received;
    for r2o_index in 0..R2O_DISCOVERY_REPEATS {
        let Some(r2o_probe) = r2o_trace.direct_probes.get(r2o_index).copied() else {
            return R2oDiscoveryVerdict::Unmeasured;
        };
        if r2o_probe.local_error || !r2o_probe.marked {
            return R2oDiscoveryVerdict::Unmeasured;
        }
        if r2o_cutoff == 0
            || r2o_probe.received != r2o_cutoff
            || r2o_cutoff.checked_add(1) != Some(r2o_probe.sent)
        {
            return R2oDiscoveryVerdict::Flaky;
        }
    }

    let Some(r2o_prefix) = r2o_trace.candidate_prefix else {
        return R2oDiscoveryVerdict::Unmeasured;
    };
    for r2o_index in 0..R2O_DISCOVERY_REPEATS {
        let Some(r2o_probe) = r2o_trace.candidate_probes.get(r2o_index).copied() else {
            return R2oDiscoveryVerdict::Unmeasured;
        };
        if r2o_probe.local_error || !r2o_probe.marked {
            return R2oDiscoveryVerdict::Unmeasured;
        }
        if r2o_probe.received != R2O_DISCOVERY_EXCHANGES {
            return R2oDiscoveryVerdict::Unmeasured;
        }
    }

    R2oDiscoveryVerdict::Blocked {
        prefix: r2o_prefix,
        cutoff: r2o_cutoff,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        R2O_DISCOVERY_EXCHANGES, R2O_DISCOVERY_REPEATS, R2oDiscoveryProbe, R2oDiscoveryTrace,
        R2oDiscoveryVerdict, evaluate_r2o_discovery, r2o_build_ipv4_udp_template,
        r2o_voice_arm_plan, r2o_voice_target_from_event,
    };

    fn r2o_probe(r2o_sent: u8, r2o_received: u8) -> R2oDiscoveryProbe {
        R2oDiscoveryProbe {
            sent: r2o_sent,
            received: r2o_received,
            local_error: false,
            marked: true,
        }
    }

    fn r2o_trace(r2o_direct_cutoff: u8) -> R2oDiscoveryTrace {
        R2oDiscoveryTrace {
            known_prefix: None,
            known_prefix_probe: None,
            direct_probes: vec![
                r2o_probe(r2o_direct_cutoff + 1, r2o_direct_cutoff);
                R2O_DISCOVERY_REPEATS
            ],
            candidate_prefix: Some([0x5a; 20]),
            candidate_probes: vec![
                r2o_probe(R2O_DISCOVERY_EXCHANGES, R2O_DISCOVERY_EXCHANGES);
                R2O_DISCOVERY_REPEATS
            ],
        }
    }

    #[test]
    fn r2o_устойчивая_граница_и_три_полных_прогона_подтверждают_кандидат() {
        assert_eq!(
            evaluate_r2o_discovery(&r2o_trace(12)),
            R2oDiscoveryVerdict::Blocked {
                prefix: [0x5a; 20],
                cutoff: 12,
            }
        );
    }

    #[test]
    fn r2o_первый_прямой_прогон_без_ответов_оставляет_старый_путь() {
        let mut r2o_evidence = r2o_trace(12);
        r2o_evidence.direct_probes[0] = r2o_probe(1, 0);
        assert_eq!(
            evaluate_r2o_discovery(&r2o_evidence),
            R2oDiscoveryVerdict::Continue
        );
    }

    #[test]
    fn r2o_полная_прямая_серия_не_запускает_подбор() {
        let mut r2o_evidence = r2o_trace(12);
        r2o_evidence.direct_probes[0] = r2o_probe(R2O_DISCOVERY_EXCHANGES, R2O_DISCOVERY_EXCHANGES);
        assert_eq!(
            evaluate_r2o_discovery(&r2o_evidence),
            R2oDiscoveryVerdict::Clear
        );
    }

    #[test]
    fn r2o_неповторяемая_граница_не_ставит_кандидат() {
        let mut r2o_evidence = r2o_trace(12);
        r2o_evidence.direct_probes[2] = r2o_probe(14, 13);
        assert_eq!(
            evaluate_r2o_discovery(&r2o_evidence),
            R2oDiscoveryVerdict::Flaky
        );
    }

    #[test]
    fn r2o_неподтверждённая_метка_делает_измерение_неопределённым() {
        let mut r2o_evidence = r2o_trace(12);
        r2o_evidence.direct_probes[1].marked = false;
        assert_eq!(
            evaluate_r2o_discovery(&r2o_evidence),
            R2oDiscoveryVerdict::Unmeasured
        );
    }

    #[test]
    fn r2o_неполная_серия_кандидата_не_создаёт_план() {
        let mut r2o_evidence = r2o_trace(12);
        r2o_evidence.candidate_probes[2] = r2o_probe(14, 13);
        assert_eq!(
            evaluate_r2o_discovery(&r2o_evidence),
            R2oDiscoveryVerdict::Unmeasured
        );
    }

    #[test]
    fn r2o_подтверждённый_известный_префикс_останавливает_поиск() {
        let mut r2o_evidence = r2o_trace(12);
        r2o_evidence.known_prefix = Some([0x33; 20]);
        r2o_evidence.known_prefix_probe =
            Some(r2o_probe(R2O_DISCOVERY_EXCHANGES, R2O_DISCOVERY_EXCHANGES));
        assert_eq!(
            evaluate_r2o_discovery(&r2o_evidence),
            R2oDiscoveryVerdict::Clear
        );
    }

    #[test]
    fn r2o_ошибка_известного_префикса_не_маскируется_следующими_прогонами() {
        let mut r2o_evidence = r2o_trace(12);
        r2o_evidence.known_prefix = Some([0x33; 20]);
        let mut r2o_probe_result = r2o_probe(1, 0);
        r2o_probe_result.local_error = true;
        r2o_evidence.known_prefix_probe = Some(r2o_probe_result);
        assert_eq!(
            evaluate_r2o_discovery(&r2o_evidence),
            R2oDiscoveryVerdict::Unmeasured
        );
    }

    #[test]
    fn r2o_событие_подозрения_даёт_клиента_и_точку_сервера() {
        use r2k_core::control::R2oVoiceSuspectEvent;
        use std::net::{Ipv4Addr, SocketAddrV4};

        let mut r2o_key = [0; r2k_core::control::KEY_LEN];
        r2o_key[0] = 4;
        r2o_key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        r2o_key[17..21].copy_from_slice(&[198, 51, 100, 20]);
        r2o_key[33..35].copy_from_slice(&50_000_u16.to_be_bytes());
        r2o_key[35..37].copy_from_slice(&50_004_u16.to_be_bytes());
        r2o_key[37] = 17;

        let r2o_target = r2o_voice_target_from_event(&R2oVoiceSuspectEvent {
            key: r2o_key,
            client_is_low: true,
        })
        .unwrap();

        assert_eq!(r2o_target.client, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(
            r2o_target.server,
            SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 50_004)
        );
    }

    #[test]
    fn r2o_повторное_подключение_того_же_клиента_не_меняет_контекст_цели() {
        use r2k_core::control::R2oVoiceSuspectEvent;
        use std::net::{Ipv4Addr, SocketAddrV4};

        let mut r2o_key = [0; r2k_core::control::KEY_LEN];
        r2o_key[0] = 4;
        r2o_key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        r2o_key[17..21].copy_from_slice(&[198, 51, 100, 20]);
        r2o_key[33..35].copy_from_slice(&50_000_u16.to_be_bytes());
        r2o_key[35..37].copy_from_slice(&50_004_u16.to_be_bytes());
        r2o_key[37] = 17;

        let first = r2o_voice_target_from_event(&R2oVoiceSuspectEvent {
            key: r2o_key,
            client_is_low: true,
        })
        .unwrap();
        assert_eq!(
            first.server,
            SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 50_004)
        );

        r2o_key[33..35].copy_from_slice(&50_001_u16.to_be_bytes());
        let reconnected = r2o_voice_target_from_event(&R2oVoiceSuspectEvent {
            key: r2o_key,
            client_is_low: true,
        })
        .unwrap();

        assert_eq!(reconnected, first);
    }

    #[test]
    fn r2o_событие_с_нулевым_портом_не_становится_сетевой_целью() {
        use r2k_core::control::R2oVoiceSuspectEvent;

        let mut r2o_key = [0; r2k_core::control::KEY_LEN];
        r2o_key[0] = 4;
        r2o_key[1..5].copy_from_slice(&[192, 0, 2, 10]);
        r2o_key[17..21].copy_from_slice(&[198, 51, 100, 20]);
        r2o_key[33..35].copy_from_slice(&50_000_u16.to_be_bytes());
        r2o_key[37] = 17;
        assert!(
            r2o_voice_target_from_event(&R2oVoiceSuspectEvent {
                key: r2o_key,
                client_is_low: true,
            })
            .is_none()
        );
    }

    #[test]
    fn r2o_план_ставит_один_stun_пакет_перед_discovery_с_выдержкой() {
        use r2k_core::packet::PacketView;
        use r2k_core::plan::EmitKind;
        use std::net::{Ipv4Addr, SocketAddrV4};

        let r2o_prefix = r2k_core::stun::binding_request([0x81; 12]);
        let r2o_plan = r2o_voice_arm_plan(&r2o_prefix).unwrap();
        let r2o_request = [
            0, 1, 0, 70, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let r2o_input = r2o_build_ipv4_udp_template(
            Ipv4Addr::new(192, 0, 2, 10),
            43_210,
            SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 50_012),
            0x1234,
            64,
            &r2o_request,
        )
        .unwrap();

        match r2o_datapath::engine::decide(&r2o_plan, &r2o_input) {
            r2o_datapath::engine::PacketDecision::Transmit { packets, .. } => {
                assert_eq!(packets.len(), 2);
                assert_eq!(packets[0].kind, EmitKind::Fake);
                assert_eq!(packets[0].delay_us, 0);
                assert_eq!(packets[1].kind, EmitKind::Payload);
                assert_eq!(packets[1].delay_us, 15_000);
                let r2o_fake_view = PacketView::parse(&packets[0].packet).unwrap();
                let r2o_fake_range = r2o_fake_view.udp_payload_range(&packets[0].packet).unwrap();
                assert_eq!(&packets[0].packet[r2o_fake_range], r2o_prefix);
                let r2o_real_view = PacketView::parse(&packets[1].packet).unwrap();
                let r2o_real_range = r2o_real_view.udp_payload_range(&packets[1].packet).unwrap();
                assert_eq!(&packets[1].packet[r2o_real_range], r2o_request);
            }
            other => panic!("ожидались две UDP-посылки: {other:?}"),
        }
    }

    #[test]
    fn r2o_узнаёт_только_точный_план_подтверждённого_voice_discovery() {
        let r2o_prefix = r2k_core::stun::binding_request([0x91; 12]);
        let r2o_text = super::r2o_voice_arm_plan_text(&r2o_prefix);
        assert_eq!(
            super::r2o_voice_discovery_prefix_from_plan_text(&r2o_text),
            Some(r2o_prefix)
        );
        assert!(
            super::r2o_voice_discovery_prefix_from_plan_text(
                &r2o_text.replace("pace 15000", "pace 14999")
            )
            .is_none()
        );
    }

    #[test]
    fn r2o_сохраняет_подтверждённый_voice_план_как_адресную_привязку() {
        let r2o_prefix = r2k_core::stun::binding_request([0x92; 12]);
        let r2o_text = super::r2o_voice_arm_plan_text(&r2o_prefix);
        let mut r2o_catalog = crate::catalog::Catalog::default();
        let r2o_plan_id = super::r2o_save_confirmed_voice_binding(
            &mut r2o_catalog,
            "198.51.100.20".parse().unwrap(),
            &r2o_text,
            1_800_000_000,
        )
        .unwrap();
        assert!(!r2o_plan_id.bytes().all(|byte| byte == b'0'));

        let r2o_json = r2o_catalog.to_json_at(1_800_000_000).unwrap();
        let r2o_reloaded = crate::catalog::Catalog::parse(r2o_json.as_bytes()).unwrap();
        let r2o_binding = &r2o_reloaded.boxes[0].bindings[0];
        assert_eq!(r2o_binding.kind, "addr");
        assert_eq!(r2o_binding.target, "198.51.100.20");
        assert_eq!(r2o_binding.transport, 17);
        assert_eq!(r2o_binding.family, 4);
        assert_eq!(r2o_binding.shape, r2k_core::control::SHAPE_VOICE);
        assert_eq!(r2o_binding.verified_by, 4);
        assert_eq!(r2o_binding.plan_id, r2o_plan_id);
        assert_eq!(
            super::r2o_voice_discovery_prefix_from_plan_text(&r2o_reloaded.boxes[0].plans[0].text),
            Some(r2o_prefix)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn r2o_зонд_считает_только_ответы_с_совпавшим_ssrc() {
        use super::r2o_probe_discovery_endpoint;
        use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
        use std::thread;
        use std::time::Duration;

        let r2o_server = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        r2o_server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let r2o_address = match r2o_server.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let r2o_server_thread = thread::spawn(move || {
            let mut r2o_request = [0; 128];
            let mut r2o_received = 0;
            for _ in 0..usize::from(R2O_DISCOVERY_EXCHANGES) {
                let Ok((r2o_length, r2o_peer)) = r2o_server.recv_from(&mut r2o_request) else {
                    break;
                };
                if r2o_length != 74 {
                    continue;
                }
                let mut r2o_response = [0; 74];
                r2o_response[..8].copy_from_slice(&[
                    0,
                    2,
                    0,
                    70,
                    r2o_request[4],
                    r2o_request[5],
                    r2o_request[6],
                    r2o_request[7],
                ]);
                r2o_response[8..19].copy_from_slice(b"203.0.113.7");
                r2o_response[72..74].copy_from_slice(&50_001_u16.to_be_bytes());
                r2o_server.send_to(&r2o_response, r2o_peer).unwrap();
                r2o_received += 1;
            }
            r2o_received
        });

        let r2o_result =
            r2o_probe_discovery_endpoint(r2o_address, None, Duration::from_millis(100), None);

        let r2o_responses = r2o_server_thread.join().unwrap();
        assert_eq!(r2o_result.error, None);
        assert_eq!(r2o_responses, usize::from(R2O_DISCOVERY_EXCHANGES));
        assert_eq!(r2o_result.probe.sent, R2O_DISCOVERY_EXCHANGES);
        assert_eq!(r2o_result.probe.received, R2O_DISCOVERY_EXCHANGES);
        assert!(!r2o_result.probe.marked);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "требуется Linux с CAP_NET_RAW и CAP_NET_ADMIN"]
    fn r2o_отмеченный_raw_зонд_проходит_прямые_обрывы_и_проверяет_три_кандидата() {
        use super::{R2O_DISCOVERY_EXCHANGES, R2oDiscoveryVerdict, r2o_search_discovery_endpoint};
        use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
        use std::thread;
        use std::time::Duration;

        let r2o_server = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        r2o_server
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let r2o_address = match r2o_server.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        };
        let r2o_server_thread = thread::spawn(move || {
            let mut r2o_data = [0; 2048];
            let mut r2o_direct = 0_u8;
            let mut r2o_candidate = 0_u8;
            let mut r2o_candidate_phase = false;
            while r2o_direct < 39 || r2o_candidate < 3 * R2O_DISCOVERY_EXCHANGES {
                let (r2o_length, r2o_peer) = r2o_server.recv_from(&mut r2o_data).unwrap();
                let r2o_request = &r2o_data[..r2o_length];
                if r2o_request.len() == 20 && r2k_core::stun::is_binding_request(r2o_request) {
                    r2o_candidate_phase = true;
                    continue;
                }
                if r2o_request.len() != 74 || r2o_request[..4] != [0, 1, 0, 70] {
                    continue;
                }
                let r2o_should_answer = if r2o_candidate_phase {
                    r2o_candidate += 1;
                    true
                } else {
                    let r2o_position = r2o_direct % 13;
                    r2o_direct += 1;
                    r2o_position < 12
                };
                if !r2o_should_answer {
                    continue;
                }
                let mut r2o_response = [0; 74];
                r2o_response[..8].copy_from_slice(&[
                    0,
                    2,
                    0,
                    70,
                    r2o_request[4],
                    r2o_request[5],
                    r2o_request[6],
                    r2o_request[7],
                ]);
                r2o_response[8..19].copy_from_slice(b"203.0.113.1");
                r2o_response[72..74].copy_from_slice(&52_323_u16.to_be_bytes());
                r2o_server.send_to(&r2o_response, r2o_peer).unwrap();
            }
            (r2o_direct, r2o_candidate)
        });

        let r2o_result = r2o_search_discovery_endpoint(
            r2o_address,
            None,
            Duration::from_millis(250),
            Some(0x5252_4f01),
        );
        let (r2o_direct, r2o_candidates) = r2o_server_thread.join().unwrap();
        assert_eq!(r2o_direct, 39);
        assert_eq!(r2o_candidates, 3 * R2O_DISCOVERY_EXCHANGES);
        assert_eq!(
            r2o_result.verdict,
            R2oDiscoveryVerdict::Blocked {
                prefix: r2o_result.trace.candidate_prefix.unwrap(),
                cutoff: 12,
            }
        );
        assert!(
            r2o_result
                .trace
                .direct_probes
                .iter()
                .all(|probe| probe.marked)
        );
        assert!(
            r2o_result
                .trace
                .candidate_probes
                .iter()
                .all(|probe| probe.marked && probe.received == R2O_DISCOVERY_EXCHANGES)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn r2o_поиск_подтверждает_три_обрыва_и_три_полных_прогона() {
        use super::{R2oDiscoveryProbeOutcome, R2oDiscoveryVerdict, r2o_search_discovery_with};

        let r2o_prefix = r2k_core::stun::binding_request([0x55; 12]);
        let mut r2o_calls = 0;
        let r2o_result = r2o_search_discovery_with(
            None,
            || Ok(r2o_prefix),
            |r2o_candidate| {
                r2o_calls += 1;
                let r2o_probe = if r2o_candidate.is_some() {
                    r2o_probe(R2O_DISCOVERY_EXCHANGES, R2O_DISCOVERY_EXCHANGES)
                } else {
                    r2o_probe(13, 12)
                };
                R2oDiscoveryProbeOutcome {
                    probe: r2o_probe,
                    error: None,
                }
            },
        );

        assert_eq!(r2o_calls, 6);
        assert_eq!(r2o_result.trace.direct_probes.len(), R2O_DISCOVERY_REPEATS);
        assert_eq!(
            r2o_result.trace.candidate_probes.len(),
            R2O_DISCOVERY_REPEATS
        );
        assert_eq!(
            r2o_result.verdict,
            R2oDiscoveryVerdict::Blocked {
                prefix: r2o_prefix,
                cutoff: 12,
            }
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn r2o_известный_префикс_останавливает_поиск_после_полной_серии() {
        use super::{R2oDiscoveryProbeOutcome, R2oDiscoveryVerdict, r2o_search_discovery_with};

        let r2o_prefix = r2k_core::stun::binding_request([0x66; 12]);
        let mut r2o_calls = 0;
        let r2o_result = r2o_search_discovery_with(
            Some(r2o_prefix),
            || panic!("для полного известного префикса новый префикс не нужен"),
            |r2o_candidate| {
                r2o_calls += 1;
                assert_eq!(r2o_candidate, Some(&r2o_prefix));
                R2oDiscoveryProbeOutcome {
                    probe: r2o_probe(R2O_DISCOVERY_EXCHANGES, R2O_DISCOVERY_EXCHANGES),
                    error: None,
                }
            },
        );

        assert_eq!(r2o_calls, 1);
        assert_eq!(r2o_result.verdict, R2oDiscoveryVerdict::Clear);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn r2o_ошибка_прямого_зонда_возвращает_неизмеренный_результат() {
        use super::{R2oDiscoveryProbeOutcome, R2oDiscoveryVerdict, r2o_search_discovery_with};

        let mut r2o_calls = 0;
        let r2o_result = r2o_search_discovery_with(
            None,
            || Ok(r2k_core::stun::binding_request([0x77; 12])),
            |_| {
                r2o_calls += 1;
                R2oDiscoveryProbeOutcome {
                    probe: R2oDiscoveryProbe {
                        local_error: true,
                        marked: true,
                        ..R2oDiscoveryProbe::default()
                    },
                    error: Some("сокет недоступен".into()),
                }
            },
        );

        assert_eq!(r2o_calls, 1);
        assert_eq!(r2o_result.verdict, R2oDiscoveryVerdict::Unmeasured);
        assert_eq!(r2o_result.error.as_deref(), Some("сокет недоступен"));
    }
}
