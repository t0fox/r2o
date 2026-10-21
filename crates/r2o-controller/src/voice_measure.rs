//! Честное измерение активного Discord voice-потока.

use crate::voice_targets::{R2oVoiceTarget, r2o_read_voice_targets};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub const R2O_VOICE_REPEATS: u8 = 3;
pub const R2O_VOICE_DEFAULT_WAIT: Duration = Duration::from_secs(3);
pub const R2O_VOICE_DEFAULT_CONTROL: &str = "stun.cloudflare.com:3478";
const R2O_VOICE_ARM_MAX: usize = 1600;
const R2O_VOICE_ARM_PROFILES: [(&str, Option<&[u8]>); 3] = [
    ("active_discord_udp", None),
    ("stun", Some(include_bytes!("../assets/voice/stun.bin"))),
    (
        "quic_dbankcloud",
        Some(include_bytes!(
            "../assets/voice/quic_initial_dbankcloud_ru.bin"
        )),
    ),
];
const R2O_VOICE_ARM_COPIES: [u8; 2] = [1, 6];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum R2oVoiceVerdict {
    Clear,
    Blocked,
    NoUdp,
    NoCall,
    Flaky,
    NoOracle,
    Unmeasured,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2oVoiceArm {
    pub name: &'static str,
    pub bytes: &'static [u8],
    pub copies: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oVoiceMeasurement {
    pub verdict: R2oVoiceVerdict,
    pub reason: String,
    pub address: Option<SocketAddrV4>,
    pub probes: u32,
    pub marked: bool,
    pub discovery_verified: bool,
    pub arm: Option<R2oVoiceArm>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2oVoiceOptions {
    pub address: Option<SocketAddrV4>,
    pub control: String,
    pub conntrack_path: Option<PathBuf>,
    pub wait: Duration,
    pub mark: Option<u32>,
    pub discovery: bool,
}

impl Default for R2oVoiceOptions {
    fn default() -> Self {
        Self {
            address: None,
            control: R2O_VOICE_DEFAULT_CONTROL.into(),
            conntrack_path: None,
            wait: R2O_VOICE_DEFAULT_WAIT,
            mark: None,
            discovery: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct R2oVoiceTally {
    passed: u8,
    errors: u8,
    rtt_ms: Option<u32>,
    marked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum R2oVoiceObservation {
    Answers,
    Silent { packets: i32 },
    Young { packets: i32 },
    Unseen,
}

pub fn r2o_parse_voice_options(
    r2o_arguments: &[std::ffi::OsString],
) -> Result<R2oVoiceOptions, String> {
    let mut r2o_options = R2oVoiceOptions::default();
    let mut r2o_index = 0;
    while r2o_index < r2o_arguments.len() {
        let r2o_argument = r2o_arguments[r2o_index]
            .to_str()
            .ok_or("параметр проверки голоса должен быть в UTF-8")?;
        match r2o_argument {
            "--addr" => {
                let r2o_value = r2o_voice_option_value(r2o_arguments, &mut r2o_index, "--addr")?;
                r2o_options.address = Some(r2o_parse_voice_address(r2o_value)?);
            }
            "--control" => {
                r2o_options.control =
                    r2o_voice_option_value(r2o_arguments, &mut r2o_index, "--control")?.to_owned();
            }
            "--conntrack" => {
                r2o_index += 1;
                let r2o_path = r2o_arguments
                    .get(r2o_index)
                    .ok_or("--conntrack требует путь к файлу")?;
                r2o_options.conntrack_path = Some(PathBuf::from(r2o_path));
            }
            "--wait" => {
                let r2o_value = r2o_voice_option_value(r2o_arguments, &mut r2o_index, "--wait")?;
                let r2o_millis = r2o_value
                    .parse::<u64>()
                    .map_err(|_| "--wait должен быть числом миллисекунд")?;
                r2o_options.wait = Duration::from_millis(r2o_millis);
            }
            "--mark" => {
                let r2o_value = r2o_voice_option_value(r2o_arguments, &mut r2o_index, "--mark")?;
                r2o_options.mark = Some(r2o_parse_voice_mark(r2o_value)?);
            }
            "--discovery" => r2o_options.discovery = true,
            _ => {
                return Err(format!(
                    "неизвестный параметр проверки голоса: {r2o_argument}"
                ));
            }
        }
        r2o_index += 1;
    }
    Ok(r2o_options)
}

pub fn r2o_measure_voice(r2o_options: &R2oVoiceOptions) -> R2oVoiceMeasurement {
    let r2o_control = r2o_resolve_voice_control(&r2o_options.control);
    let r2o_targets = r2o_read_voice_targets(r2o_options.conntrack_path.as_deref());
    let Some((r2o_address, r2o_flow)) =
        r2o_select_voice_target(r2o_options.address, &r2o_targets, r2o_control)
    else {
        return R2oVoiceMeasurement {
            verdict: R2oVoiceVerdict::NoCall,
            reason: "живого разговора не видно. Начните звонок и повторите замер: у голоса нет имени, которое можно вписать, и адрес берётся из идущего разговора".into(),
            address: None,
            probes: 0,
            marked: r2o_options.mark.is_some_and(|r2o_mark| r2o_mark != 0),
            discovery_verified: false,
            arm: None,
        };
    };
    let mut r2o_result = R2oVoiceMeasurement {
        verdict: R2oVoiceVerdict::Unmeasured,
        reason: String::new(),
        address: Some(r2o_address),
        probes: 0,
        marked: r2o_options.mark.is_some_and(|r2o_mark| r2o_mark != 0),
        discovery_verified: false,
        arm: None,
    };

    if r2o_options.discovery {
        #[cfg(target_os = "linux")]
        {
            let r2o_discovery = crate::voice_discovery::r2o_search_discovery_endpoint(
                r2o_address,
                None,
                r2o_options.wait,
                r2o_options.mark,
            );
            r2o_result.probes = r2o_discovery
                .trace
                .known_prefix_probe
                .iter()
                .chain(r2o_discovery.trace.direct_probes.iter())
                .chain(r2o_discovery.trace.candidate_probes.iter())
                .map(|r2o_probe| u32::from(r2o_probe.sent))
                .sum();
            if r2o_discovery
                .trace
                .known_prefix_probe
                .iter()
                .chain(r2o_discovery.trace.direct_probes.iter())
                .chain(r2o_discovery.trace.candidate_probes.iter())
                .any(|r2o_probe| r2o_probe.sent != 0 && !r2o_probe.marked)
            {
                r2o_result.marked = false;
            }
            match r2o_discovery.verdict {
                crate::voice_discovery::R2oDiscoveryVerdict::Continue => {}
                crate::voice_discovery::R2oDiscoveryVerdict::Clear => {
                    r2o_result.verdict = R2oVoiceVerdict::Clear;
                    r2o_result.reason = "Discord IP Discovery отвечает напрямую; поздний обрыв не воспроизведён (звук отдельно)".into();
                    return r2o_result;
                }
                crate::voice_discovery::R2oDiscoveryVerdict::Flaky => {
                    r2o_result.verdict = R2oVoiceVerdict::Flaky;
                    r2o_result.reason = "Discord IP Discovery: граница прекращения ответов не повторилась; вердикт не выношу".into();
                    return r2o_result;
                }
                crate::voice_discovery::R2oDiscoveryVerdict::Unmeasured => {
                    r2o_result.verdict = R2oVoiceVerdict::Unmeasured;
                    r2o_result.reason = r2o_discovery.error.unwrap_or_else(|| {
                        "Discord IP Discovery завершился без подтверждённого измерения".into()
                    });
                    return r2o_result;
                }
                crate::voice_discovery::R2oDiscoveryVerdict::Blocked { cutoff, .. } => {
                    r2o_result.verdict = R2oVoiceVerdict::Blocked;
                    r2o_result.reason = format!(
                        "Discord IP Discovery: прямой поток устойчиво обрывается после {cutoff} ответов; STUN-префикс трижды дал полную серию. Проверка медиасессии отдельно"
                    );
                    r2o_result.discovery_verified = true;
                    return r2o_result;
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            r2o_result.reason = "Discord IP Discovery поддерживается только в Linux".into();
            return r2o_result;
        }
    }

    let r2o_current_targets = r2o_read_voice_targets(r2o_options.conntrack_path.as_deref());
    let r2o_observation = r2o_voice_observation(r2o_address, r2o_flow, &r2o_current_targets);
    let r2o_evaluated = r2o_evaluate_voice(
        r2o_options,
        r2o_address,
        r2o_observation,
        r2o_control,
        |r2o_server, r2o_wait, r2o_mark, r2o_arm| {
            r2o_ask_voice_with_arm(r2o_server, r2o_wait, r2o_mark, r2o_arm)
        },
    );
    R2oVoiceMeasurement {
        probes: r2o_result.probes.saturating_add(r2o_evaluated.probes),
        marked: r2o_result.marked && r2o_evaluated.marked,
        ..r2o_evaluated
    }
}

pub fn r2o_format_voice_measurement(r2o_result: &R2oVoiceMeasurement) -> String {
    let r2o_verdict = match r2o_result.verdict {
        R2oVoiceVerdict::Clear => "резать нечего",
        R2oVoiceVerdict::Blocked => "режут этот поток",
        R2oVoiceVerdict::NoUdp => "UDP не ходит вовсе",
        R2oVoiceVerdict::NoCall => "мерить нечего",
        R2oVoiceVerdict::Flaky => "не воспроизводится",
        R2oVoiceVerdict::NoOracle => "мерить этим зондом нечем",
        R2oVoiceVerdict::Unmeasured => "измерение не закончено",
    };
    let mut r2o_output = String::new();
    if let Some(r2o_address) = r2o_result.address {
        r2o_output.push_str(&format!("Разговор:  {r2o_address}\n"));
    }
    r2o_output.push_str(&format!(
        "Вердикт:   {r2o_verdict} — {}\n",
        r2o_result.reason
    ));
    if r2o_result.probes != 0 {
        r2o_output.push_str(&format!(
            "Зондов:    {} (по {R2O_VOICE_REPEATS} повтора)\n",
            r2o_result.probes
        ));
    }
    if !r2o_result.marked {
        r2o_output.push_str(
            "ВНИМАНИЕ:  сокет не помечен — замер прошёл через наш же обход и недостоверен\n",
        );
    }
    if r2o_result.discovery_verified {
        r2o_output
            .push_str("\nПриём:     Discovery-серия подтверждена; звук проверяется в приложении\n");
    } else if let Some(r2o_arm) = r2o_result.arm {
        r2o_output.push_str(&format!(
            "\nПриманка:  кандидат {} ({} копий, {} байт); ответы STUN не подтверждают работу голосовой сессии\n",
            r2o_arm.name,
            r2o_arm.copies,
            r2o_arm.bytes.len()
        ));
    } else if r2o_result.verdict == R2oVoiceVerdict::Blocked {
        r2o_output.push_str(
            "\nПриём:     зондом не проверяется — голосовая точка молчит посторонним;\n           проверять можно только на самом разговоре, через датапат\n",
        );
    }
    r2o_output
}

fn r2o_evaluate_voice<F>(
    r2o_options: &R2oVoiceOptions,
    r2o_address: SocketAddrV4,
    r2o_observation: R2oVoiceObservation,
    r2o_control: Option<SocketAddrV4>,
    mut r2o_ask: F,
) -> R2oVoiceMeasurement
where
    F: FnMut(SocketAddrV4, Duration, Option<u32>, Option<R2oVoiceArm>) -> R2oVoiceTally,
{
    let mut r2o_result = R2oVoiceMeasurement {
        verdict: R2oVoiceVerdict::Unmeasured,
        reason: String::new(),
        address: Some(r2o_address),
        probes: 0,
        marked: r2o_options.mark.is_some_and(|r2o_mark| r2o_mark != 0),
        discovery_verified: false,
        arm: None,
    };
    match r2o_observation {
        R2oVoiceObservation::Answers => {
            r2o_result.verdict = R2oVoiceVerdict::Clear;
            r2o_result.reason =
                format!("разговор с {} идёт, и сервер по нему отвечает", r2o_address);
        }
        R2oVoiceObservation::Young { packets } => {
            r2o_result.reason = format!(
                "поток к {r2o_address} без ответа, но ушло {packets} из 4 пакетов, после которых молчание что-то значит — рано судить, повторите замер через несколько секунд разговора"
            );
        }
        R2oVoiceObservation::Silent { packets: _ } => {
            let r2o_direct = r2o_ask(r2o_address, r2o_options.wait, r2o_options.mark, None);
            r2o_record_voice_tally(&mut r2o_result, r2o_direct);
            if r2o_direct.passed == R2O_VOICE_REPEATS {
                r2o_result.verdict = R2oVoiceVerdict::Clear;
                r2o_result.reason = format!(
                    "точка {r2o_address} отвечает на прямой STUN-зонд ({}/{} за {} мс) — резать нечего",
                    r2o_direct.passed,
                    R2O_VOICE_REPEATS,
                    r2o_direct.rtt_ms.unwrap_or(0)
                );
            } else if r2o_direct.passed != 0 {
                r2o_result.verdict = R2oVoiceVerdict::Flaky;
                r2o_result.reason = format!(
                    "прямой STUN-зонд к {r2o_address}: ответов {} из {} — не воспроизводится, вердикт выносить нельзя",
                    r2o_direct.passed, R2O_VOICE_REPEATS
                );
            } else if r2o_direct.errors != 0 {
                r2o_result.reason = format!(
                    "прямой STUN-зонд к {r2o_address} не ушёл ({} из {} — местная ошибка сокета или отправки): измерение не закончено",
                    r2o_direct.errors, R2O_VOICE_REPEATS
                );
            } else if let Some(r2o_control_address) = r2o_control {
                let r2o_control_tally = r2o_ask(
                    r2o_control_address,
                    r2o_options.wait,
                    r2o_options.mark,
                    None,
                );
                r2o_record_voice_tally(&mut r2o_result, r2o_control_tally);
                if r2o_control_tally.passed == 0 && r2o_control_tally.errors != 0 {
                    r2o_result.reason = format!(
                        "поток к {r2o_address} идёт без ответов, но контрольный зонд к {} не ушёл (местная ошибка сокета или отправки): измерение не закончено",
                        r2o_options.control
                    );
                } else if r2o_control_tally.passed == 0 {
                    r2o_result.verdict = R2oVoiceVerdict::NoUdp;
                    r2o_result.reason = format!(
                        "поток к {r2o_address} идёт без ответов, и публичный STUN {} тоже молчит: на этом канале не ходит UDP или его режут целиком — обходить голос отдельно бессмысленно",
                        r2o_options.control
                    );
                } else {
                    r2o_result.verdict = R2oVoiceVerdict::Blocked;
                    r2o_result.reason = format!(
                        "поток к {r2o_address} идёт, а ответов нет ни одного, при живом публичном STUN: режут именно этот поток"
                    );
                    r2o_search_voice_arms(
                        &mut r2o_result,
                        r2o_address,
                        r2o_options.wait,
                        r2o_options.mark,
                        &mut r2o_ask,
                    );
                    if let Some(r2o_arm) = r2o_result.arm {
                        r2o_result.reason.push_str(&format!(
                            "; исходный поиск нашёл {} ({} копий), {} байт",
                            r2o_arm.name,
                            r2o_arm.copies,
                            r2o_arm.bytes.len()
                        ));
                    } else {
                        r2o_result
                            .reason
                            .push_str("; исходный перебор голосовых приманок ответа не получил");
                    }
                }
            } else {
                r2o_result.reason = format!(
                    "поток к {r2o_address} идёт без единого ответа, но контроль {} не разрешился: отделить блокировку этого потока от полного отказа UDP нечем — измерение не закончено",
                    r2o_options.control
                );
            }
        }
        R2oVoiceObservation::Unseen => {
            let r2o_direct = r2o_ask(r2o_address, r2o_options.wait, r2o_options.mark, None);
            r2o_record_voice_tally(&mut r2o_result, r2o_direct);
            if r2o_direct.passed == R2O_VOICE_REPEATS {
                r2o_result.verdict = R2oVoiceVerdict::Clear;
                r2o_result.reason = format!(
                    "точка {r2o_address} отвечает на зонд ({}/{} за {} мс) — резать нечего",
                    r2o_direct.passed,
                    R2O_VOICE_REPEATS,
                    r2o_direct.rtt_ms.unwrap_or(0)
                );
            } else if r2o_direct.passed != 0 {
                r2o_result.verdict = R2oVoiceVerdict::Flaky;
                r2o_result.reason = format!(
                    "ответов {} из {} — не воспроизводится, вердикт выносить нельзя",
                    r2o_direct.passed, R2O_VOICE_REPEATS
                );
            } else {
                r2o_result.verdict = R2oVoiceVerdict::NoOracle;
                r2o_result.reason = format!(
                    "зонд к {r2o_address} молчит (0/{}), а разговора к этой точке ядро не видит — опровергнуть молчание нечем. Голосовая точка не отвечает посторонним и на исправной линии, поэтому её молчание блокировкой не является: мерить этим способом нечем",
                    R2O_VOICE_REPEATS
                );
            }
        }
    }
    r2o_result
}

fn r2o_search_voice_arms<F>(
    r2o_result: &mut R2oVoiceMeasurement,
    r2o_address: SocketAddrV4,
    r2o_wait: Duration,
    r2o_mark: Option<u32>,
    r2o_ask: &mut F,
) where
    F: FnMut(SocketAddrV4, Duration, Option<u32>, Option<R2oVoiceArm>) -> R2oVoiceTally,
{
    for (r2o_name, r2o_bytes) in R2O_VOICE_ARM_PROFILES {
        let Some(r2o_bytes) = r2o_bytes else {
            continue;
        };
        if r2o_bytes.is_empty() || r2o_bytes.len() > R2O_VOICE_ARM_MAX {
            continue;
        }
        for r2o_copies in R2O_VOICE_ARM_COPIES {
            let r2o_arm = R2oVoiceArm {
                name: r2o_name,
                bytes: r2o_bytes,
                copies: r2o_copies,
            };
            let r2o_tally = r2o_ask(r2o_address, r2o_wait, r2o_mark, Some(r2o_arm));
            r2o_record_voice_tally(r2o_result, r2o_tally);
            if r2o_tally.passed == R2O_VOICE_REPEATS {
                r2o_result.arm = Some(r2o_arm);
                return;
            }
        }
    }
}

fn r2o_record_voice_tally(r2o_result: &mut R2oVoiceMeasurement, r2o_tally: R2oVoiceTally) {
    r2o_result.probes = r2o_result.probes.saturating_add(u32::from(
        R2O_VOICE_REPEATS.saturating_sub(r2o_tally.errors),
    ));
    r2o_result.marked &= r2o_tally.marked;
}

fn r2o_select_voice_target(
    r2o_requested: Option<SocketAddrV4>,
    r2o_targets: &[R2oVoiceTarget],
    r2o_control: Option<SocketAddrV4>,
) -> Option<(SocketAddrV4, Option<R2oVoiceTarget>)> {
    if let Some(r2o_requested) = r2o_requested {
        let r2o_flow = r2o_targets
            .iter()
            .find(|r2o_target| r2o_voice_target_address(r2o_target) == r2o_requested)
            .copied();
        return Some((r2o_requested, r2o_flow));
    }
    r2o_targets
        .iter()
        .find(|r2o_target| {
            r2o_control.is_none_or(|r2o_control| r2o_target.server_ip != *r2o_control.ip())
        })
        .copied()
        .map(|r2o_target| (r2o_voice_target_address(&r2o_target), Some(r2o_target)))
}

fn r2o_voice_target_address(r2o_target: &R2oVoiceTarget) -> SocketAddrV4 {
    SocketAddrV4::new(r2o_target.server_ip, r2o_target.server_port)
}

fn r2o_voice_observation(
    r2o_address: SocketAddrV4,
    r2o_flow: Option<R2oVoiceTarget>,
    r2o_targets: &[R2oVoiceTarget],
) -> R2oVoiceObservation {
    let r2o_target = r2o_targets.iter().find(|r2o_target| {
        r2o_voice_target_address(r2o_target) == r2o_address
            && r2o_flow.is_none_or(|r2o_flow| {
                r2o_target.client_ip == r2o_flow.client_ip
                    && r2o_target.client_port == r2o_flow.client_port
            })
    });
    let Some(r2o_target) = r2o_target else {
        return R2oVoiceObservation::Unseen;
    };
    if r2o_target.replied {
        R2oVoiceObservation::Answers
    } else if r2o_target.packets >= 4 {
        R2oVoiceObservation::Silent {
            packets: r2o_target.packets,
        }
    } else {
        R2oVoiceObservation::Young {
            packets: r2o_target.packets,
        }
    }
}

fn r2o_resolve_voice_control(r2o_control: &str) -> Option<SocketAddrV4> {
    let (r2o_host, r2o_port) = r2o_control.rsplit_once(':')?;
    if r2o_host.is_empty() {
        return None;
    }
    let r2o_port = r2o_port
        .parse::<u16>()
        .ok()
        .filter(|r2o_port| *r2o_port != 0)?;
    (r2o_host, r2o_port)
        .to_socket_addrs()
        .ok()?
        .find_map(|r2o_address| match r2o_address {
            SocketAddr::V4(r2o_address) => Some(r2o_address),
            SocketAddr::V6(_) => None,
        })
}

#[cfg(test)]
fn r2o_ask_voice(
    r2o_server: SocketAddrV4,
    r2o_wait: Duration,
    r2o_mark: Option<u32>,
) -> R2oVoiceTally {
    r2o_ask_voice_with_arm(r2o_server, r2o_wait, r2o_mark, None)
}

fn r2o_ask_voice_with_arm(
    r2o_server: SocketAddrV4,
    r2o_wait: Duration,
    r2o_mark: Option<u32>,
    r2o_arm: Option<R2oVoiceArm>,
) -> R2oVoiceTally {
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        use std::os::fd::AsRawFd;

        struct R2oPendingProbe {
            socket: UdpSocket,
            txid: [u8; 12],
        }

        let mut r2o_tally = R2oVoiceTally {
            marked: true,
            ..R2oVoiceTally::default()
        };
        if r2o_arm.is_some_and(|r2o_arm| {
            r2o_arm.bytes.is_empty()
                || r2o_arm.bytes.len() > R2O_VOICE_ARM_MAX
                || r2o_arm.copies == 0
        }) {
            r2o_tally.errors = R2O_VOICE_REPEATS;
            r2o_tally.marked = false;
            return r2o_tally;
        }
        let r2o_started = Instant::now();
        let mut r2o_random = match std::fs::File::open("/dev/urandom") {
            Ok(r2o_random) => r2o_random,
            Err(_) => {
                r2o_tally.errors = R2O_VOICE_REPEATS;
                r2o_tally.marked = false;
                return r2o_tally;
            }
        };
        let r2o_wait = if r2o_wait.is_zero() {
            R2O_VOICE_DEFAULT_WAIT
        } else {
            r2o_wait
        };
        let mut r2o_pending = Vec::with_capacity(usize::from(R2O_VOICE_REPEATS));

        for _ in 0..R2O_VOICE_REPEATS {
            let mut r2o_txid = [0; 12];
            if r2o_random.read_exact(&mut r2o_txid).is_err() {
                r2o_tally.errors = r2o_tally.errors.saturating_add(1);
                r2o_tally.marked = false;
                continue;
            }
            let r2o_socket = match UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                0,
            ))) {
                Ok(r2o_socket) => r2o_socket,
                Err(_) => {
                    r2o_tally.errors = r2o_tally.errors.saturating_add(1);
                    r2o_tally.marked = false;
                    continue;
                }
            };
            let mut r2o_marked = false;
            if let Some(r2o_mark) = r2o_mark.filter(|r2o_mark| *r2o_mark != 0)
                && crate::voice_discovery::r2o_set_socket_mark(r2o_socket.as_raw_fd(), r2o_mark)
                    .is_ok()
            {
                r2o_marked = true;
            }
            r2o_tally.marked &= r2o_marked;
            if r2o_socket.connect(SocketAddr::V4(r2o_server)).is_err() {
                r2o_tally.errors = r2o_tally.errors.saturating_add(1);
                continue;
            }
            if let Some(r2o_arm) = r2o_arm {
                let mut r2o_failed = false;
                for _ in 0..r2o_arm.copies {
                    if r2o_socket.send(r2o_arm.bytes).ok() != Some(r2o_arm.bytes.len()) {
                        r2o_failed = true;
                        break;
                    }
                }
                if r2o_failed {
                    r2o_tally.errors = r2o_tally.errors.saturating_add(1);
                    continue;
                }
            }
            let r2o_request = r2k_core::stun::binding_request(r2o_txid);
            if r2o_socket.send(&r2o_request).ok() != Some(r2o_request.len()) {
                r2o_tally.errors = r2o_tally.errors.saturating_add(1);
                continue;
            }
            r2o_pending.push(Some(R2oPendingProbe {
                socket: r2o_socket,
                txid: r2o_txid,
            }));
        }

        while r2o_pending.iter().any(Option::is_some) {
            let r2o_remaining = r2o_wait.saturating_sub(r2o_started.elapsed());
            if r2o_remaining.is_zero() {
                break;
            }
            let mut r2o_indices = Vec::with_capacity(r2o_pending.len());
            let mut r2o_pollfds: Vec<libc::pollfd> = r2o_pending
                .iter()
                .enumerate()
                .filter_map(|(r2o_index, r2o_probe)| {
                    r2o_probe.as_ref().map(|r2o_probe| {
                        r2o_indices.push(r2o_index);
                        libc::pollfd {
                            fd: r2o_probe.socket.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        }
                    })
                })
                .collect();
            if r2o_pollfds.is_empty() {
                break;
            }
            let r2o_timeout = r2o_remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let r2o_ready = unsafe {
                libc::poll(
                    r2o_pollfds.as_mut_ptr(),
                    r2o_pollfds.len() as libc::nfds_t,
                    r2o_timeout,
                )
            };
            if r2o_ready == 0 {
                break;
            }
            if r2o_ready < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            for (r2o_poll_index, r2o_pollfd) in r2o_pollfds.iter().enumerate() {
                if r2o_pollfd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) == 0 {
                    continue;
                }
                let r2o_index = r2o_indices[r2o_poll_index];
                let Some(r2o_probe) = r2o_pending[r2o_index].as_ref() else {
                    continue;
                };
                let mut r2o_response = [0; 1500];
                let r2o_received = match r2o_probe.socket.recv(&mut r2o_response) {
                    Ok(r2o_received) => r2o_received,
                    Err(r2o_error) if r2o_error.kind() == std::io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(_) => {
                        r2o_pending[r2o_index] = None;
                        continue;
                    }
                };
                if r2k_core::stun::parse_binding_response(
                    &r2o_response[..r2o_received],
                    &r2o_probe.txid,
                )
                .is_ok()
                {
                    r2o_tally.passed = r2o_tally.passed.saturating_add(1);
                    let r2o_rtt_ms =
                        r2o_started.elapsed().as_millis().clamp(1, u32::MAX as u128) as u32;
                    r2o_tally.rtt_ms = Some(
                        r2o_tally
                            .rtt_ms
                            .map_or(r2o_rtt_ms, |r2o_prior| r2o_prior.min(r2o_rtt_ms)),
                    );
                    r2o_pending[r2o_index] = None;
                }
            }
        }
        return r2o_tally;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (r2o_server, r2o_wait, r2o_mark, r2o_arm);
        R2oVoiceTally {
            errors: R2O_VOICE_REPEATS,
            marked: false,
            ..R2oVoiceTally::default()
        }
    }
}

fn r2o_voice_option_value<'a>(
    r2o_arguments: &'a [std::ffi::OsString],
    r2o_index: &mut usize,
    r2o_option: &str,
) -> Result<&'a str, String> {
    *r2o_index += 1;
    r2o_arguments
        .get(*r2o_index)
        .and_then(|r2o_value| r2o_value.to_str())
        .ok_or_else(|| format!("{r2o_option} требует значение в UTF-8"))
}

fn r2o_parse_voice_address(r2o_value: &str) -> Result<SocketAddrV4, String> {
    let (r2o_ip, r2o_port) = r2o_value
        .rsplit_once(':')
        .ok_or("--addr должен быть в формате IPv4:ПОРТ")?;
    let r2o_ip = r2o_ip
        .parse::<Ipv4Addr>()
        .map_err(|_| "--addr должен содержать IPv4-адрес")?;
    let r2o_port = r2o_port
        .parse::<u16>()
        .ok()
        .filter(|r2o_port| *r2o_port != 0)
        .ok_or("--addr содержит неверный порт")?;
    Ok(SocketAddrV4::new(r2o_ip, r2o_port))
}

fn r2o_parse_voice_mark(r2o_value: &str) -> Result<u32, String> {
    let (r2o_digits, r2o_radix) = if let Some(r2o_hex) = r2o_value
        .strip_prefix("0x")
        .or_else(|| r2o_value.strip_prefix("0X"))
    {
        (r2o_hex, 16)
    } else {
        (r2o_value, 10)
    };
    u32::from_str_radix(r2o_digits, r2o_radix)
        .map_err(|_| "--mark должен быть числом от 0 до 4294967295".into())
}

#[cfg(test)]
mod tests {
    use super::{
        R2O_VOICE_REPEATS, R2oVoiceArm, R2oVoiceObservation, R2oVoiceOptions, R2oVoiceTally,
        R2oVoiceVerdict, r2o_ask_voice, r2o_ask_voice_with_arm, r2o_evaluate_voice,
        r2o_parse_voice_options, r2o_select_voice_target, r2o_voice_observation,
    };
    use crate::voice_targets::R2oVoiceTarget;
    use std::ffi::OsString;
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use std::time::Duration;

    fn r2o_flow(
        server: [u8; 4],
        client: [u8; 4],
        sport: u16,
        packets: i32,
        replied: bool,
    ) -> R2oVoiceTarget {
        R2oVoiceTarget {
            server_ip: Ipv4Addr::from(server),
            server_port: 50_004,
            client_ip: Ipv4Addr::from(client),
            client_port: sport,
            packets,
            replied,
        }
    }

    fn r2o_tally(passed: u8, errors: u8) -> R2oVoiceTally {
        R2oVoiceTally {
            passed,
            errors,
            rtt_ms: (passed != 0).then_some(5),
            marked: true,
        }
    }

    #[test]
    fn разбирает_параметры_адреса_контроля_ожидания_метки_и_discovery() {
        let r2o_arguments = [
            "--addr",
            "35.217.0.67:50004",
            "--control",
            "stun.example:3478",
            "--conntrack",
            "таблица",
            "--wait",
            "25",
            "--mark",
            "0x2d",
            "--discovery",
        ]
        .map(OsString::from);
        let r2o_options = r2o_parse_voice_options(&r2o_arguments).unwrap();

        assert_eq!(
            r2o_options.address,
            Some(SocketAddrV4::new(Ipv4Addr::new(35, 217, 0, 67), 50_004))
        );
        assert_eq!(r2o_options.control, "stun.example:3478");
        assert_eq!(
            r2o_options.conntrack_path.unwrap().as_path(),
            std::path::Path::new("таблица")
        );
        assert_eq!(r2o_options.wait, Duration::from_millis(25));
        assert_eq!(r2o_options.mark, Some(45));
        assert!(r2o_options.discovery);
    }

    #[test]
    fn отклоняет_неполный_адрес_и_неверный_порт() {
        assert!(r2o_parse_voice_options(&[OsString::from("--addr")]).is_err());
        assert!(
            r2o_parse_voice_options(&[OsString::from("--addr"), OsString::from("35.217.0.67:0")])
                .is_err()
        );
        assert!(
            r2o_parse_voice_options(&[
                OsString::from("--addr"),
                OsString::from("discord.example:50004")
            ])
            .is_err()
        );
    }

    #[test]
    fn выбирает_самый_нагруженный_поток_кроме_контрольного_сервера() {
        let r2o_targets = [
            r2o_flow([104, 16, 58, 100], [192, 168, 1, 2], 50_001, 50, false),
            r2o_flow([104, 16, 58, 99], [192, 168, 1, 3], 50_002, 15, false),
        ];
        let r2o_control = Some(SocketAddrV4::new(Ipv4Addr::new(104, 16, 58, 100), 3478));
        let r2o_chosen = r2o_select_voice_target(None, &r2o_targets, r2o_control).unwrap();

        assert_eq!(r2o_chosen.0.ip(), &Ipv4Addr::new(104, 16, 58, 99));
        assert_eq!(r2o_chosen.1.unwrap().client_port, 50_002);
    }

    #[test]
    fn заданная_точка_остаётся_доступной_даже_без_строки_conntrack() {
        let r2o_address = SocketAddrV4::new(Ipv4Addr::new(35, 217, 0, 67), 50_004);
        assert_eq!(
            r2o_select_voice_target(Some(r2o_address), &[], None),
            Some((r2o_address, None))
        );
    }

    #[test]
    fn ответный_флаг_и_порог_пакетов_сверяются_с_точным_клиентским_потоком() {
        let r2o_selected_flow = r2o_flow([35, 217, 0, 67], [192, 168, 1, 2], 50_001, 4, false);
        let r2o_address =
            SocketAddrV4::new(r2o_selected_flow.server_ip, r2o_selected_flow.server_port);
        assert_eq!(
            r2o_voice_observation(r2o_address, Some(r2o_selected_flow), &[r2o_selected_flow]),
            R2oVoiceObservation::Silent { packets: 4 }
        );
        let r2o_other_client = r2o_flow([35, 217, 0, 67], [192, 168, 1, 3], 50_002, 50, true);
        assert_eq!(
            r2o_voice_observation(r2o_address, Some(r2o_selected_flow), &[r2o_other_client]),
            R2oVoiceObservation::Unseen
        );
        let r2o_young = R2oVoiceTarget {
            packets: 3,
            ..r2o_selected_flow
        };
        assert_eq!(
            r2o_voice_observation(r2o_address, Some(r2o_selected_flow), &[r2o_young]),
            R2oVoiceObservation::Young { packets: 3 }
        );
        let r2o_answered = R2oVoiceTarget {
            replied: true,
            ..r2o_selected_flow
        };
        assert_eq!(
            r2o_voice_observation(r2o_address, Some(r2o_selected_flow), &[r2o_answered]),
            R2oVoiceObservation::Answers
        );
    }

    #[test]
    fn ответы_на_живом_потоке_не_создают_зондов() {
        let r2o_options = R2oVoiceOptions::default();
        let r2o_address = SocketAddrV4::new(Ipv4Addr::new(35, 217, 0, 67), 50_004);
        let mut r2o_calls = 0;
        let r2o_result = r2o_evaluate_voice(
            &r2o_options,
            r2o_address,
            R2oVoiceObservation::Answers,
            None,
            |_, _, _, _| {
                r2o_calls += 1;
                R2oVoiceTally::default()
            },
        );

        assert_eq!(r2o_result.verdict, R2oVoiceVerdict::Clear);
        assert_eq!(r2o_result.probes, 0);
        assert_eq!(r2o_calls, 0);
    }

    #[test]
    fn молодой_поток_не_объявляется_заблокированным() {
        let r2o_result = r2o_evaluate_voice(
            &R2oVoiceOptions::default(),
            SocketAddrV4::new(Ipv4Addr::new(35, 217, 0, 67), 50_004),
            R2oVoiceObservation::Young { packets: 2 },
            None,
            |_, _, _, _| panic!("молодой поток не должен запускать зонды"),
        );
        assert_eq!(r2o_result.verdict, R2oVoiceVerdict::Unmeasured);
    }

    #[test]
    fn три_ответа_на_прямой_зонд_дают_чистый_вердикт() {
        let r2o_address = SocketAddrV4::new(Ipv4Addr::new(35, 217, 0, 67), 50_004);
        let r2o_result = r2o_evaluate_voice(
            &R2oVoiceOptions::default(),
            r2o_address,
            R2oVoiceObservation::Unseen,
            None,
            |r2o_server, _, _, r2o_arm| {
                assert_eq!(r2o_server, r2o_address);
                assert!(r2o_arm.is_none());
                r2o_tally(R2O_VOICE_REPEATS, 0)
            },
        );
        assert_eq!(r2o_result.verdict, R2oVoiceVerdict::Clear);
        assert_eq!(r2o_result.probes, 3);
    }

    #[test]
    fn прямой_ответ_цели_не_запускает_перебор_голосовых_приманок() {
        let r2o_address = SocketAddrV4::new(Ipv4Addr::new(35, 217, 0, 67), 50_004);
        let mut r2o_calls = 0;
        let r2o_result = r2o_evaluate_voice(
            &R2oVoiceOptions::default(),
            r2o_address,
            R2oVoiceObservation::Silent { packets: 4 },
            None,
            |_, _, _, r2o_arm| {
                r2o_calls += 1;
                assert!(r2o_arm.is_none());
                r2o_tally(R2O_VOICE_REPEATS, 0)
            },
        );

        assert_eq!(r2o_result.verdict, R2oVoiceVerdict::Clear);
        assert_eq!(r2o_result.arm, None);
        assert_eq!(r2o_calls, 1);
    }

    #[test]
    fn частичный_ответ_не_становится_успехом_или_блокировкой() {
        let r2o_result = r2o_evaluate_voice(
            &R2oVoiceOptions::default(),
            SocketAddrV4::new(Ipv4Addr::new(35, 217, 0, 67), 50_004),
            R2oVoiceObservation::Unseen,
            None,
            |_, _, _, _| r2o_tally(1, 0),
        );
        assert_eq!(r2o_result.verdict, R2oVoiceVerdict::Flaky);
    }

    #[test]
    fn местная_ошибка_прямого_зонда_не_выдаётся_за_блокировку() {
        let r2o_result = r2o_evaluate_voice(
            &R2oVoiceOptions::default(),
            SocketAddrV4::new(Ipv4Addr::new(35, 217, 0, 67), 50_004),
            R2oVoiceObservation::Silent { packets: 4 },
            Some(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 3478)),
            |_, _, _, _| r2o_tally(0, R2O_VOICE_REPEATS),
        );
        assert_eq!(r2o_result.verdict, R2oVoiceVerdict::Unmeasured);
        assert_eq!(r2o_result.probes, 0);
    }

    #[test]
    fn молчание_цели_и_контроля_означает_отказ_udp() {
        let r2o_control = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 3478);
        let mut r2o_calls = Vec::new();
        let r2o_result = r2o_evaluate_voice(
            &R2oVoiceOptions::default(),
            SocketAddrV4::new(Ipv4Addr::new(35, 217, 0, 67), 50_004),
            R2oVoiceObservation::Silent { packets: 4 },
            Some(r2o_control),
            |r2o_server, _, _, r2o_arm| {
                r2o_calls.push((r2o_server, r2o_arm.is_some()));
                R2oVoiceTally {
                    marked: true,
                    ..R2oVoiceTally::default()
                }
            },
        );
        assert_eq!(r2o_result.verdict, R2oVoiceVerdict::NoUdp);
        assert_eq!(
            r2o_calls,
            [(r2o_result.address.unwrap(), false), (r2o_control, false)]
        );
    }

    #[test]
    fn молчащий_поток_при_живом_stun_считается_заблокированным() {
        let r2o_control = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 3478);
        let mut r2o_calls = Vec::new();
        let r2o_result = r2o_evaluate_voice(
            &R2oVoiceOptions {
                mark: Some(45),
                ..R2oVoiceOptions::default()
            },
            SocketAddrV4::new(Ipv4Addr::new(35, 217, 0, 67), 50_004),
            R2oVoiceObservation::Silent { packets: 5 },
            Some(r2o_control),
            |r2o_server, _, _, r2o_arm| {
                r2o_calls.push((
                    r2o_server,
                    r2o_arm.map(|r2o_arm| (r2o_arm.name, r2o_arm.copies)),
                ));
                if r2o_arm.is_some() {
                    if r2o_arm.is_some_and(|r2o_arm| {
                        r2o_arm.name == "quic_dbankcloud" && r2o_arm.copies == 1
                    }) {
                        r2o_tally(R2O_VOICE_REPEATS, 0)
                    } else {
                        r2o_tally(0, 0)
                    }
                } else if r2o_server == r2o_control {
                    r2o_tally(1, 0)
                } else {
                    r2o_tally(0, 0)
                }
            },
        );
        assert_eq!(r2o_result.verdict, R2oVoiceVerdict::Blocked);
        assert!(r2o_result.marked);
        assert_eq!(
            r2o_calls,
            [
                (r2o_result.address.unwrap(), None),
                (r2o_control, None),
                (r2o_result.address.unwrap(), Some(("stun", 1))),
                (r2o_result.address.unwrap(), Some(("stun", 6))),
                (r2o_result.address.unwrap(), Some(("quic_dbankcloud", 1))),
            ]
        );
        assert_eq!(
            r2o_result.arm,
            Some(R2oVoiceArm {
                name: "quic_dbankcloud",
                bytes: include_bytes!("../assets/voice/quic_initial_dbankcloud_ru.bin"),
                copies: 1,
            })
        );
        assert_eq!(r2o_result.probes, 15);
        let r2o_output = super::r2o_format_voice_measurement(&r2o_result);
        assert!(r2o_output.contains("кандидат quic_dbankcloud"));
        assert!(r2o_output.contains("не подтверждают работу голосовой сессии"));
    }

    #[test]
    fn непринятая_приманка_не_меняет_вердикт_и_перебирает_оба_числа_копий() {
        let r2o_control = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 3478);
        let r2o_result = r2o_evaluate_voice(
            &R2oVoiceOptions::default(),
            SocketAddrV4::new(Ipv4Addr::new(35, 217, 0, 67), 50_004),
            R2oVoiceObservation::Silent { packets: 4 },
            Some(r2o_control),
            |r2o_server, _, _, r2o_arm| {
                if r2o_arm.is_none() && r2o_server == r2o_control {
                    r2o_tally(1, 0)
                } else {
                    r2o_tally(0, 0)
                }
            },
        );

        assert_eq!(r2o_result.verdict, R2oVoiceVerdict::Blocked);
        assert_eq!(r2o_result.arm, None);
        assert!(r2o_result.reason.contains("перебор голосовых приманок"));
        assert_eq!(r2o_result.probes, 18);
    }

    #[test]
    fn соединённый_udp_оракул_проверяет_каждый_stun_id_на_arm64_linux() {
        let r2o_server = UdpSocket::bind("127.0.0.1:0").unwrap();
        r2o_server
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        let r2o_address = match r2o_server.local_addr().unwrap() {
            std::net::SocketAddr::V4(r2o_address) => r2o_address,
            std::net::SocketAddr::V6(_) => unreachable!(),
        };
        let r2o_thread = std::thread::spawn(move || {
            let mut r2o_buffer = [0; 1500];
            for _ in 0..R2O_VOICE_REPEATS {
                let (r2o_size, r2o_client) = r2o_server.recv_from(&mut r2o_buffer).unwrap();
                assert_eq!(r2o_size, 20);
                let mut r2o_response = [0; 20];
                r2o_response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
                r2o_response[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
                r2o_response[8..].copy_from_slice(&r2o_buffer[8..20]);
                let mut r2o_wrong = r2o_response;
                r2o_wrong[19] ^= 1;
                r2o_server.send_to(&r2o_wrong, r2o_client).unwrap();
                r2o_server.send_to(&r2o_response, r2o_client).unwrap();
            }
        });
        let r2o_result = r2o_ask_voice(r2o_address, Duration::from_secs(2), None);
        r2o_thread.join().unwrap();

        assert_eq!(r2o_result.passed, R2O_VOICE_REPEATS);
        assert_eq!(r2o_result.errors, 0);
        assert!(!r2o_result.marked);
        assert!(r2o_result.rtt_ms.is_some());
    }

    #[test]
    fn отправляет_копии_приманки_перед_каждым_stun_запросом_arm64_linux() {
        const R2O_TEST_ARM: &[u8] = b"r2o-test-voice-arm";
        let r2o_server = UdpSocket::bind("127.0.0.1:0").unwrap();
        r2o_server
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        let r2o_address = match r2o_server.local_addr().unwrap() {
            std::net::SocketAddr::V4(r2o_address) => r2o_address,
            std::net::SocketAddr::V6(_) => unreachable!(),
        };
        let r2o_thread = std::thread::spawn(move || {
            let mut r2o_sequences = std::collections::HashMap::new();
            let mut r2o_buffer = [0; 1500];
            for _ in 0..usize::from(R2O_VOICE_REPEATS) * 3 {
                let (r2o_size, r2o_client) = r2o_server.recv_from(&mut r2o_buffer).unwrap();
                let r2o_payload = r2o_buffer[..r2o_size].to_vec();
                let r2o_sequence = r2o_sequences
                    .entry(r2o_client)
                    .or_insert_with(Vec::<Vec<u8>>::new);
                if r2o_payload == R2O_TEST_ARM {
                    assert!(r2o_sequence.len() < 2);
                    r2o_sequence.push(r2o_payload);
                    continue;
                }
                assert_eq!(r2o_payload.len(), 20);
                assert_eq!(r2o_sequence.len(), 2);
                assert!(r2o_sequence.iter().all(|r2o_copy| r2o_copy == R2O_TEST_ARM));
                let mut r2o_response = [0; 20];
                r2o_response[..2].copy_from_slice(&0x0101_u16.to_be_bytes());
                r2o_response[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
                r2o_response[8..].copy_from_slice(&r2o_payload[8..20]);
                r2o_server.send_to(&r2o_response, r2o_client).unwrap();
            }
            assert_eq!(r2o_sequences.len(), usize::from(R2O_VOICE_REPEATS));
        });
        let r2o_result = r2o_ask_voice_with_arm(
            r2o_address,
            Duration::from_secs(2),
            None,
            Some(R2oVoiceArm {
                name: "test",
                bytes: R2O_TEST_ARM,
                copies: 2,
            }),
        );
        r2o_thread.join().unwrap();

        assert_eq!(r2o_result.passed, R2O_VOICE_REPEATS);
        assert_eq!(r2o_result.errors, 0);
        assert!(!r2o_result.marked);
    }
}
