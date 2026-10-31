//! Основные средства классификации DPI и дерево решений TCP из `r2o/detect`.

pub use crate::classify_measured::{plan_bytes_for_poison, plan_for_poison, plan_text_for_poison};

use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use crate::response::{ResponseOptions, ResponseResult, ResponseVerdict, probe_response};

const TRACE_MAX: usize = 512;
const CLEAR_CONFIRM_REPEATS: usize = 2;
const PROBE_TIMEOUT_CEILING: Duration = Duration::from_secs(5);

pub(crate) fn effective_probe_timeout(timeout: Duration) -> Duration {
    if timeout.is_zero() || timeout > PROBE_TIMEOUT_CEILING {
        PROBE_TIMEOUT_CEILING
    } else {
        timeout
    }
}

/// Один непрерывный диапазон данных триггера, отправляемый пробой с разрезанием.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    pub from: usize,
    pub to: usize,
}

/// Преобразовать смещения разрезов в упорядоченные непустые диапазоны данных.
///
/// Поведение совпадает с `r2o_split_offsets`: используются первые восемь
/// корректных разрезов, дубликаты игнорируются, а границы данных не считаются разрезами.
pub fn split_offsets(cuts: &[usize], len: usize, capacity: usize) -> Vec<Span> {
    let mut cuts: Vec<usize> = cuts
        .iter()
        .copied()
        .filter(|cut| *cut > 0 && *cut < len)
        .take(8)
        .collect();
    cuts.sort_unstable();

    let mut spans = Vec::with_capacity(capacity.min(cuts.len() + 1));
    let mut previous = 0;
    for cut in cuts {
        if cut == previous {
            continue;
        }
        if spans.len() < capacity {
            spans.push(Span {
                from: previous,
                to: cut,
            });
        }
        previous = cut;
    }
    if spans.len() < capacity {
        spans.push(Span {
            from: previous,
            to: len,
        });
    }
    spans
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Accept {
    #[default]
    Any,
    ServerHello,
    TlsRecord,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trigger {
    pub name: String,
    pub payload: Vec<u8>,
    pub accept: Accept,
}

impl Trigger {
    /// Build the donor's arbitrary-byte trigger from its command-line hex form.
    pub fn raw_hex(hex: &str) -> Result<Self, &'static str> {
        let payload = crate::trigger::parse_raw_hex(hex)?;
        Ok(Self {
            name: format!("raw:{}B", payload.len()),
            payload,
            accept: Accept::Any,
        })
    }

    /// Собрать снятый триггер устаревшего TLS, используемый эталонным классификатором.
    pub fn tls(sni: &str) -> Result<Self, &'static str> {
        Ok(Self {
            name: format!("tls:{sni}"),
            payload: crate::hello::legacy_client_hello(sni)?,
            accept: Accept::ServerHello,
        })
    }

    /// Собрать снятый браузерный триггер TLS 1.3 для современных клиентов.
    pub fn tls13(sni: &str) -> Result<Self, &'static str> {
        Ok(Self {
            name: format!("tls:{sni}"),
            payload: crate::hello::modern_client_hello(sni)?,
            accept: Accept::ServerHello,
        })
    }

    /// Собрать триггер из полного ClientHello, снятого с клиентского потока.
    pub fn tls_client_hello(sni: &str, client_hello: &[u8]) -> Result<Self, &'static str> {
        let tls = r2k_core::tls::parse(client_hello);
        let captured_sni = tls
            .sni_range
            .as_ref()
            .and_then(|range| client_hello.get(range.clone()));
        if !tls.is_client_hello
            || tls.extensions_truncated
            || tls.record_end != Some(client_hello.len())
            || captured_sni.is_none_or(|captured| !captured.eq_ignore_ascii_case(sni.as_bytes()))
        {
            return Err("снятый TLS ClientHello неполон или его SNI не совпадает с целью");
        }
        Ok(Self {
            name: format!("tls:{sni}"),
            payload: client_hello.to_vec(),
            accept: Accept::ServerHello,
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Poison {
    pub name: String,
    pub ttl: i32,
    pub badsum: bool,
    pub seq_shift: i32,
    pub md5: bool,
    pub decoy_hello: bool,
    pub disorder: bool,
    pub disorder_pos: i32,
    pub tcp_ts: bool,
    pub ip_id_zero: bool,
    pub gap_ms: i32,
    pub syn_data: bool,
    pub oob: bool,
    pub fake_between: bool,
    pub repeats: i32,
    pub seqovl_exact: bool,
    pub seqovl: i32,
    pub split_pos: i32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TriState {
    #[default]
    Unset,
    False,
    True,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DpiProps {
    pub reassembles: TriState,
    pub parses_l7: TriState,
    pub validates_checksum: TriState,
    pub tolerates_reorder: TriState,
    pub tolerates_left_overlap: TriState,
    pub counts_duplicates: TriState,
    pub inspects_syn: TriState,
    pub validates_md5: TriState,
    pub validates_seq_window: TriState,
    pub validates_timestamps: TriState,
    pub overlap_covers_sni: TriState,
    pub hop_ttl: Option<i32>,
}

/// Записать только свойства, подтверждённые всеми успешными пробами искажения.
pub fn note_props_hit(properties: &mut DpiProps, poison: &Poison) {
    if poison.badsum {
        properties.validates_checksum = TriState::False;
    } else if poison.ttl > 0 {
        properties.hop_ttl = Some(poison.ttl);
    } else if poison.disorder {
        properties.tolerates_reorder = TriState::False;
    } else if poison.seqovl > 0 {
        properties.tolerates_left_overlap = TriState::False;
    }
    if poison.decoy_hello {
        properties.parses_l7 = TriState::True;
    }
}

/// Неудачная проба подтверждает только проверенные случаи порядка и допустимого перекрытия.
pub fn note_props_miss(properties: &mut DpiProps, poison: &Poison) {
    if poison.disorder {
        properties.tolerates_reorder = TriState::True;
    } else if poison.seqovl > 0 && !poison.decoy_hello {
        properties.tolerates_left_overlap = TriState::True;
    }
}

impl Poison {
    /// Сравнить гипотезы вроде `r2o_poison_same`: имя игнорируется, а ноль и один
    /// повтор считаются одинаковым числом передач.
    pub fn same_hypothesis(&self, other: &Self) -> bool {
        let mut left = self.clone();
        let mut right = other.clone();
        left.name.clear();
        right.name.clear();
        if left.repeats <= 1 {
            left.repeats = 1;
        }
        if right.repeats <= 1 {
            right.repeats = 1;
        }
        left == right
    }
}

fn add_poison(list: &mut Vec<Poison>, name: impl Into<String>) -> &mut Poison {
    list.push(Poison {
        name: name.into(),
        ..Poison::default()
    });
    list.last_mut().expect("just pushed poison")
}

fn build_poisons() -> Vec<Poison> {
    let mut list = Vec::with_capacity(85);
    add_poison(&mut list, "seqovl-1").seqovl = 1;
    {
        let poison = add_poison(&mut list, "badsum-x2-g20");
        poison.badsum = true;
        poison.repeats = 2;
        poison.gap_ms = 20;
    }
    {
        let poison = add_poison(&mut list, "badsum-x2-g80");
        poison.badsum = true;
        poison.repeats = 2;
        poison.gap_ms = 80;
    }
    {
        let poison = add_poison(&mut list, "badsum-x7");
        poison.badsum = true;
        poison.repeats = 7;
    }
    add_poison(&mut list, "disorder").disorder = true;
    {
        let poison = add_poison(&mut list, "disorder-pos2");
        poison.disorder = true;
        poison.disorder_pos = 2;
    }
    add_poison(&mut list, "badsum").badsum = true;
    add_poison(&mut list, "md5").md5 = true;
    add_poison(&mut list, "seq-out-of-window").seq_shift = -66_000;
    add_poison(&mut list, "syndata").syn_data = true;
    add_poison(&mut list, "oob").oob = true;
    {
        let poison = add_poison(&mut list, "fakedsplit");
        poison.fake_between = true;
        poison.badsum = true;
    }
    {
        let poison = add_poison(&mut list, "fakedsplit-x7");
        poison.fake_between = true;
        poison.badsum = true;
        poison.repeats = 7;
    }

    for repeats in [7, 4, 2] {
        for (name, ttl, seqovl, exact) in [
            (format!("fake-x{repeats}+seqovl-hello"), 0, 0, true),
            (format!("fake-x{repeats}+seqovl-681"), 0, 681, false),
            (format!("fake-x{repeats}+ttl62+seqovl-hello"), 62, 0, true),
        ] {
            let poison = add_poison(&mut list, name);
            poison.badsum = true;
            poison.ttl = ttl;
            poison.repeats = repeats;
            poison.seqovl_exact = exact;
            poison.seqovl = seqovl;
            poison.decoy_hello = true;
        }
    }
    {
        let poison = add_poison(&mut list, "seqovl-hello");
        poison.seqovl_exact = true;
        poison.decoy_hello = true;
    }
    {
        let poison = add_poison(&mut list, "seqovl-hello+disorder");
        poison.seqovl_exact = true;
        poison.decoy_hello = true;
        poison.disorder = true;
    }
    {
        let poison = add_poison(&mut list, "seqovl-hello+disorder+badsum");
        poison.seqovl_exact = true;
        poison.decoy_hello = true;
        poison.disorder = true;
        poison.badsum = true;
    }
    for overlap in [1, 336, 681] {
        for (suffix, decoy, badsum) in [
            ("", false, false),
            ("+hello", true, false),
            ("+badsum", false, true),
        ] {
            let poison = add_poison(&mut list, format!("seqovl-{overlap}+disorder{suffix}"));
            poison.seqovl = overlap;
            poison.disorder = true;
            poison.decoy_hello = decoy;
            poison.badsum = badsum;
        }
    }
    for overlap in [2, 4, 8, 16, 64, 336, 681] {
        add_poison(&mut list, format!("seqovl-{overlap}")).seqovl = overlap;
        let poison = add_poison(&mut list, format!("seqovl-{overlap}+hello"));
        poison.seqovl = overlap;
        poison.decoy_hello = true;
    }
    for gap in [0, 20, 80, 300] {
        for repeats in [2, 3, 4, 7] {
            let poison = Poison {
                name: format!("badsum-x{repeats}-g{gap}"),
                badsum: true,
                repeats,
                gap_ms: gap,
                ..Poison::default()
            };
            if !list
                .iter()
                .any(|previous| previous.same_hypothesis(&poison))
            {
                list.push(poison);
            }
        }
    }
    for ttl in [62, 60, 58, 55, 50, 40, 20, 8] {
        add_poison(&mut list, format!("ttl-{ttl}")).ttl = ttl;
        let poison = add_poison(&mut list, format!("badsum+ttl-{ttl}"));
        poison.ttl = ttl;
        poison.badsum = true;
    }
    {
        let poison = add_poison(&mut list, "disorder+badsum");
        poison.disorder = true;
        poison.badsum = true;
    }
    {
        let poison = add_poison(&mut list, "disorder+badsum+hello");
        poison.disorder = true;
        poison.badsum = true;
        poison.decoy_hello = true;
    }
    for ttl in [62, 58, 50] {
        let poison = add_poison(&mut list, format!("disorder+badsum+ttl-{ttl}"));
        poison.disorder = true;
        poison.badsum = true;
        poison.ttl = ttl;
    }
    {
        let poison = add_poison(&mut list, "badsum+ts");
        poison.badsum = true;
        poison.tcp_ts = true;
    }
    {
        let poison = add_poison(&mut list, "badsum+ipid");
        poison.badsum = true;
        poison.ip_id_zero = true;
    }
    {
        let poison = add_poison(&mut list, "badsum+hello");
        poison.badsum = true;
        poison.decoy_hello = true;
    }
    list
}

/// Неизменяемый порядок эталона для перебора raw-искажений при поиске.
pub fn poisons() -> &'static [Poison] {
    static POISONS: OnceLock<Vec<Poison>> = OnceLock::new();
    POISONS.get_or_init(build_poisons)
}

pub fn poison_has_fake(poison: &Poison) -> bool {
    !poison.syn_data
        && !poison.oob
        && !poison.fake_between
        && (poison.badsum || poison.md5 || poison.ttl > 0 || poison.seq_shift != 0 || poison.tcp_ts)
}

pub fn poison_supports_family(poison: &Poison, family: u8) -> bool {
    family == 4 || (family == 6 && !poison.ip_id_zero)
}

/// Преобразовать одно измеренное искажение в текст стратегии эталонного nfqws2.
pub fn strategy_for_poison(poison: &Poison) -> Option<String> {
    if poison.syn_data {
        return Some("--lua-desync=syndata:payload=tls_client_hello:dir=out".into());
    }
    if poison.oob {
        return Some("--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:oob".into());
    }
    if poison.fake_between {
        let mut strategy =
            "--lua-desync=fakedsplit:payload=tls_client_hello:dir=out:pos=1".to_owned();
        if poison.badsum {
            strategy.push_str(":badsum");
        }
        push_repeats(&mut strategy, poison.repeats);
        return Some(strategy);
    }
    if poison_has_fake(poison) && (poison.seqovl > 0 || poison.seqovl_exact) {
        let mut fake = overlap_fake(poison);
        let mut overlap = if poison.seqovl_exact {
            "--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=681:seqovl_pattern=tls_clienthello_www_google_com".to_owned()
        } else {
            let mut overlap = format!(
                "--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl={}",
                poison.seqovl
            );
            if poison.decoy_hello {
                overlap.push_str(":seqovl_pattern=tls_clienthello_www_google_com");
            }
            overlap
        };
        if poison.disorder {
            overlap.push_str(
                " --lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld",
            );
        }
        fake.push(' ');
        fake.push_str(&overlap);
        return Some(fake);
    }
    if poison.seqovl_exact {
        let mut strategy = "--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=681:seqovl_pattern=tls_clienthello_www_google_com".to_owned();
        if poison.disorder {
            strategy.push_str(
                " --lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld",
            );
        }
        return Some(strategy);
    }
    if poison.seqovl > 0 && poison.disorder {
        let mut strategy = format!(
            "--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl={}",
            poison.seqovl
        );
        if poison.decoy_hello {
            strategy.push_str(":seqovl_pattern=tls_clienthello_www_google_com");
        }
        strategy
            .push_str(" --lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld");
        return Some(strategy);
    }
    if poison.disorder_pos > 0 {
        return Some(format!(
            "--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos={}",
            poison.disorder_pos
        ));
    }
    if poison.disorder {
        let disorder = "--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld";
        if poison_has_fake(poison) {
            let fake = disorder_fake(poison);
            return Some(format!("{fake} {disorder}"));
        }
        return Some(disorder.into());
    }
    if poison.seqovl > 0 {
        let mut strategy = format!(
            "--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl={}",
            poison.seqovl
        );
        if poison.decoy_hello {
            strategy.push_str(":seqovl_pattern=tls_clienthello_www_google_com");
        }
        return Some(strategy);
    }

    let mut fake =
        "--lua-desync=fake:payload=tls_client_hello:dir=out:blob=fake_default_tls".to_owned();
    push_repeats(&mut fake, poison.repeats);
    if poison.tcp_ts {
        fake.push_str(":tcp_ts=-1000");
    }
    if poison.ip_id_zero {
        fake.push_str(":ip_id=zero");
    }
    if poison.badsum && poison.ttl > 0 {
        fake.push_str(&format!(":badsum:ip_ttl={}", poison.ttl));
        return Some(fake);
    }
    if poison.decoy_hello {
        fake.push_str(":tls_mod=rnd,dupsid,sni=www.google.com");
    }
    if poison.badsum {
        fake.push_str(":badsum");
    } else if poison.md5 {
        fake.push_str(":tcp_md5");
    } else if poison.seq_shift != 0 {
        fake.push_str(&format!(":tcp_seq={}", poison.seq_shift));
    } else if poison.ttl > 0 {
        fake.push_str(&format!(":ip_ttl={}", poison.ttl));
    } else {
        return None;
    }
    Some(fake)
}

fn overlap_fake(poison: &Poison) -> String {
    let mut fake = "--lua-desync=fake:payload=tls_client_hello:dir=out:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=www.google.com".to_owned();
    if poison.badsum {
        fake.push_str(":badsum");
    }
    if poison.ttl > 0 {
        fake.push_str(&format!(":ip_ttl={}", poison.ttl));
    }
    fake
}

fn disorder_fake(poison: &Poison) -> String {
    let mut fake =
        "--lua-desync=fake:payload=tls_client_hello:dir=out:blob=fake_default_tls".to_owned();
    if poison.decoy_hello {
        fake.push_str(":tls_mod=rnd,dupsid,sni=www.google.com");
    }
    if poison.badsum {
        fake.push_str(":badsum");
    }
    if poison.ttl > 0 {
        fake.push_str(&format!(":ip_ttl={}", poison.ttl));
    }
    push_repeats(&mut fake, poison.repeats);
    fake
}

fn push_repeats(strategy: &mut String, repeats: i32) {
    if repeats > 1 {
        strategy.push_str(&format!(":repeats={repeats}"));
    }
}

/// Применить правило `r2o_trigger_accepts` эталона к принятому буферу.
pub fn trigger_accepts(accept: Accept, bytes: &[u8]) -> bool {
    match accept {
        Accept::ServerHello => {
            bytes.len() >= 6 && bytes[0] == 0x16 && bytes[1] == 0x03 && bytes[5] == 0x02
        }
        Accept::TlsRecord => {
            bytes.len() >= 3 && matches!(bytes[0], 0x16 | 0x15) && bytes[1] == 0x03
        }
        Accept::Any => !bytes.is_empty(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeError {
    DialTimeout(String),
    RawConnectTimeout { message: String, peer: SocketAddr },
    Transport(String),
    Local(String),
    Unsupported(String),
}

impl ProbeError {
    fn message(&self) -> &str {
        match self {
            Self::DialTimeout(message)
            | Self::RawConnectTimeout { message, .. }
            | Self::Transport(message)
            | Self::Local(message)
            | Self::Unsupported(message) => message,
        }
    }

    fn is_dial_timeout(&self) -> bool {
        match self {
            Self::DialTimeout(_) => true,
            Self::Transport(message) => is_dial_timeout_text(message),
            _ => false,
        }
    }

    fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeTarget {
    pub host: String,
    pub port: u16,
}

pub struct ProbeRequest<'a> {
    pub target: &'a ProbeTarget,
    pub trigger: &'a Trigger,
    pub cuts: &'a [usize],
    pub gap: Duration,
    pub timeout: Duration,
    pub mark: Option<u32>,
    pub no_raw: bool,
    pub client_tcp_has_timestamps: Option<bool>,
    pub cancel: Option<&'a AtomicBool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeOutcome {
    Accepted,
    Rejected,
    Unproven,
    AcceptedUnmarked,
    RejectedUnmarked,
    UnprovenUnmarked,
}

impl ProbeOutcome {
    fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted | Self::AcceptedUnmarked)
    }

    fn is_unmarked(self) -> bool {
        matches!(
            self,
            Self::AcceptedUnmarked | Self::RejectedUnmarked | Self::UnprovenUnmarked
        )
    }

    pub(crate) fn with_mark_status(self, marked: bool) -> Self {
        match (self, marked) {
            (Self::Accepted, false) | (Self::AcceptedUnmarked, false) => Self::AcceptedUnmarked,
            (Self::Rejected, false) | (Self::RejectedUnmarked, false) => Self::RejectedUnmarked,
            (Self::Unproven, false) | (Self::UnprovenUnmarked, false) => Self::UnprovenUnmarked,
            (Self::AcceptedUnmarked, true) => Self::Accepted,
            (Self::RejectedUnmarked, true) => Self::Rejected,
            (Self::UnprovenUnmarked, true) => Self::Unproven,
            (outcome, true) => outcome,
        }
    }
}

/// Интерфейс ввода-вывода классификатора. Рабочая реализация использует
/// помеченные сокеты TCP; тестовые реализации проходят то же дерево решений.
pub trait ProbeBackend {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError>;

    fn probe_outcome(&mut self, request: ProbeRequest<'_>) -> Result<ProbeOutcome, ProbeError> {
        self.probe(request).map(|accepted| {
            if accepted {
                ProbeOutcome::Accepted
            } else {
                ProbeOutcome::Rejected
            }
        })
    }

    fn tcp_control_peer(
        &mut self,
        _peer: SocketAddr,
        _timeout: Duration,
        _mark: Option<u32>,
    ) -> Result<(), ProbeError> {
        Err(ProbeError::Unsupported(
            "TCP control fallback is unavailable in this probe backend".into(),
        ))
    }

    fn neutral_ack(
        &mut self,
        _target: &ProbeTarget,
        _timeout: Duration,
        _mark: Option<u32>,
        _cancel: Option<&AtomicBool>,
    ) -> Result<bool, ProbeError> {
        Err(ProbeError::Unsupported(
            "подтверждение TCP-данных не наблюдается на этой платформе".into(),
        ))
    }

    fn raw_supported(&self) -> bool {
        false
    }

    fn sweep_poisons(
        &mut self,
        _target: &ProbeTarget,
        _trigger: &Trigger,
        _options: &ClassifyOptions,
        _result: &mut ClassifyResult,
    ) -> Result<Option<PoisonHit>, ProbeError> {
        Ok(None)
    }

    fn sweep_poisons_with_progress(
        &mut self,
        target: &ProbeTarget,
        trigger: &Trigger,
        options: &ClassifyOptions,
        result: &mut ClassifyResult,
        _progress: &mut dyn FnMut(&str, usize, usize, usize),
    ) -> Result<Option<PoisonHit>, ProbeError> {
        self.sweep_poisons(target, trigger, options, result)
    }
}

/// Рабочая реализация проб через сокеты и переносимого дерева решений TCP.
pub struct TcpProbeBackend;

impl ProbeBackend for TcpProbeBackend {
    fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        self.probe_outcome(request).map(ProbeOutcome::is_accepted)
    }

    fn probe_outcome(&mut self, request: ProbeRequest<'_>) -> Result<ProbeOutcome, ProbeError> {
        crate::response::probe_trigger(
            request.target,
            request.trigger,
            request.cuts,
            request.gap,
            request.timeout,
            request.mark,
            request.no_raw,
            request.client_tcp_has_timestamps,
            request.cancel,
        )
    }

    fn neutral_ack(
        &mut self,
        target: &ProbeTarget,
        timeout: Duration,
        mark: Option<u32>,
        cancel: Option<&AtomicBool>,
    ) -> Result<bool, ProbeError> {
        crate::response::probe_neutral_ack(target, timeout, mark, cancel)
    }

    fn tcp_control_peer(
        &mut self,
        peer: SocketAddr,
        timeout: Duration,
        mark: Option<u32>,
    ) -> Result<(), ProbeError> {
        crate::response::probe_tcp_control_peer(peer, timeout, mark)
    }

    fn raw_supported(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            crate::raw_probe::raw_supported()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    fn sweep_poisons(
        &mut self,
        target: &ProbeTarget,
        trigger: &Trigger,
        options: &ClassifyOptions,
        result: &mut ClassifyResult,
    ) -> Result<Option<PoisonHit>, ProbeError> {
        #[cfg(target_os = "linux")]
        {
            crate::raw_probe::sweep_poisons(target, trigger, options, result, &mut |_, _, _, _| {})
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (target, trigger, options, result);
            Ok(None)
        }
    }

    fn sweep_poisons_with_progress(
        &mut self,
        target: &ProbeTarget,
        trigger: &Trigger,
        options: &ClassifyOptions,
        result: &mut ClassifyResult,
        progress: &mut dyn FnMut(&str, usize, usize, usize),
    ) -> Result<Option<PoisonHit>, ProbeError> {
        #[cfg(target_os = "linux")]
        {
            crate::raw_probe::sweep_poisons(target, trigger, options, result, progress)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (target, trigger, options, result, progress);
            Ok(None)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoisonHit {
    pub name: String,
    pub strategy: String,
    /// Канонический текст для компиляции `plan`, пригодный для хранения в каталоге.
    pub plan_text: String,
    /// Проверенная программа R2OP, полученная из успешной измеренной гипотезы.
    pub plan: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnplannablePoison {
    pub name: String,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct ClassifyOptions {
    pub repeats: usize,
    pub timeout: Duration,
    pub write_gap: Duration,
    pub long_gap: Duration,
    pub allow_loopback: bool,
    pub no_raw: bool,
    /// Use `d2k_classify_run` semantics instead of the core cancelable path.
    pub full_detect_semantics: bool,
    /// Confirm a successful clear with two additional probes.
    pub confirm_clear: bool,
    /// Limit the raw poison sweep to one hypothesis, as D2O `--only` does.
    pub only_poison: Option<String>,
    /// Skip these exact names in property, composed, and normal poison sweeps.
    pub skip_poisons: Vec<String>,
    pub control: Option<Trigger>,
    pub white: Option<Trigger>,
    pub control_vouched: bool,
    /// Снятый с клиентского потока профиль, а не созданный профиль-заготовка.
    pub trigger_snapped: bool,
    /// TCP timestamp profile captured with the client trigger; `None` uses the local stack profile.
    pub client_tcp_has_timestamps: Option<bool>,
    /// `None` использует метку обхода r2o; `Some(0)` отключает маркировку.
    pub mark: Option<u32>,
    pub cancel: Option<Arc<AtomicBool>>,
    pub seed_whole: Option<SeedWhole>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeedWhole {
    pub input: u64,
    pub repeats: usize,
    pub pass: usize,
    pub fail: usize,
    pub errors: usize,
    pub unproven: usize,
    pub marked: bool,
    pub error: Option<String>,
}

/// Result of the donor's standalone whole-ClientHello question.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BaseProbe {
    pub seed_whole: Option<SeedWhole>,
    pub blocked: bool,
    pub probes: usize,
}

impl Default for ClassifyOptions {
    fn default() -> Self {
        Self {
            repeats: 3,
            timeout: Duration::from_secs(6),
            write_gap: Duration::from_millis(60),
            long_gap: Duration::from_millis(700),
            allow_loopback: false,
            no_raw: false,
            full_detect_semantics: false,
            confirm_clear: true,
            only_poison: None,
            skip_poisons: Vec::new(),
            control: None,
            white: None,
            control_vouched: false,
            trigger_snapped: false,
            client_tcp_has_timestamps: None,
            mark: None,
            cancel: None,
            seed_whole: None,
        }
    }
}

pub fn poison_selected(options: &ClassifyOptions, name: &str) -> bool {
    options
        .only_poison
        .as_deref()
        .is_none_or(|only| only == name)
        && !options.skip_poisons.iter().any(|skip| skip == name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Clear,
    Prefix,
    WholePacket,
    Opaque,
    Inconclusive,
    Address,
    Poisonable,
    Flaky,
    Unreachable,
    Response,
}

impl Verdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Prefix => "prefix",
            Self::WholePacket => "whole_packet",
            Self::Opaque => "opaque",
            Self::Inconclusive => "inconclusive",
            Self::Address => "address",
            Self::Poisonable => "poisonable",
            Self::Flaky => "flaky",
            Self::Unreachable => "unreachable",
            Self::Response => "response",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub probe: String,
    pub cuts: Vec<usize>,
    pub delay: Duration,
    pub pass: usize,
    pub fail: usize,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ClassifyResult {
    pub target: String,
    pub verdict: Verdict,
    pub reason: String,
    pub repeats: usize,
    pub probes: usize,
    pub duration: Duration,
    pub stopped: bool,
    pub boundary: Option<usize>,
    pub split_pos: Option<usize>,
    pub reassembles: Option<bool>,
    pub strategy: Option<String>,
    pub response: Option<ResponseResult>,
    pub hit: Option<PoisonHit>,
    pub unplannable: Vec<UnplannablePoison>,
    pub raw_usable: bool,
    pub rst_rule_failures: usize,
    pub raw_dials: u64,
    pub trace: Vec<Observation>,
    rst_rule_failure_base: u64,
    raw_dial_base: u64,
}

impl ClassifyResult {
    fn new(target: &str, repeats: usize) -> Self {
        Self {
            target: target.to_owned(),
            verdict: Verdict::Flaky,
            reason: String::new(),
            repeats,
            probes: 0,
            duration: Duration::ZERO,
            stopped: false,
            boundary: None,
            split_pos: None,
            reassembles: None,
            strategy: None,
            response: None,
            hit: None,
            unplannable: Vec::new(),
            raw_usable: false,
            rst_rule_failures: 0,
            raw_dials: 0,
            trace: Vec::new(),
            rst_rule_failure_base: crate::raw_probe::rst_rule_failure_count(),
            raw_dial_base: current_raw_dial_count(),
        }
    }
}

#[derive(Default)]
struct Tally {
    pass: usize,
    fail: usize,
    errors: usize,
    unproven: usize,
    unmarked: bool,
    error: Option<ProbeError>,
}

struct MeasureSpec<'a> {
    name: &'a str,
    cuts: &'a [usize],
    gap: Duration,
    until_pass: bool,
}

fn parse_target(target: &str) -> Result<ProbeTarget, &'static str> {
    let Some((raw_host, raw_port)) = target.rsplit_once(':') else {
        return Err("адрес не разобран, ожидается host:port");
    };
    if raw_host.is_empty() || raw_port.is_empty() || raw_host.len() >= 160 {
        return Err("адрес не разобран, ожидается host:port");
    }
    let host = if raw_host.starts_with('[') {
        let Some(host) = raw_host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
        else {
            return Err("адрес IPv6 не разобран");
        };
        if host.is_empty() {
            return Err("адрес IPv6 не разобран");
        }
        host
    } else {
        raw_host
    };
    if host.contains('%') {
        return Err("локальная область IPv6 не является целью замера");
    }
    let port = raw_port
        .parse::<u16>()
        .map_err(|_| "адрес не разобран, ожидается host:port")?;
    Ok(ProbeTarget {
        host: host.to_owned(),
        port,
    })
}

fn stopped(options: &ClassifyOptions) -> bool {
    options
        .cancel
        .as_ref()
        .is_some_and(|cancel| cancel.load(Ordering::Relaxed))
}

fn add_observation(
    result: &mut ClassifyResult,
    probe: &str,
    cuts: &[usize],
    delay: Duration,
) -> usize {
    if result.trace.len() < TRACE_MAX {
        result.trace.push(Observation {
            probe: probe.to_owned(),
            cuts: cuts.iter().copied().take(4).collect(),
            delay,
            pass: 0,
            fail: 0,
            error: None,
        });
    }
    result.trace.len().saturating_sub(1)
}

fn seed_input(trigger: &Trigger, target: &ProbeTarget) -> u64 {
    let mut hash = 1_469_598_103_934_665_603_u64;
    for byte in trigger.payload.iter().chain(target.host.as_bytes()) {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(1_099_511_628_211);
    }
    hash = (hash ^ u64::from(target.port)).wrapping_mul(1_099_511_628_211);
    hash ^ trigger.payload.len() as u64
}

fn measure<B: ProbeBackend>(
    backend: &mut B,
    target: &ProbeTarget,
    trigger: &Trigger,
    options: &ClassifyOptions,
    result: &mut ClassifyResult,
    spec: MeasureSpec<'_>,
    progress: &mut dyn FnMut(&str, usize, usize, usize),
) -> Tally {
    let index = add_observation(result, spec.name, spec.cuts, spec.gap);
    if spec.name == "whole"
        && spec.cuts.is_empty()
        && let Some(seed) = &options.seed_whole
        && seed.input == seed_input(trigger, target)
        && seed.repeats == options.repeats
        && !seed.error.as_deref().is_some_and(is_dial_timeout_text)
    {
        let tally = Tally {
            pass: seed.pass,
            fail: seed.fail,
            errors: seed.errors,
            unproven: seed.unproven,
            unmarked: !seed.marked,
            error: seed.error.clone().map(ProbeError::Transport),
        };
        let observation = &mut result.trace[index];
        observation.pass = tally.pass;
        observation.fail = tally.fail;
        observation.error = seed.error.clone();
        progress(spec.name, result.probes, tally.pass, tally.fail);
        return tally;
    }

    let mut tally = Tally::default();
    progress(spec.name, result.probes, tally.pass, tally.fail);
    for _ in 0..options.repeats {
        if stopped(options) {
            break;
        }
        result.probes += 1;
        let mut outcome = backend.probe_outcome(ProbeRequest {
            target,
            trigger,
            cuts: spec.cuts,
            gap: spec.gap,
            timeout: options.timeout,
            mark: options.mark,
            no_raw: options.no_raw,
            client_tcp_has_timestamps: options.client_tcp_has_timestamps,
            cancel: options.cancel.as_deref(),
        });
        let raw_timeout = match &outcome {
            Err(ProbeError::RawConnectTimeout { message, peer }) => Some((message.clone(), *peer)),
            _ => None,
        };
        let mut terminal_transport_failure = false;
        if let Some((message, peer)) = raw_timeout {
            let raw_index = add_observation(result, "transport:raw-connect", &[], Duration::ZERO);
            result.trace[raw_index].fail = 1;
            result.trace[raw_index].error = Some(message.clone());
            progress("transport:raw-connect", result.probes, 0, 1);

            if stopped(options) {
                terminal_transport_failure = true;
            } else {
                result.probes += 1;
                let control = backend.tcp_control_peer(peer, options.timeout, options.mark);
                let control_error = control
                    .as_ref()
                    .err()
                    .map(|error| error.message().to_owned());
                let control_pass = usize::from(control.is_ok());
                let control_fail = usize::from(control.is_err());
                let control_index =
                    add_observation(result, "transport:tcp-control", &[], Duration::ZERO);
                result.trace[control_index].pass = control_pass;
                result.trace[control_index].fail = control_fail;
                result.trace[control_index].error = control_error;
                progress(
                    "transport:tcp-control",
                    result.probes,
                    control_pass,
                    control_fail,
                );

                match control {
                    Err(error) => {
                        outcome = Err(error);
                        terminal_transport_failure = true;
                    }
                    Ok(()) if stopped(options) => {
                        terminal_transport_failure = true;
                    }
                    Ok(()) => {
                        let retry_target = ProbeTarget {
                            host: peer.ip().to_string(),
                            port: peer.port(),
                        };
                        result.probes += 1;
                        outcome = backend.probe_outcome(ProbeRequest {
                            target: &retry_target,
                            trigger,
                            cuts: spec.cuts,
                            gap: spec.gap,
                            timeout: options.timeout,
                            mark: options.mark,
                            no_raw: options.no_raw,
                            client_tcp_has_timestamps: options.client_tcp_has_timestamps,
                            cancel: options.cancel.as_deref(),
                        });
                        if let Err(ProbeError::RawConnectTimeout { message, .. }) = &outcome {
                            let retry_index = add_observation(
                                result,
                                "transport:raw-connect-retry",
                                &[],
                                Duration::ZERO,
                            );
                            result.trace[retry_index].fail = 1;
                            result.trace[retry_index].error = Some(message.clone());
                            progress("transport:raw-connect-retry", result.probes, 0, 1);
                            terminal_transport_failure = true;
                        }
                    }
                }
            }
        }

        if terminal_transport_failure {
            tally.errors += 1;
            if tally.error.is_none() {
                tally.error = outcome.err();
            }
            break;
        }

        if outcome.as_ref().is_ok_and(|outcome| outcome.is_unmarked()) {
            tally.unmarked = true;
        }
        match outcome {
            Ok(ProbeOutcome::Accepted | ProbeOutcome::AcceptedUnmarked) => {
                tally.pass += 1;
                if spec.until_pass {
                    break;
                }
            }
            Ok(ProbeOutcome::Rejected | ProbeOutcome::RejectedUnmarked) => tally.fail += 1,
            Ok(ProbeOutcome::Unproven | ProbeOutcome::UnprovenUnmarked) => {
                tally.fail += 1;
                tally.unproven += 1;
            }
            Err(error) => {
                tally.fail += 1;
                tally.errors += 1;
                if tally.error.is_none() {
                    tally.error = Some(error);
                }
            }
        }
        progress(spec.name, result.probes, tally.pass, tally.fail);
    }
    let observation = &mut result.trace[index];
    observation.pass = tally.pass;
    observation.fail = tally.fail;
    observation.error = tally.error.as_ref().map(|error| error.message().to_owned());
    tally
}

fn is_dial_timeout_text(error: &str) -> bool {
    error.starts_with("dial tcp ") && error.contains(": i/o timeout")
}

fn append_reason(reason: &mut String, tail: &str) {
    reason.push_str(tail);
}

fn append_unplannable_reason(result: &mut ClassifyResult) {
    let Some(first) = result.unplannable.first() else {
        return;
    };
    if result.hit.is_none() {
        result.verdict = Verdict::Opaque;
        result.reason = format!(
            "поток пересобирается, но буфер травится: коробка глотает «{}», сервер выбрасывает",
            first.name
        );
    }
    let others = result
        .unplannable
        .iter()
        .skip(1)
        .map(|poison| format!("«{}»", poison.name))
        .collect::<Vec<_>>()
        .join(", ");
    append_reason(
        &mut result.reason,
        &format!(
            "; приём «{}» сработал, но планом не задаётся: {}{}{}",
            first.name,
            first.reason,
            if others.is_empty() {
                ""
            } else {
                "; также "
            },
            others
        ),
    );
}

/// Выполнить эталонное дерево TCP: базовую пробу, разрезание, сборку и поиск границы префикса.
pub fn run_with_backend<B: ProbeBackend>(
    address: &str,
    trigger: &Trigger,
    options: ClassifyOptions,
    backend: &mut B,
) -> ClassifyResult {
    run_with_backend_progress(address, trigger, options, backend, &mut |_, _, _, _| {})
}

/// Run the classifier while reporting each active question and completed probe.
/// The callback runs on the measuring worker so callers can publish live progress.
pub fn run_with_backend_progress<B: ProbeBackend>(
    address: &str,
    trigger: &Trigger,
    mut options: ClassifyOptions,
    backend: &mut B,
    progress: &mut dyn FnMut(&str, usize, usize, usize),
) -> ClassifyResult {
    crate::raw_probe::flush_pending_rst_releases();
    options = configured_options(options);
    let start = Instant::now();
    let mut result = ClassifyResult::new(address, options.repeats);

    let target = match parse_target(address) {
        Ok(target) => target,
        Err(reason) => {
            result.reason = reason.to_owned();
            result.duration = start.elapsed();
            return result;
        }
    };
    if !options.allow_loopback
        && target
            .host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback() || address.is_unspecified())
    {
        result.reason =
            "цель указывает на localhost — мерить нечего, проверь как резолвится имя".into();
        result.duration = start.elapsed();
        return result;
    }
    if trigger.payload.len() < 2 {
        result.reason = "триггер короче двух байт — резать нечего".into();
        result.duration = start.elapsed();
        return result;
    }
    if stopped(&options) {
        finish_cancelled(&mut result, &options, start);
        return result;
    }

    let mut base = measure_baseline(backend, &target, trigger, &options, &mut result, progress);
    if stopped(&options) {
        finish_cancelled(&mut result, &options, start);
        return result;
    }

    if options.full_detect_semantics
        && base.pass == 0
        && base.error.as_ref().is_some_and(ProbeError::is_dial_timeout)
    {
        let mut slow_options = options.clone();
        slow_options.timeout = options.timeout.saturating_mul(2);
        slow_options.seed_whole = None;
        base = measure_baseline(
            backend,
            &target,
            trigger,
            &slow_options,
            &mut result,
            progress,
        );
        if stopped(&options) {
            finish_cancelled(&mut result, &options, start);
            return result;
        }
    }

    if options.full_detect_semantics && base.pass == 0 && base.errors > 0 {
        if base.error.as_ref().is_some_and(ProbeError::is_dial_timeout) {
            result.verdict = Verdict::Flaky;
            result.reason = format!(
                "наш срок на подключение {} мс истёк — замер не состоялся: {}",
                options.timeout.as_millis(),
                base.error
                    .as_ref()
                    .expect("error count without error")
                    .message()
            );
        } else {
            result.verdict = Verdict::Unreachable;
            result.reason = format!(
                "нет TCP до цели: {}",
                base.error
                    .as_ref()
                    .expect("error count without error")
                    .message()
            );
        }
        finish(&mut result, &options, start);
        return result;
    }
    if !options.full_detect_semantics && base.pass == 0 && base.errors == options.repeats {
        result.reason = format!(
            "нет TCP до цели: ни один из {} опытов не состоялся",
            options.repeats
        );
        result.verdict = Verdict::Unreachable;
        finish(&mut result, &options, start);
        return result;
    }
    if base.pass == options.repeats {
        if options.confirm_clear {
            let mut confirm_options = options.clone();
            confirm_options.repeats = CLEAR_CONFIRM_REPEATS;
            confirm_options.seed_whole = None;
            let confirm = measure(
                backend,
                &target,
                trigger,
                &confirm_options,
                &mut result,
                MeasureSpec {
                    name: "whole-confirm",
                    cuts: &[],
                    gap: options.write_gap,
                    until_pass: false,
                },
                progress,
            );
            if stopped(&options) {
                finish_cancelled(&mut result, &options, start);
                return result;
            }
            if confirm.errors > 0 {
                result.verdict = Verdict::Flaky;
                result.reason = format!(
                    "подтверждение базы: {} из {} опытов не состоялись — ошибка транспорта, а не решение коробки",
                    confirm.errors, CLEAR_CONFIRM_REPEATS
                );
                finish(&mut result, &options, start);
                return result;
            }
            let total_pass = base.pass + confirm.pass;
            let total_repeats = options.repeats + CLEAR_CONFIRM_REPEATS;
            if total_pass != total_repeats {
                result.verdict = Verdict::Flaky;
                result.reason = format!(
                    "база не подтвердилась: итого {} из {} — ложный clear дороже честного flaky",
                    total_pass, total_repeats
                );
                finish(&mut result, &options, start);
                return result;
            }
            if base.unmarked || confirm.unmarked {
                result.verdict = Verdict::Inconclusive;
                result.reason = format!(
                    "триггер прошёл ({total_pass}/{total_repeats}), но без подтверждённой метки SO_MARK — clear не принимается"
                );
                finish(&mut result, &options, start);
                return result;
            }
        }
        if base.unmarked {
            result.verdict = Verdict::Inconclusive;
            result.reason =
                "триггер прошёл, но без подтверждённой метки SO_MARK — clear не принимается".into();
            finish(&mut result, &options, start);
            return result;
        }

        result.verdict = Verdict::Clear;
        result.reason = "триггер проходит как есть — обходить нечего".into();
        let sni = trigger.name.strip_prefix("tls:").unwrap_or("");
        if !sni.is_empty() {
            let response = probe_response(
                &target.host,
                target.port,
                sni,
                ResponseOptions {
                    repeats: options.repeats,
                    timeout: options.timeout,
                    mark: options.mark,
                },
            );
            result.probes = result.probes.saturating_add(response.probes);
            if response.verdict == ResponseVerdict::Blocked {
                result.verdict = Verdict::Response;
                result.reason = response.reason.clone();
            } else if matches!(
                response.verdict,
                ResponseVerdict::NotApplicable | ResponseVerdict::Flaky
            ) {
                append_reason(
                    &mut result.reason,
                    &format!(" (ответное направление: {})", response.reason),
                );
            }
            result.response = Some(response);
        } else if trigger.accept == Accept::ServerHello {
            append_reason(
                &mut result.reason,
                " (ответное направление не проверено: нет SNI)",
            );
        }
        finish(&mut result, &options, start);
        return result;
    }
    if base.pass > 0 {
        result.verdict = Verdict::Flaky;
        result.reason = format!(
            "база не воспроизводится: {} прошло из {}",
            base.pass, options.repeats
        );
        finish(&mut result, &options, start);
        return result;
    }

    let one = measure(
        backend,
        &target,
        trigger,
        &options,
        &mut result,
        MeasureSpec {
            name: "split",
            cuts: &[1],
            gap: options.write_gap,
            until_pass: false,
        },
        progress,
    );
    if let Some(error) = &one.error {
        result.reason = format!("ошибка замера разреза: {}", error.message());
        finish(&mut result, &options, start);
        return result;
    }
    if one.pass == 0 {
        let mut control_ok = options.control.is_none();
        if let Some(control) = &options.control {
            let measured = measure(
                backend,
                &target,
                control,
                &options,
                &mut result,
                MeasureSpec {
                    name: "control",
                    cuts: &[],
                    gap: options.write_gap,
                    until_pass: options.full_detect_semantics,
                },
                progress,
            );
            if !options.full_detect_semantics {
                if measured.errors > 0 {
                    result.verdict = Verdict::Flaky;
                    result.reason = format!(
                        "контроль другим именем: {} из {} опытов не состоялись — ошибка транспорта, а не решение коробки",
                        measured.errors, options.repeats
                    );
                    finish(&mut result, &options, start);
                    return result;
                }
                if measured.pass > 0 && measured.pass < options.repeats {
                    result.verdict = Verdict::Flaky;
                    result.reason = format!(
                        "контроль другим именем не воспроизводится: {} из {}",
                        measured.pass, options.repeats
                    );
                    finish(&mut result, &options, start);
                    return result;
                }
            }
            control_ok = if options.full_detect_semantics {
                measured.pass > 0
            } else {
                measured.pass == options.repeats
            };
            if !options.full_detect_semantics && control_ok && base.unproven + one.unproven > 0 {
                result.verdict = Verdict::Inconclusive;
                result.reason = format!(
                    "на триггер ответили не доказательством прохода ({} опытов из {}): алерт инжектируют и коробки, и серверы — вердикта нет",
                    base.unproven + one.unproven,
                    options.repeats * 2
                );
                finish(&mut result, &options, start);
                return result;
            }
            if !options.full_detect_semantics && !control_ok && measured.unproven > 0 {
                result.verdict = Verdict::Inconclusive;
                result.reason = format!(
                    "контроль другим именем ответил не записью TLS ({} из {}) — это не проход и не молчание; вердикта нет",
                    measured.unproven, options.repeats
                );
                finish(&mut result, &options, start);
                return result;
            }
        }
        if !control_ok {
            let index = add_observation(&mut result, "neutral-ack", &[], Duration::ZERO);
            let mut observed = true;
            progress("neutral-ack", result.probes, 0, 0);
            for _ in 0..options.repeats {
                if stopped(&options) {
                    observed = false;
                    break;
                }
                match backend.neutral_ack(
                    &target,
                    options.timeout,
                    options.mark,
                    options.cancel.as_deref(),
                ) {
                    Ok(true) => {
                        result.probes += 1;
                        result.trace[index].pass += 1;
                        break;
                    }
                    Ok(false) => {
                        result.probes += 1;
                        result.trace[index].fail += 1;
                    }
                    Err(error) => {
                        result.trace[index].error = Some(error.message().to_owned());
                        if !error.is_unsupported() {
                            result.probes += 1;
                            result.trace[index].fail += 1;
                        }
                        observed = false;
                        break;
                    }
                }
                progress(
                    "neutral-ack",
                    result.probes,
                    result.trace[index].pass,
                    result.trace[index].fail,
                );
            }
            let ack = &result.trace[index];
            if observed && ack.pass == 0 && ack.fail == options.repeats {
                result.verdict = Verdict::Address;
                result.reason = format!(
                    "рукопожатие проходит, но сервер не подтвердил ни одного нейтрального байта (0 из {}): данные к адресу режутся целиком, содержимое ни при чём — обходить содержимым нечего",
                    options.repeats
                );
                finish(&mut result, &options, start);
                return result;
            }
        }

        let raw_available = !options.no_raw && backend.raw_supported();
        result.raw_usable = raw_available;
        if result.raw_usable {
            match backend.sweep_poisons_with_progress(
                &target,
                trigger,
                &options,
                &mut result,
                progress,
            ) {
                Ok(Some(hit)) => {
                    result.verdict = Verdict::Poisonable;
                    result.boundary = Some(0);
                    result.strategy = Some(hit.strategy.clone());
                    result.reason = format!(
                        "поток пересобирается, но буфер травится: коробка глотает «{}», сервер выбрасывает",
                        hit.name
                    );
                    result.hit = Some(hit);
                    append_unplannable_reason(&mut result);
                    finish(&mut result, &options, start);
                    return result;
                }
                Ok(None) => {}
                Err(error) => {
                    result.raw_usable = false;
                    result.trace.push(Observation {
                        probe: "raw-selftest".into(),
                        cuts: Vec::new(),
                        delay: Duration::ZERO,
                        pass: 0,
                        fail: 1,
                        error: Some(error.message().to_owned()),
                    });
                }
            }
        }
        if result.stopped || stopped(&options) {
            finish_cancelled(&mut result, &options, start);
            return result;
        }
        if !result.unplannable.is_empty() {
            append_unplannable_reason(&mut result);
            finish(&mut result, &options, start);
            return result;
        }
        if !control_ok {
            if options.control_vouched {
                result.verdict = Verdict::Address;
                result.reason = "молчит и контроль на имени, за которое ручается оператор, и ни одна гипотеза не сработала — похоже на блок по адресу".into();
            } else {
                result.verdict = Verdict::Inconclusive;
                result.reason = "контроль не ответил и отравить не удалось: базы нет, отличить блок по адресу от нехватки гипотез нельзя".into();
            }
            finish(&mut result, &options, start);
            return result;
        }
        result.verdict = Verdict::Opaque;
        result.reason = if !result.raw_usable {
            if raw_available {
                let detail = result
                    .trace
                    .iter()
                    .rev()
                    .find(|observation| observation.probe == "raw-selftest")
                    .and_then(|observation| observation.error.as_deref())
                    .unwrap_or("самопроверка не прошла");
                format!(
                    "разрез не помогает, контроль проходит; сырые зонды недоступны: {detail} — результата поиска нет"
                )
            } else {
                "разрез не помогает, а контроль проходит: решение по содержимому, поток пересобирается — сырые зонды выключены или недоступны".into()
            }
        } else {
            "разрез не помогает, контроль проходит, отравить буфер не удалось — содержимое важно, но чем брать, зондами не нашли".into()
        };
        finish(&mut result, &options, start);
        return result;
    }
    if one.pass != options.repeats {
        result.verdict = Verdict::Flaky;
        result.reason = format!(
            "разрез pos=1 не воспроизводится: {} из {}",
            one.pass, options.repeats
        );
        finish(&mut result, &options, start);
        return result;
    }

    let long = measure(
        backend,
        &target,
        trigger,
        &options,
        &mut result,
        MeasureSpec {
            name: "split-long",
            cuts: &[1],
            gap: options.long_gap,
            until_pass: false,
        },
        progress,
    );
    if let Some(error) = &long.error {
        result.reason = format!("ошибка замера разреза: {}", error.message());
        finish(&mut result, &options, start);
        return result;
    }
    let reassembles = long.pass == 0;
    result.reassembles = Some(reassembles);

    let mut hi = trigger.payload.len() - 1;
    let last = measure(
        backend,
        &target,
        trigger,
        &options,
        &mut result,
        MeasureSpec {
            name: "split",
            cuts: &[hi],
            gap: options.write_gap,
            until_pass: false,
        },
        progress,
    );
    if let Some(error) = &last.error {
        result.reason = format!("ошибка замера разреза: {}", error.message());
        finish(&mut result, &options, start);
        return result;
    }
    if last.pass == options.repeats {
        result.verdict = Verdict::WholePacket;
        result.reason = "проходит любой разрез — матчер требует пакет целиком".into();
        result.split_pos = Some(1);
        result.strategy = Some(strategy_for(1));
        finish(&mut result, &options, start);
        return result;
    }

    let mut lo = 1;
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        let measured = measure(
            backend,
            &target,
            trigger,
            &options,
            &mut result,
            MeasureSpec {
                name: "split",
                cuts: &[mid],
                gap: options.write_gap,
                until_pass: false,
            },
            progress,
        );
        if let Some(error) = &measured.error {
            result.reason = format!("ошибка замера разреза: {}", error.message());
            finish(&mut result, &options, start);
            return result;
        }
        if measured.pass == options.repeats {
            lo = mid;
        } else if measured.pass == 0 {
            hi = mid;
        } else {
            result.verdict = Verdict::Flaky;
            result.reason = format!(
                "разрез pos={mid} не воспроизводится: {} из {}",
                measured.pass, options.repeats
            );
            finish(&mut result, &options, start);
            return result;
        }
    }

    result.verdict = Verdict::Prefix;
    result.boundary = Some(hi);
    result.split_pos = Some(1);
    result.strategy = Some(strategy_for(1));
    result.reason =
        format!("префиксный матчер: сигнатура кончается на байте {hi}, разрез левее её ломает");
    if reassembles {
        result.reason.push_str(&format!(
            "; при паузе {}ms блок возвращается — у коробки есть буфер пересборки",
            options.long_gap.as_millis()
        ));
    }
    finish(&mut result, &options, start);
    result
}

/// Run only the donor's whole-trigger question so confirmed catalog plans can
/// be tried before the full classifier. A complete result can seed that later
/// classifier without repeating these same probes.
pub fn run_base_with_backend_progress<B: ProbeBackend>(
    address: &str,
    trigger: &Trigger,
    mut options: ClassifyOptions,
    backend: &mut B,
    progress: &mut dyn FnMut(&str, usize, usize, usize),
) -> BaseProbe {
    crate::raw_probe::flush_pending_rst_releases();
    options = configured_options(options);
    options.seed_whole = None;
    let target = match parse_target(address) {
        Ok(target) => target,
        Err(_) => return BaseProbe::default(),
    };
    if !options.allow_loopback
        && target
            .host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback() || address.is_unspecified())
        || trigger.payload.len() < 2
    {
        return BaseProbe::default();
    }
    let mut result = ClassifyResult::new(address, options.repeats);
    let base = measure_baseline(backend, &target, trigger, &options, &mut result, progress);
    let complete = base.pass.saturating_add(base.fail) >= options.repeats
        && !base.error.as_ref().is_some_and(ProbeError::is_dial_timeout);
    let seed_whole = complete.then(|| SeedWhole {
        input: seed_input(trigger, &target),
        repeats: options.repeats,
        pass: base.pass,
        fail: base.fail,
        errors: base.errors,
        unproven: base.unproven,
        marked: !base.unmarked,
        error: base.error.as_ref().map(|error| error.message().to_owned()),
    });
    BaseProbe {
        blocked: seed_whole
            .as_ref()
            .is_some_and(|seed| seed.pass == 0 && seed.fail == seed.repeats && seed.errors == 0),
        seed_whole,
        probes: result.probes,
    }
}

fn configured_options(mut options: ClassifyOptions) -> ClassifyOptions {
    if options.repeats == 0 {
        options.repeats = 3;
    }
    if options.timeout.is_zero() {
        options.timeout = Duration::from_secs(6);
    }
    if options.write_gap.is_zero() {
        options.write_gap = Duration::from_millis(60);
    }
    if options.long_gap.is_zero() {
        options.long_gap = Duration::from_millis(700);
    }
    options
}

fn measure_baseline<B: ProbeBackend>(
    backend: &mut B,
    target: &ProbeTarget,
    trigger: &Trigger,
    options: &ClassifyOptions,
    result: &mut ClassifyResult,
    progress: &mut dyn FnMut(&str, usize, usize, usize),
) -> Tally {
    measure(
        backend,
        target,
        trigger,
        options,
        result,
        MeasureSpec {
            name: "whole",
            cuts: &[],
            gap: options.write_gap,
            until_pass: false,
        },
        progress,
    )
}

/// Запустить классификатор через помеченные TCP-сокеты узла.
pub fn run(address: &str, trigger: &Trigger, options: ClassifyOptions) -> ClassifyResult {
    run_with_backend(address, trigger, options, &mut TcpProbeBackend)
}

fn strategy_for(pos: usize) -> String {
    format!("--lua-desync=multisplit:payload=unknown:dir=out:pos={pos}")
}

fn finish(result: &mut ClassifyResult, options: &ClassifyOptions, start: Instant) {
    result.stopped = stopped(options);
    result.raw_dials = current_raw_dial_count().saturating_sub(result.raw_dial_base);
    result.duration = start.elapsed();
    result.rst_rule_failures = usize::try_from(
        crate::raw_probe::rst_rule_failure_count().saturating_sub(result.rst_rule_failure_base),
    )
    .unwrap_or(usize::MAX);
}

fn finish_cancelled(result: &mut ClassifyResult, options: &ClassifyOptions, start: Instant) {
    result.verdict = Verdict::Inconclusive;
    result.reason = format!(
        "замер брошен по требованию остановки на {}-м зонде — о цели не сказано ничего",
        result.probes
    );
    finish(result, options, start);
}

fn current_raw_dial_count() -> u64 {
    #[cfg(target_os = "linux")]
    {
        crate::raw_probe::raw_dial_count()
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(test)]
mod raw_connect_fallback_tests {
    use super::{
        ClassifyOptions, ClassifyResult, MeasureSpec, ProbeBackend, ProbeError, ProbeOutcome,
        ProbeRequest, ProbeTarget, Tally, Trigger, Verdict, measure,
    };
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    struct ScriptedBackend {
        outcomes: VecDeque<Result<ProbeOutcome, ProbeError>>,
        control_results: VecDeque<Result<(), ProbeError>>,
        targets: Vec<(String, u16)>,
        controls: Vec<(SocketAddr, Duration, Option<u32>)>,
        cancel_after: Option<(Arc<AtomicBool>, usize)>,
    }

    impl ProbeBackend for ScriptedBackend {
        fn probe(&mut self, request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
            self.probe_outcome(request).map(ProbeOutcome::is_accepted)
        }

        fn probe_outcome(&mut self, request: ProbeRequest<'_>) -> Result<ProbeOutcome, ProbeError> {
            self.targets
                .push((request.target.host.clone(), request.target.port));
            if let Some((cancel, after)) = &self.cancel_after
                && self.targets.len() == *after
            {
                cancel.store(true, Ordering::Relaxed);
            }
            self.outcomes.pop_front().expect("scripted probe result")
        }

        fn tcp_control_peer(
            &mut self,
            peer: SocketAddr,
            timeout: Duration,
            mark: Option<u32>,
        ) -> Result<(), ProbeError> {
            self.controls.push((peer, timeout, mark));
            self.control_results.pop_front().unwrap_or(Ok(()))
        }
    }

    fn fixture(
        outcomes: &[Result<ProbeOutcome, ProbeError>],
        control_results: &[Result<(), ProbeError>],
    ) -> (
        ScriptedBackend,
        ProbeTarget,
        Trigger,
        ClassifyOptions,
        ClassifyResult,
    ) {
        let target = ProbeTarget {
            host: "split.example".into(),
            port: 443,
        };
        let trigger = Trigger {
            name: "fixture".into(),
            payload: b"ABCD".to_vec(),
            accept: super::Accept::Any,
        };
        let options = ClassifyOptions {
            repeats: 1,
            timeout: Duration::from_millis(600),
            mark: Some(0x2d),
            ..ClassifyOptions::default()
        };
        let result = ClassifyResult::new("split.example:443", 1);
        (
            ScriptedBackend {
                outcomes: outcomes.iter().cloned().collect(),
                control_results: control_results.iter().cloned().collect(),
                targets: Vec::new(),
                controls: Vec::new(),
                cancel_after: None,
            },
            target,
            trigger,
            options,
            result,
        )
    }

    fn raw_timeout(peer: SocketAddr) -> Result<ProbeOutcome, ProbeError> {
        Err(ProbeError::RawConnectTimeout {
            message: "classify: SYN-ACK не пришёл".into(),
            peer,
        })
    }

    #[test]
    fn clear_requires_two_additional_confirmation_probes() {
        let mut backend = ScriptedBackend {
            outcomes: [
                Ok(ProbeOutcome::Accepted),
                Ok(ProbeOutcome::Accepted),
                Ok(ProbeOutcome::Accepted),
                Ok(ProbeOutcome::Rejected),
                Ok(ProbeOutcome::Rejected),
            ]
            .into(),
            control_results: VecDeque::new(),
            targets: Vec::new(),
            controls: Vec::new(),
            cancel_after: None,
        };
        let trigger = Trigger {
            name: "fixture".into(),
            payload: b"ABCD".to_vec(),
            accept: super::Accept::Any,
        };
        let options = ClassifyOptions {
            repeats: 3,
            allow_loopback: true,
            ..ClassifyOptions::default()
        };

        let result = super::run_with_backend("127.0.0.1:443", &trigger, options, &mut backend);

        assert_eq!(result.verdict, Verdict::Flaky);
        assert_eq!(result.probes, 5);
        assert_eq!(backend.targets.len(), 5);
    }

    #[test]
    fn confirmed_clear_uses_five_successful_probes() {
        let mut backend = ScriptedBackend {
            outcomes: vec![Ok(ProbeOutcome::Accepted); 5].into(),
            control_results: VecDeque::new(),
            targets: Vec::new(),
            controls: Vec::new(),
            cancel_after: None,
        };
        let trigger = Trigger {
            name: "fixture".into(),
            payload: b"ABCD".to_vec(),
            accept: super::Accept::Any,
        };
        let options = ClassifyOptions {
            repeats: 3,
            allow_loopback: true,
            ..ClassifyOptions::default()
        };

        let result = super::run_with_backend("127.0.0.1:443", &trigger, options, &mut backend);

        assert_eq!(result.verdict, Verdict::Clear);
        assert_eq!(result.probes, 5);
        assert_eq!(backend.targets.len(), 5);
    }

    #[test]
    fn unmarked_success_is_inconclusive_after_confirmation_probes() {
        let mut backend = ScriptedBackend {
            outcomes: vec![Ok(ProbeOutcome::AcceptedUnmarked); 5].into(),
            control_results: VecDeque::new(),
            targets: Vec::new(),
            controls: Vec::new(),
            cancel_after: None,
        };
        let trigger = Trigger {
            name: "fixture".into(),
            payload: b"ABCD".to_vec(),
            accept: super::Accept::Any,
        };
        let options = ClassifyOptions {
            repeats: 3,
            allow_loopback: true,
            mark: Some(0x2d),
            ..ClassifyOptions::default()
        };

        let result = super::run_with_backend("127.0.0.1:443", &trigger, options, &mut backend);

        assert_eq!(result.verdict, Verdict::Inconclusive);
        assert_eq!(result.probes, 5);
        assert_eq!(backend.targets.len(), 5);
    }

    #[test]
    fn probe_outcomes_retain_mark_failure_state() {
        assert_eq!(
            ProbeOutcome::Accepted.with_mark_status(false),
            ProbeOutcome::AcceptedUnmarked
        );
        assert_eq!(
            ProbeOutcome::Rejected.with_mark_status(false),
            ProbeOutcome::RejectedUnmarked
        );
        assert_eq!(
            ProbeOutcome::Unproven.with_mark_status(false),
            ProbeOutcome::UnprovenUnmarked
        );
        assert_eq!(
            ProbeOutcome::AcceptedUnmarked.with_mark_status(true),
            ProbeOutcome::Accepted
        );
    }

    #[test]
    fn probe_timeout_ceiling_matches_d2o() {
        assert_eq!(
            super::effective_probe_timeout(Duration::ZERO),
            Duration::from_secs(5)
        );
        assert_eq!(
            super::effective_probe_timeout(Duration::from_secs(3)),
            Duration::from_secs(3)
        );
        let timeout = super::effective_probe_timeout(Duration::from_secs(7));
        assert_eq!(timeout, Duration::from_secs(5));
        assert_eq!(timeout.as_millis(), 5_000);
    }

    #[test]
    fn confirmation_transport_error_is_flaky() {
        let mut backend = ScriptedBackend {
            outcomes: [
                Ok(ProbeOutcome::Accepted),
                Ok(ProbeOutcome::Accepted),
                Ok(ProbeOutcome::Accepted),
                Err(ProbeError::DialTimeout("confirm timed out".into())),
                Ok(ProbeOutcome::Accepted),
            ]
            .into(),
            control_results: VecDeque::new(),
            targets: Vec::new(),
            controls: Vec::new(),
            cancel_after: None,
        };
        let trigger = Trigger {
            name: "fixture".into(),
            payload: b"ABCD".to_vec(),
            accept: super::Accept::Any,
        };
        let options = ClassifyOptions {
            repeats: 3,
            allow_loopback: true,
            ..ClassifyOptions::default()
        };

        let result = super::run_with_backend("127.0.0.1:443", &trigger, options, &mut backend);

        assert_eq!(result.verdict, Verdict::Flaky);
        assert_eq!(result.probes, 5);
        assert!(result.reason.contains("1 из 2 опытов не состоялись"));
    }

    #[test]
    fn cancellation_after_baseline_prevents_clear_confirmation() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut backend = ScriptedBackend {
            outcomes: vec![Ok(ProbeOutcome::Accepted); 3].into(),
            control_results: VecDeque::new(),
            targets: Vec::new(),
            controls: Vec::new(),
            cancel_after: Some((cancel.clone(), 3)),
        };
        let trigger = Trigger {
            name: "fixture".into(),
            payload: b"ABCD".to_vec(),
            accept: super::Accept::Any,
        };
        let options = ClassifyOptions {
            repeats: 3,
            allow_loopback: true,
            cancel: Some(cancel),
            ..ClassifyOptions::default()
        };

        let result = super::run_with_backend("127.0.0.1:443", &trigger, options, &mut backend);

        assert_eq!(result.verdict, Verdict::Inconclusive);
        assert_eq!(result.probes, 3);
        assert!(result.stopped);
        assert_eq!(backend.targets.len(), 3);
    }

    #[test]
    fn all_baseline_connect_failures_are_unreachable_without_extra_retries() {
        let mut backend = ScriptedBackend {
            outcomes: vec![Err(ProbeError::DialTimeout("dial timed out".into())); 6].into(),
            control_results: VecDeque::new(),
            targets: Vec::new(),
            controls: Vec::new(),
            cancel_after: None,
        };
        let trigger = Trigger {
            name: "fixture".into(),
            payload: b"ABCD".to_vec(),
            accept: super::Accept::Any,
        };
        let options = ClassifyOptions {
            repeats: 3,
            allow_loopback: true,
            ..ClassifyOptions::default()
        };

        let result = super::run_with_backend("127.0.0.1:443", &trigger, options, &mut backend);

        assert_eq!(result.verdict, Verdict::Unreachable);
        assert_eq!(result.probes, 3);
        assert_eq!(backend.targets.len(), 3);
    }

    #[test]
    fn partial_baseline_transport_errors_continue_to_the_split_question() {
        let mut backend = ScriptedBackend {
            outcomes: [
                Ok(ProbeOutcome::Rejected),
                Ok(ProbeOutcome::Rejected),
                Err(ProbeError::Transport("connection refused".into())),
                Err(ProbeError::Transport("connection refused".into())),
                Err(ProbeError::Transport("connection refused".into())),
                Err(ProbeError::Transport("connection refused".into())),
            ]
            .into(),
            control_results: VecDeque::new(),
            targets: Vec::new(),
            controls: Vec::new(),
            cancel_after: None,
        };
        let trigger = Trigger {
            name: "fixture".into(),
            payload: b"ABCD".to_vec(),
            accept: super::Accept::Any,
        };
        let options = ClassifyOptions {
            repeats: 3,
            allow_loopback: true,
            ..ClassifyOptions::default()
        };

        let result = super::run_with_backend("127.0.0.1:443", &trigger, options, &mut backend);

        assert_eq!(result.verdict, Verdict::Flaky);
        assert_eq!(result.probes, 6);
        assert_eq!(backend.targets.len(), 6);
    }

    #[test]
    fn unproven_trigger_responses_keep_the_c_inconclusive_verdict() {
        let (mut backend, _, trigger, mut options, _) = fixture(&[], &[]);
        backend.outcomes = [
            Ok(ProbeOutcome::Unproven),
            Ok(ProbeOutcome::Unproven),
            Ok(ProbeOutcome::Unproven),
            Ok(ProbeOutcome::Unproven),
            Ok(ProbeOutcome::Unproven),
            Ok(ProbeOutcome::Unproven),
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Accepted),
        ]
        .into();
        options.repeats = 3;
        options.control = Some(Trigger {
            name: "control".into(),
            payload: b"WXYZ".to_vec(),
            accept: super::Accept::Any,
        });
        options.allow_loopback = true;

        let result = super::run_with_backend("127.0.0.1:443", &trigger, options, &mut backend);

        assert_eq!(result.verdict, Verdict::Inconclusive);
        assert_eq!(result.probes, 9);
    }

    #[test]
    fn seeded_baseline_preserves_unproven_response_counts() {
        let target = "192.0.2.44:443";
        let trigger = Trigger {
            name: "fixture".into(),
            payload: b"ABCD".to_vec(),
            accept: super::Accept::Any,
        };
        let mut base_backend = ScriptedBackend {
            outcomes: vec![Ok(ProbeOutcome::Unproven); 3].into(),
            control_results: VecDeque::new(),
            targets: Vec::new(),
            controls: Vec::new(),
            cancel_after: None,
        };
        let base = super::run_base_with_backend_progress(
            target,
            &trigger,
            ClassifyOptions {
                repeats: 3,
                ..ClassifyOptions::default()
            },
            &mut base_backend,
            &mut |_, _, _, _| {},
        );
        assert_eq!(base.seed_whole.as_ref().map(|seed| seed.unproven), Some(3));

        let mut classifier_backend = ScriptedBackend {
            outcomes: vec![
                Ok(ProbeOutcome::Unproven),
                Ok(ProbeOutcome::Unproven),
                Ok(ProbeOutcome::Unproven),
                Ok(ProbeOutcome::Accepted),
                Ok(ProbeOutcome::Accepted),
                Ok(ProbeOutcome::Accepted),
            ]
            .into(),
            control_results: VecDeque::new(),
            targets: Vec::new(),
            controls: Vec::new(),
            cancel_after: None,
        };
        let options = ClassifyOptions {
            repeats: 3,
            control: Some(Trigger {
                name: "control".into(),
                payload: b"WXYZ".to_vec(),
                accept: super::Accept::Any,
            }),
            seed_whole: base.seed_whole,
            ..ClassifyOptions::default()
        };

        let result = super::run_with_backend(target, &trigger, options, &mut classifier_backend);

        assert_eq!(result.verdict, Verdict::Inconclusive);
        assert_eq!(classifier_backend.targets.len(), 6);
    }

    #[test]
    fn partial_control_response_is_flaky_after_all_repeats() {
        let (mut backend, _, trigger, mut options, _) = fixture(&[], &[]);
        backend.outcomes = [
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Accepted),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
        ]
        .into();
        options.repeats = 3;
        options.control = Some(Trigger {
            name: "control".into(),
            payload: b"WXYZ".to_vec(),
            accept: super::Accept::Any,
        });
        options.allow_loopback = true;

        let result = super::run_with_backend("127.0.0.1:443", &trigger, options, &mut backend);

        assert_eq!(result.verdict, Verdict::Flaky);
        assert_eq!(result.probes, 9);
    }

    #[test]
    fn control_transport_error_after_a_pass_is_flaky() {
        let (mut backend, _, trigger, mut options, _) = fixture(&[], &[]);
        backend.outcomes = [
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Rejected),
            Ok(ProbeOutcome::Accepted),
            Err(ProbeError::Transport("connection refused".into())),
            Err(ProbeError::Transport("connection refused".into())),
        ]
        .into();
        options.repeats = 3;
        options.control = Some(Trigger {
            name: "control".into(),
            payload: b"WXYZ".to_vec(),
            accept: super::Accept::Any,
        });
        options.allow_loopback = true;

        let result = super::run_with_backend("127.0.0.1:443", &trigger, options, &mut backend);

        assert_eq!(result.verdict, Verdict::Flaky);
        assert_eq!(result.probes, 9);
    }

    fn run_measure(
        backend: &mut ScriptedBackend,
        target: &ProbeTarget,
        trigger: &Trigger,
        options: &ClassifyOptions,
        result: &mut ClassifyResult,
    ) -> Tally {
        run_measure_with_progress(
            backend,
            target,
            trigger,
            options,
            result,
            &mut |_, _, _, _| {},
        )
    }

    fn run_measure_with_progress(
        backend: &mut ScriptedBackend,
        target: &ProbeTarget,
        trigger: &Trigger,
        options: &ClassifyOptions,
        result: &mut ClassifyResult,
        progress: &mut dyn FnMut(&str, usize, usize, usize),
    ) -> Tally {
        measure(
            backend,
            target,
            trigger,
            options,
            result,
            MeasureSpec {
                name: "split",
                cuts: &[2],
                gap: Duration::ZERO,
                until_pass: false,
            },
            progress,
        )
    }

    #[test]
    fn raw_connect_timeout_runs_control_then_retries_once_on_the_same_peer() {
        let peer: SocketAddr = "192.0.2.44:443".parse().unwrap();
        let (mut backend, target, trigger, options, mut result) =
            fixture(&[raw_timeout(peer), Ok(ProbeOutcome::Accepted)], &[Ok(())]);

        let tally = run_measure(&mut backend, &target, &trigger, &options, &mut result);

        assert_eq!(tally.pass, 1);
        assert_eq!(tally.fail, 0);
        assert_eq!(tally.errors, 0);
        assert_eq!(result.probes, 3);
        assert_eq!(backend.targets[0], ("split.example".into(), 443));
        assert_eq!(backend.targets[1], ("192.0.2.44".into(), 443));
        assert_eq!(backend.controls, [(peer, options.timeout, options.mark)]);
        assert_eq!(result.trace[1].probe, "transport:raw-connect");
        assert_eq!(result.trace[1].fail, 1);
        assert_eq!(result.trace[2].probe, "transport:tcp-control");
        assert_eq!(result.trace[2].pass, 1);
    }

    #[test]
    fn recovered_raw_connect_timeout_does_not_spend_an_extra_repeat() {
        let peer: SocketAddr = "192.0.2.44:443".parse().unwrap();
        let (mut backend, target, trigger, mut options, mut result) = fixture(
            &[
                raw_timeout(peer),
                Ok(ProbeOutcome::Accepted),
                Ok(ProbeOutcome::Accepted),
                Ok(ProbeOutcome::Accepted),
            ],
            &[Ok(())],
        );
        options.repeats = 3;
        result.repeats = 3;
        let mut progress_events = Vec::new();
        let mut progress = |probe: &str, _: usize, pass: usize, fail: usize| {
            progress_events.push((probe.to_owned(), pass, fail));
        };

        let tally = run_measure_with_progress(
            &mut backend,
            &target,
            &trigger,
            &options,
            &mut result,
            &mut progress,
        );

        assert_eq!(tally.pass, 3);
        assert_eq!(tally.fail, 0);
        assert_eq!(result.probes, 5);
        let transport_units = progress_events
            .iter()
            .filter(|(probe, _, _)| probe.starts_with("transport:"))
            .map(|(_, pass, fail)| pass + fail)
            .sum::<usize>();
        let completed_question_units = progress_events
            .iter()
            .rev()
            .find(|(probe, _, _)| probe == "split")
            .map(|(_, pass, fail)| pass + fail)
            .unwrap();
        assert_eq!(transport_units + completed_question_units, 5);
        assert_eq!(backend.targets.len(), 4);
        assert_eq!(backend.controls.len(), 1);
    }

    #[test]
    fn failed_tcp_control_stops_without_retry_or_negative_probe() {
        let peer: SocketAddr = "192.0.2.44:443".parse().unwrap();
        let control_error = ProbeError::DialTimeout("dial tcp 192.0.2.44:443: i/o timeout".into());
        let (mut backend, target, trigger, options, mut result) = fixture(
            &[raw_timeout(peer), Ok(ProbeOutcome::Accepted)],
            &[Err(control_error.clone())],
        );

        let tally = run_measure(&mut backend, &target, &trigger, &options, &mut result);

        assert_eq!(tally.pass, 0);
        assert_eq!(tally.fail, 0);
        assert_eq!(tally.errors, 1);
        assert_eq!(tally.error, Some(control_error));
        assert_eq!(result.probes, 2);
        assert_eq!(backend.targets.len(), 1);
        assert_eq!(result.trace[2].probe, "transport:tcp-control");
        assert_eq!(result.trace[2].fail, 1);
    }

    #[test]
    fn repeated_raw_connect_timeout_is_reported_after_the_diagnostic_pair() {
        let peer: SocketAddr = "192.0.2.44:443".parse().unwrap();
        let (mut backend, target, trigger, options, mut result) =
            fixture(&[raw_timeout(peer), raw_timeout(peer)], &[Ok(())]);

        let tally = run_measure(&mut backend, &target, &trigger, &options, &mut result);

        assert_eq!(tally.pass, 0);
        assert_eq!(tally.fail, 0);
        assert_eq!(tally.errors, 1);
        assert_eq!(result.probes, 3);
        assert_eq!(backend.targets.len(), 2);
        assert_eq!(result.trace[3].probe, "transport:raw-connect-retry");
        assert_eq!(result.trace[3].fail, 1);
    }

    #[test]
    fn cancellation_after_raw_connect_does_not_start_the_tcp_control() {
        let peer: SocketAddr = "192.0.2.44:443".parse().unwrap();
        let (mut backend, target, trigger, mut options, mut result) =
            fixture(&[raw_timeout(peer), Ok(ProbeOutcome::Accepted)], &[Ok(())]);
        let cancel = Arc::new(AtomicBool::new(false));
        options.cancel = Some(Arc::clone(&cancel));
        let mut progress = |probe: &str, _, _, _| {
            if probe == "transport:raw-connect" {
                cancel.store(true, Ordering::Relaxed);
            }
        };

        let tally = run_measure_with_progress(
            &mut backend,
            &target,
            &trigger,
            &options,
            &mut result,
            &mut progress,
        );

        assert_eq!(tally.errors, 1);
        assert_eq!(tally.pass, 0);
        assert_eq!(result.probes, 1);
        assert!(backend.controls.is_empty());
    }

    #[test]
    fn cancellation_after_tcp_control_does_not_start_the_raw_retry() {
        let peer: SocketAddr = "192.0.2.44:443".parse().unwrap();
        let (mut backend, target, trigger, mut options, mut result) =
            fixture(&[raw_timeout(peer), Ok(ProbeOutcome::Accepted)], &[Ok(())]);
        let cancel = Arc::new(AtomicBool::new(false));
        options.cancel = Some(Arc::clone(&cancel));
        let mut progress = |probe: &str, _, _, _| {
            if probe == "transport:tcp-control" {
                cancel.store(true, Ordering::Relaxed);
            }
        };

        let tally = run_measure_with_progress(
            &mut backend,
            &target,
            &trigger,
            &options,
            &mut result,
            &mut progress,
        );

        assert_eq!(tally.errors, 1);
        assert_eq!(tally.pass, 0);
        assert_eq!(result.probes, 2);
        assert_eq!(backend.targets.len(), 1);
        assert_eq!(backend.controls.len(), 1);
    }
}
