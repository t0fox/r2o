use super::*;
use std::collections::BTreeSet;
use std::fmt::Write as _;

const PRIVATE: [&str; 5] = [
    "R2O_OUT",
    "R2O_IN",
    "R2O_INPUT",
    "R2O_DNS_OUT",
    "R2O_DNS_IN",
];
const NAT_TAG: &str = "r2o-raw-udp";
const PPE_TAG: &str = "r2o-ppe";

#[derive(Debug)]
pub(super) struct PpePorts {
    tcp: String,
    udp: String,
    http: String,
}

impl PpePorts {
    pub(super) fn detect(tcp: &str, http: &str) -> Result<Self> {
        Ok(Self {
            tcp: ports(&value("R2O_PPE_TCP_PORTS", tcp))?,
            udp: ports(&value("R2O_PPE_UDP_PORTS", "0:65535"))?,
            http: ports(&value("R2O_PPE_HTTP_PORTS", http))?,
        })
    }
}

fn tool(version: u8) -> &'static str {
    if version == 4 {
        "iptables"
    } else {
        "ip6tables"
    }
}

// Адаптация IPTables::new / has_wait из rust-iptables (Navid Fathollahzade, MIT).
fn supports_wait(version: &str) -> bool {
    let Some(version) = version
        .split_whitespace()
        .find_map(|field| field.strip_prefix('v'))
    else {
        return false;
    };
    let mut parts = version.split(|c: char| !c.is_ascii_digit());
    let major = parts.next().and_then(|part| part.parse::<u16>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u16>().ok());
    let patch = parts.next().and_then(|part| part.parse::<u16>().ok());
    matches!((major, minor, patch), (Some(major), Some(minor), Some(patch)) if (major, minor, patch) >= (1, 4, 20))
}

fn read_listing(version: u8, table: &str) -> Result<Output> {
    static V4_WAIT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    static V6_WAIT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let binary = tool(version);
    let cache = if version == 4 { &V4_WAIT } else { &V6_WAIT };
    let wait = *cache
        .get_or_init(|| command(binary, &["--version"], None).is_ok_and(|s| supports_wait(&s)));
    let args = ["-w", "-t", table, "-S"];
    let args = &args[usize::from(!wait)..];
    // Entware 1.4.21 polls the xtables lock at one-second intervals. NDM can
    // still be holding it when the ordinary two-second command deadline fires.
    if wait && Kind::detect() == Kind::Keenetic {
        invoke_before(binary, args, None, Instant::now() + Duration::from_secs(5))
    } else {
        invoke(binary, args, None)
    }
}

pub(super) fn list(version: u8, table: &str) -> Result<String> {
    checked(
        tool(version),
        &["-t", table, "-S"],
        read_listing(version, table)?,
    )
}

pub(super) fn print_listing(version: u8, table: &str) -> Result<()> {
    let output = read_listing(version, table)?;
    if !output.status.success() {
        io::stderr().write_all(&output.stderr)?;
        if let Some(code) = output.status.code() {
            std::process::exit(code);
        }
        return Err(error("iptables listing terminated before completion"));
    }
    io::stdout().write_all(&output.stdout)
}

struct Iptables<'a> {
    version: u8,
    table: &'a str,
}

impl FirewallBackend for Iptables<'_> {
    type Rule = str;

    fn apply(&self, script: &str) -> Result<()> {
        if script.is_empty() {
            return Ok(());
        }
        command(
            &format!("{}-restore", tool(self.version)),
            &["--noflush"],
            Some(&format!("*{}\n{script}COMMIT\n", self.table)),
        )
        .map(drop)
    }
}

#[derive(Default)]
struct Rules {
    chains: BTreeMap<String, Vec<String>>,
    hooks: BTreeMap<String, Vec<(usize, String)>>,
}

fn owned(platform: &Platform, table: &str, rule: &str) -> bool {
    let fields: Vec<_> = rule.split_whitespace().collect();
    let target = fields
        .windows(2)
        .find(|pair| pair[0] == "-j")
        .map(|pair| pair[1]);
    if table == "mangle" && target.is_some_and(|name| PRIVATE.contains(&name)) {
        return true;
    }
    let tag = fields
        .windows(2)
        .find(|pair| pair[0] == "--comment")
        .map(|pair| pair[1].trim_matches('"'));
    if table == "mangle" {
        return tag == Some(PPE_TAG);
    }
    tag == Some(NAT_TAG)
        || (target == Some("MASQUERADE")
            && fields.starts_with(&["-p", "udp", "-m", "mark", "--mark"])
            && fields.get(5).is_some_and(|selector| {
                if platform.kind == Kind::Keenetic {
                    exact_mark(selector, platform.raw)
                } else {
                    mark(selector).ok() == Some(platform.raw)
                }
            })
            && fields.len() == 8)
}

fn exact_mark(selector: &str, expected: u32) -> bool {
    let (value, mask) = selector.split_once('/').unwrap_or((selector, "0xffffffff"));
    mark(value).ok() == Some(expected) && mark(mask).ok() == Some(u32::MAX)
}

fn ppe_rule(rule: &str) -> bool {
    let mut fields = rule.split_whitespace();
    fields
        .find(|field| *field == "--comment")
        .and_then(|_| fields.next())
        .is_some_and(|tag| tag.trim_matches('"') == PPE_TAG)
}

fn split_state(platform: &Platform, table: &str, listing: &str) -> Rules {
    let mut result = Rules::default();
    let mut indices = BTreeMap::new();
    for line in listing.lines() {
        if let Some(chain) = line
            .strip_prefix("-N ")
            .filter(|chain| PRIVATE.contains(chain))
        {
            result.chains.entry(chain.to_owned()).or_default();
        }
        if let Some((chain, rule)) = line.strip_prefix("-A ").and_then(|s| s.split_once(' ')) {
            if PRIVATE.contains(&chain) {
                result
                    .chains
                    .entry(chain.to_owned())
                    .or_default()
                    .push(rule.to_owned());
            } else {
                let index = indices.entry(chain).or_insert(0);
                *index += 1;
                if owned(platform, table, rule) {
                    result
                        .hooks
                        .entry(chain.to_owned())
                        .or_default()
                        .push((*index, rule.to_owned()));
                }
            }
        }
    }
    result
}

fn render(before: &Rules, after: &Rules) -> String {
    let mut script = String::new();
    for (chain, rules) in &before.hooks {
        for (_, rule) in rules {
            writeln!(script, "-D {chain} {rule}").unwrap();
        }
    }
    for chain in before.chains.keys() {
        writeln!(script, "-F {chain}").unwrap();
    }
    for chain in before
        .chains
        .keys()
        .filter(|key| !after.chains.contains_key(*key))
    {
        writeln!(script, "-X {chain}").unwrap();
    }
    for chain in after
        .chains
        .keys()
        .filter(|key| !before.chains.contains_key(*key))
    {
        writeln!(script, "-N {chain}").unwrap();
    }
    for (chain, rules) in &after.chains {
        for rule in rules {
            writeln!(script, "-A {chain} {rule}").unwrap();
        }
    }
    for (chain, rules) in &after.hooks {
        for (index, rule) in rules {
            writeln!(script, "-I {chain} {index} {rule}").unwrap();
        }
    }
    script
}

impl Rules {
    fn push(&mut self, chain: &str, rule: String) {
        self.chains.entry(chain.to_owned()).or_default().push(rule);
    }

    fn hook(&mut self, chain: &str, rule: String) {
        let rules = self.hooks.entry(chain.to_owned()).or_default();
        rules.push((rules.len() + 1, rule));
    }
}

// D2K user_rules_save/user_rules_restore. An absent chain was lost during a
// rebuild, while a readable chain is authoritative even if its owner removed
// every exception. Keep the snapshots independent across chains and families.
fn owner_rules(
    platform: &Platform,
    version: u8,
    live: &Rules,
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut owners = BTreeMap::new();
    for chain in ["R2O_OUT", "R2O_IN"] {
        let snapshot = platform
            .run
            .join(format!("platform.owner.{version}.{chain}"));
        let saved = optional(&snapshot)?;
        let rules = if let Some(rules) = live.chains.get(chain) {
            let rules: Vec<_> = rules
                .iter()
                .filter(|rule| owner_rule(rule))
                .cloned()
                .collect();
            if rules.is_empty() {
                remove(&snapshot)?;
            } else {
                let text = rules.join("\n");
                if saved.as_deref() != Some(text.as_str()) {
                    atomic(&snapshot, &text)?;
                }
            }
            rules
        } else {
            saved
                .as_deref()
                .unwrap_or_default()
                .lines()
                .filter(|rule| owner_rule(rule))
                .map(str::to_owned)
                .collect()
        };
        if !rules.is_empty() {
            owners.insert(chain.to_owned(), rules);
        }
    }
    Ok(owners)
}

fn owner_rule(rule: &str) -> bool {
    rule.starts_with('-')
        && rule
            .split_once("-m comment --comment ")
            .is_some_and(|(_, rest)| !rest.trim_start_matches('"').starts_with("r2o-"))
}

#[derive(Clone, Copy)]
struct OptionalMatches {
    ppe: bool,
    late_stun: bool,
}

fn mangle(
    platform: &Platform,
    version: u8,
    sources: &str,
    sets: &BTreeSet<DnsSet>,
    broadcast: &[IpAddr],
    matches: OptionalMatches,
    owner_rules: &BTreeMap<String, Vec<String>>,
) -> Rules {
    let mut rules = Rules {
        chains: owner_rules.clone(),
        ..Rules::default()
    };
    let queue = platform.queue(version);
    let target = format!("-j NFQUEUE --queue-num {queue} --queue-bypass");
    let loopback = if version == 4 {
        "127.0.0.0/8"
    } else {
        "::1/128"
    };
    let multicast = if version == 4 {
        "224.0.0.0/4"
    } else {
        "ff00::/8"
    };
    let raw = platform.raw;
    let measure = platform.measure;
    let probe = platform.probe;
    let dns_probe_match = if platform.kind == Kind::Keenetic && probe != 0 {
        format!(" -m mark ! --mark {probe}")
    } else {
        String::new()
    };
    let early = format!("0:{}", platform.early);
    let voice = format!("{}:{}", platform.voice_window.0, platform.voice_window.1);
    let late = format!("{}:", u32::from(platform.early) + 1);
    for endpoint in platform
        .plain
        .iter()
        .filter(|endpoint| endpoint.version() == version)
    {
        let Endpoint {
            address,
            protocol,
            port,
            ..
        } = endpoint;
        let dest = format!("-p {protocol} -d {address} --dport {port}");
        rules.push("R2O_OUT", format!("{dest} -m owner --socket-exists -m mark --mark 0 -m conntrack --ctdir ORIGINAL ! --ctstate DNAT -j MARK --set-xmark {probe}/0xffffffff"));
        rules.push("R2O_OUT", format!("{dest} -m mark --mark {probe} -m conntrack --ctdir ORIGINAL ! --ctstate DNAT {target}"));
        if *protocol == "tcp" {
            rules.push("R2O_INPUT", format!("-p tcp -s {address} --sport {port} -m conntrack --ctdir REPLY ! --ctstate DNAT --tcp-flags SYN,ACK SYN,ACK {target}"));
        }
    }
    let mut endpoints = BTreeSet::new();
    for line in sources.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if let [_, address, port] = fields.as_slice()
            && let Ok(address) = address.parse::<IpAddr>()
            && address.is_ipv4() == (version == 4)
            && let Ok(port) = port.parse::<u16>()
            && port != 0
        {
            endpoints.insert((address, port));
        }
    }
    for (address, port) in endpoints {
        for proto in ["tcp", "udp"] {
            rules.push(
                "R2O_OUT",
                format!(
                    "-p {proto} -d {address} --dport {port} -m owner --socket-exists -j RETURN"
                ),
            );
            rules.push(
                "R2O_INPUT",
                format!("-p {proto} -s {address} --sport {port} -j RETURN"),
            );
        }
    }
    rules.push("R2O_DNS_OUT", format!("-m mark --mark {raw} -j RETURN"));
    if measure != 0 {
        rules.push("R2O_DNS_OUT", format!("-m mark --mark {measure} -j RETURN"));
    }
    for set in sets {
        let name = set.name(version);
        let (dst, src, out, incoming) = match set {
            DnsSet::Pair => ("dst,dst", "src,src", String::new(), String::new()),
            DnsSet::Net(proto, port) => (
                "dst",
                "src",
                format!("-p {proto} --dport {port} "),
                format!("-p {proto} --sport {port} "),
            ),
        };
        rules.push("R2O_OUT", format!("{out}-m owner --socket-exists -m set --match-set {name} {dst} -m conntrack ! --ctstate DNAT -j RETURN"));
        rules.push("R2O_DNS_OUT", format!("! -o lo {out}-m owner --socket-exists -m set --match-set {name} {dst} -m conntrack --ctdir ORIGINAL ! --ctstate DNAT -m connbytes --connbytes {early} --connbytes-dir original --connbytes-mode packets {target}"));
        rules.push("R2O_DNS_IN", format!("! -i lo {incoming}-m set --match-set {name} {src} -m conntrack --ctdir REPLY ! --ctstate DNAT -m connbytes --connbytes {early} --connbytes-dir reply --connbytes-mode packets {target}"));
    }
    for (chain, addr, port, selector, direction, count) in [
        (
            "R2O_OUT", "-d", "--dport", "--dports", "ORIGINAL", "original",
        ),
        ("R2O_IN", "-s", "--sport", "--sports", "REPLY", "reply"),
    ] {
        for flag in ["-s", "-d"] {
            rules.push(chain, format!("{flag} {loopback} -j RETURN"));
        }
        if chain == "R2O_OUT" && platform.kind == Kind::Keenetic {
            // При запросе роутера к собственному LAN-адресу пакет тоже идёт через lo.
            // Маршрут RTN_LOCAL не может подтвердить выход через WAN.
            rules.push(chain, "-o lo -j RETURN".into());
        }
        rules.push(chain, "-m conntrack --ctstate DNAT -j RETURN".into());
        if version == 4
            && let Some((ip, gate_port)) = platform.gate
        {
            rules.push(
                chain,
                format!("-p tcp {addr} {ip} {port} {gate_port} -j RETURN"),
            );
        }
        if chain == "R2O_OUT" {
            if version == 4 {
                if broadcast.is_empty() {
                    rules.push(chain, "-m addrtype --dst-type BROADCAST -j RETURN".into());
                } else {
                    for address in broadcast {
                        rules.push(chain, format!("-d {address} -j RETURN"));
                    }
                }
            }
            rules.push(chain, format!("-d {multicast} -j RETURN"));
            rules.push(chain, format!("-m mark --mark {raw} -j RETURN"));
            if measure != 0 {
                rules.push(chain, format!("-m mark --mark {measure} -j RETURN"));
            }
        }
        for proto in ["tcp", "udp"] {
            let except_probe = if chain == "R2O_OUT" {
                &dns_probe_match
            } else {
                ""
            };
            rules.push(
                chain,
                format!(
                    "-p {proto} -m multiport {selector} {}{except_probe} -j RETURN",
                    platform.dns
                ),
            );
        }
        let capture = |proto: &str, ports: &str, window: &str, flags: &str| {
            format!(
                "-p {proto} -m conntrack --ctdir {direction} -m multiport {selector} {ports} -m connbytes --connbytes {window} --connbytes-dir {count} --connbytes-mode packets {flags}{target}"
            )
        };
        for proto in ["tcp", "udp"] {
            rules.push(chain, capture(proto, &platform.ports, &early, ""));
        }
        rules.push(chain, capture("udp", &platform.voice, &voice, ""));
        if matches.late_stun {
            // D2K voice_late_rules: only UDP with the STUN cookie, never media.
            let cookie = if version == 4 {
                "0>>22&0x3C@12=0x2112A442"
            } else {
                "4>>8&0xFF=17&&52=0x2112A442"
            };
            let late_voice = format!("{}:", u32::from(platform.voice_window.1) + 1);
            let stun = format!("-m u32 --u32 \"{cookie}\" ");
            rules.push(chain, capture("udp", &platform.voice, &late_voice, &stun));
        }
        for flag in ["RST", "FIN"] {
            rules.push(
                chain,
                capture(
                    "tcp",
                    &platform.ports,
                    &late,
                    &format!("--tcp-flags {flag} {flag} "),
                ),
            );
        }
        rules.push(chain, capture("tcp", &platform.http, &late, ""));
    }
    let icmp = if version == 4 {
        "-p icmp --icmp-type 11/0"
    } else {
        "-p ipv6-icmp --icmpv6-type 3/0"
    };
    rules.push("R2O_IN", format!("{icmp} {target}"));
    if matches.ppe
        && value("R2O_PPE_DEOFFLOAD", "1") != "0"
        && let Some(target) = ppe_target(platform, version)
    {
        ppe_rules(platform, version, &target, &mut rules);
    }
    rules.hook("POSTROUTING", "-j R2O_OUT".into());
    rules.hook("FORWARD", "-j R2O_IN".into());
    if !sets.is_empty() {
        rules.hook("OUTPUT", "-j R2O_DNS_OUT".into());
        rules.hook("INPUT", "-j R2O_DNS_IN".into());
    }
    rules.push("R2O_INPUT", "-j R2O_IN".into());
    rules.hook("INPUT", "-j R2O_INPUT".into());
    rules
}

pub(super) fn ppe_target(platform: &Platform, version: u8) -> Option<String> {
    platform.ppe_ports.as_ref()?;
    let feature = if version == 4 {
        "ip_tables_targets"
    } else {
        "ip6_tables_targets"
    };
    let ppe = value("R2O_PPE_TARGET", "PPE");
    if ppe.is_empty()
        || !ppe.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || !fs::read_to_string(platform.proc.join("net").join(feature))
            .is_ok_and(|text| text.lines().any(|line| line == ppe))
    {
        return None;
    }
    Some(ppe)
}

fn ppe_rules(platform: &Platform, version: u8, ppe: &str, rules: &mut Rules) {
    let Some(ports) = &platform.ppe_ports else {
        return;
    };
    let early = number::<u32>(&value("R2O_PPE_CONNSKIP", "30"))
        .unwrap_or(30)
        .max(2 * u32::from(platform.early.max(platform.voice_window.1)));
    let http = number::<u32>(&value("R2O_PPE_HTTP_CONNSKIP", "1000000"))
        .unwrap_or(1000000)
        .max(early);
    let emit =
        |rules: &mut Rules, chain, matches: &str, depth| {
            rules.hook(chain, format!(
            "{matches} -m connskip --connskip {depth} -m comment --comment {PPE_TAG} -j {ppe}"
        ));
        };
    for endpoint in platform
        .software_path
        .iter()
        .filter(|ep| ep.version() == version)
    {
        let Endpoint {
            address,
            protocol,
            port,
            ..
        } = endpoint;
        let depth = if *protocol == "tcp" && has_port(&ports.http, *port) {
            http
        } else {
            early
        };
        for chain in ["PREROUTING", "FORWARD"] {
            emit(
                rules,
                chain,
                &format!("-p {protocol} -m conntrack --ctorigdst {address} --ctorigdstport {port}"),
                depth,
            );
        }
    }
    // D2K _d2k_ppe_rules: ответ проверяется в FORWARD после обратного NAT.
    // Длинное окно остаётся только у HTTP-запросов, до перехода в NFQUEUE.
    for chain in ["PREROUTING", "FORWARD"] {
        emit(
            rules,
            chain,
            &format!("-p tcp -m multiport --dports {}", ports.http),
            http,
        );
        for (protocol, ports) in [("tcp", &ports.tcp), ("udp", &ports.udp)] {
            emit(
                rules,
                chain,
                &format!("-p {protocol} -m multiport --dports {ports}"),
                early,
            );
            if chain == "FORWARD" {
                emit(
                    rules,
                    chain,
                    &format!("-p {protocol} -m multiport --sports {ports}"),
                    early,
                );
            }
        }
    }
}

fn has_port(list: &str, port: u16) -> bool {
    list.split(',').any(|item| {
        if let Some((lo, hi)) = item.split_once(':') {
            matches!((lo.parse::<u16>(), hi.parse::<u16>()), (Ok(lo), Ok(hi)) if (lo..=hi).contains(&port))
        } else { item.parse() == Ok(port) }
    })
}

fn broadcast_addresses() -> Vec<IpAddr> {
    let mut result = BTreeSet::from([IpAddr::V4(Ipv4Addr::BROADCAST)]);
    if let Ok(text) = command("ip", &["-4", "addr", "show"], None) {
        for line in text.lines() {
            let words: Vec<_> = line.split_whitespace().collect();
            if let Some(address) = words.windows(2).find_map(|pair| {
                (pair[0] == "brd")
                    .then(|| pair[1].parse::<Ipv4Addr>().ok())
                    .flatten()
            }) {
                result.insert(IpAddr::V4(address));
            }
        }
    }
    result.into_iter().collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DnsSet {
    Pair,
    Net(&'static str, u16),
}

impl DnsSet {
    fn name(self, version: u8) -> String {
        match self {
            Self::Pair => format!("r2o_dns_route{version}"),
            Self::Net(protocol, port) => format!("r2o_dn{version}_{protocol}_{port}"),
        }
    }

    fn element(self, endpoint: Endpoint) -> String {
        let Endpoint {
            address,
            protocol,
            port,
            ..
        } = endpoint;
        match self {
            Self::Pair => format!("{address},{protocol}:{port}"),
            Self::Net(..) => format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 }),
        }
    }

    fn create(self, version: u8) -> Result<()> {
        let name = self.name(version);
        let kind = if self == Self::Pair {
            "hash:ip,port"
        } else {
            "hash:net"
        };
        let family = if version == 4 { "inet" } else { "inet6" };
        command(
            "ipset",
            &[
                "-exist", "create", &name, kind, "family", family, "hashsize", "64", "timeout",
                "300", "maxelem", "64",
            ],
            None,
        )
        .map(drop)
    }
}

fn prepare_sets(version: u8, leases: &Leases) -> Result<BTreeSet<DnsSet>> {
    let now = uptime()?;
    let live: Vec<_> = leases
        .iter()
        .filter_map(|(&endpoint, &until)| {
            (endpoint.version() == version && endpoint.uid.is_none())
                .then(|| ttl(until, now))
                .flatten()
                .map(|seconds| (endpoint, seconds))
        })
        .collect();
    if live.is_empty() {
        return Ok(BTreeSet::new());
    }
    let pair = DnsSet::Pair.create(version).is_ok();
    let mut sets = BTreeSet::new();
    for (endpoint, seconds) in live {
        let set = if pair {
            DnsSet::Pair
        } else {
            DnsSet::Net(endpoint.protocol, endpoint.port)
        };
        if sets.insert(set) && !pair {
            if sets.len() > 16 {
                return Err(error("слишком много групп ipset DNS"));
            }
            set.create(version)?;
        }
        command(
            "ipset",
            &[
                "-exist",
                "add",
                &set.name(version),
                &set.element(endpoint),
                "timeout",
                &seconds.to_string(),
            ],
            None,
        )?;
    }
    Ok(sets)
}

fn dns_sets(endpoint: Endpoint) -> [DnsSet; 2] {
    [DnsSet::Pair, DnsSet::Net(endpoint.protocol, endpoint.port)]
}

fn set_names() -> Result<BTreeSet<String>> {
    command("ipset", &["list", "-name"], None)
        .map(|listing| listing.lines().map(str::to_owned).collect())
}

pub(super) fn leases_live(leases: &Leases, ipv6: bool) -> Result<bool> {
    if leases.is_empty() {
        return Ok(true);
    }
    let now = uptime()?;
    let names = set_names()?;
    for (&ep, &until) in leases {
        if ep.uid.is_some() || ep.version() == 6 && !ipv6 || ttl(until, now).is_none() {
            continue;
        }
        if !dns_sets(ep).iter().any(|set| {
            let name = set.name(ep.version());
            names.contains(&name)
                && command("ipset", &["test", &name, &set.element(ep)], None).is_ok()
        }) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn forget(endpoint: Endpoint) -> Result<()> {
    if !available("ipset") {
        return Ok(());
    }
    let names = set_names()?;
    for set in dns_sets(endpoint) {
        let name = set.name(endpoint.version());
        if names.contains(&name) {
            command(
                "ipset",
                &["-exist", "del", &name, &set.element(endpoint)],
                None,
            )?;
        }
    }
    Ok(())
}

fn nat(platform: &Platform, before: &Rules, listing: &str) -> Rules {
    let mut rules = Rules::default();
    let index = if platform.kind == Kind::Keenetic {
        // NDM's existing source-specific SNAT rules take precedence.
        listing
            .lines()
            .filter(|line| line.starts_with("-A POSTROUTING "))
            .count()
            - before.hooks.get("POSTROUTING").map_or(0, Vec::len)
            + 1
    } else {
        1
    };
    rules.hooks.insert(
        "POSTROUTING".into(),
        vec![(
            index,
            format!(
                "-p udp -m mark --mark {} -m comment --comment {NAT_TAG} -j MASQUERADE",
                platform.raw
            ),
        )],
    );
    rules
}

pub(super) fn fingerprint(platform: &Platform, ipv6: bool, hash: &mut Sha256) -> Result<()> {
    for (version, table) in [(4, "mangle"), (4, "nat"), (6, "mangle")] {
        if version == 6 && !ipv6 {
            continue;
        }
        let state = split_state(platform, table, &list(version, table)?);
        if platform.kind == Kind::Keenetic {
            verify_keenetic_rules(platform, version, table, &state)?;
        }
        hash.update(format!(
            "{version}:{table}:{:?}:{:?}",
            state.chains, state.hooks
        ));
        if table == "mangle" && value("R2O_PPE_DEOFFLOAD", "1") != "0" {
            // После перезагрузки NDM цель PPE может появиться после базовых цепочек.
            hash.update(ppe_target(platform, version).unwrap_or_default());
        }
    }
    Ok(())
}

fn verify_keenetic_rules(
    platform: &Platform,
    version: u8,
    table: &str,
    state: &Rules,
) -> Result<()> {
    if table == "nat" {
        let matches_raw = |rule: &str| {
            let fields: Vec<_> = rule.split_whitespace().collect();
            let selector = match fields.as_slice() {
                [
                    "-p",
                    "udp",
                    "-m",
                    "mark",
                    "--mark",
                    selector,
                    "-j",
                    "MASQUERADE",
                ] => selector,
                [
                    "-p",
                    "udp",
                    "-m",
                    "mark",
                    "--mark",
                    selector,
                    "-m",
                    "comment",
                    "--comment",
                    tag,
                    "-j",
                    "MASQUERADE",
                ] if tag.trim_matches('"') == NAT_TAG => selector,
                _ => return false,
            };
            exact_mark(selector, platform.raw)
        };
        let mut rules = state.hooks.get("POSTROUTING").into_iter().flatten();
        if rules.next().is_some_and(|(_, rule)| matches_raw(rule)) && rules.next().is_none() {
            return Ok(());
        }
        return Err(error(
            "IPv4 nat: ожидается один MASQUERADE с точной меткой raw UDP",
        ));
    }
    // PPE должен пройти перед захватом, а оба — перед правилами NDM.
    let forward = state
        .hooks
        .get("FORWARD")
        .into_iter()
        .flatten()
        .filter(|(_, rule)| ppe_rule(rule));
    let mut forward_position = 1;
    for (index, _) in forward {
        if *index != forward_position {
            return Err(error(format!(
                "IPv{version} mangle: правила PPE должны идти в начале FORWARD"
            )));
        }
        forward_position += 1;
    }
    let dns_input = state
        .hooks
        .get("INPUT")
        .into_iter()
        .flatten()
        .find(|(_, rule)| rule == "-j R2O_DNS_IN");
    if dns_input.is_some_and(|(index, _)| *index != 1) {
        return Err(error(format!(
            "IPv{version} mangle: переход INPUT -j R2O_DNS_IN не первый"
        )));
    }
    for (hook, jump, position) in [
        ("POSTROUTING", "-j R2O_OUT", 1),
        ("FORWARD", "-j R2O_IN", forward_position),
        (
            "INPUT",
            "-j R2O_INPUT",
            if dns_input.is_some() { 2 } else { 1 },
        ),
    ] {
        let mut jumps = state
            .hooks
            .get(hook)
            .into_iter()
            .flatten()
            .filter(|(_, rule)| rule == jump);
        if !jumps.next().is_some_and(|(index, _)| *index == position) || jumps.next().is_some() {
            return Err(error(format!(
                "IPv{version} mangle: ожидается один переход {hook} {jump} в позиции {position}"
            )));
        }
    }
    if !state
        .chains
        .get("R2O_INPUT")
        .is_some_and(|rules| rules.iter().any(|rule| rule == "-j R2O_IN"))
    {
        return Err(error(format!(
            "IPv{version} mangle: отсутствует вход к NFQUEUE"
        )));
    }
    let queue = platform.queue(version).to_string();
    let window = format!(" --connbytes 0:{} ", platform.early);
    for (chain, direction) in [
        ("R2O_OUT", " --ctdir ORIGINAL "),
        ("R2O_IN", " --ctdir REPLY "),
    ] {
        for protocol in ["-p tcp ", "-p udp "] {
            if !state.chains.get(chain).is_some_and(|rules| {
                rules.iter().any(|rule| {
                    rule.starts_with(protocol)
                        && rule.contains(direction)
                        && rule.contains(&window)
                        && rule.contains(" -j NFQUEUE ")
                        && rule
                            .split_whitespace()
                            .skip_while(|arg| *arg != "--queue-num")
                            .nth(1)
                            == Some(queue.as_str())
                        && rule.split_whitespace().any(|arg| arg == "--queue-bypass")
                })
            }) {
                return Err(error(format!(
                    "IPv{version} {chain}: отсутствует правило NFQUEUE ({})",
                    protocol.trim()
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn ppe_coverage(platform: &Platform, version: u8) -> Result<Option<(usize, usize)>> {
    let Some(target) = ppe_target(platform, version) else {
        return Ok(None);
    };
    let listing = list(version, "mangle")?;
    let live = split_state(platform, "mangle", &listing);
    let mut desired = Rules::default();
    ppe_rules(platform, version, &target, &mut desired);
    let mut expected = 0;
    let mut found = 0;
    for (chain, rules) in desired.hooks {
        let hooks = live.hooks.get(&chain).into_iter().flatten();
        let installed: BTreeSet<_> = hooks
            .take_while(|(index, _)| *index <= rules.len())
            .map(|(_, rule)| rule.replace("\"r2o-ppe\"", PPE_TAG))
            .collect();
        let desired: BTreeSet<_> = rules.iter().map(|(_, rule)| rule).collect();
        expected += desired.len();
        found += desired
            .iter()
            .filter(|rule| installed.contains(**rule))
            .count();
    }
    Ok(Some((found, expected)))
}

pub(super) fn diagnostic_counters(platform: &Platform, version: u8) -> serde_json::Value {
    use serde_json::json;
    let listing = match command(
        &format!("{}-save", tool(version)),
        &["-c", "-t", "mangle"],
        None,
    ) {
        Ok(listing) => listing,
        Err(error) => return json!({"error": super::limit_health_error(&error.to_string())}),
    };
    let [out_hook, in_hook, queue, ppe] = summarize_counters(&listing);
    let pair = |(rules, packets)| json!({"rules": rules, "packets": packets});
    json!({
        "out_hook": pair(out_hook), "in_hook": pair(in_hook),
        "nfqueue": pair(queue), "ppe": pair(ppe),
        "ppe_target_available": ppe_target(platform, version).is_some(),
    })
}

fn summarize_counters(listing: &str) -> [(u64, u64); 4] {
    let mut counts = [(0u64, 0u64); 4];
    for line in listing.lines() {
        let Some((counters, rule)) = line.split_once("] -A ") else {
            continue;
        };
        let Some(packets) = counters
            .strip_prefix('[')
            .and_then(|s| s.split_once(':'))
            .and_then(|(packets, _)| packets.parse::<u64>().ok())
        else {
            continue;
        };
        let Some((chain, rule)) = rule.split_once(' ') else {
            continue;
        };
        let slot = if chain == "POSTROUTING" && rule.ends_with("-j R2O_OUT") {
            0
        } else if chain == "FORWARD" && rule.ends_with("-j R2O_IN") {
            1
        } else if chain.starts_with("R2O_")
            && (rule.starts_with("-j NFQUEUE ") || rule.contains(" -j NFQUEUE "))
        {
            2
        } else if rule.contains("--comment \"r2o-ppe\" ") || rule.contains("--comment r2o-ppe ") {
            3
        } else {
            continue;
        };
        counts[slot].0 += 1;
        counts[slot].1 = counts[slot].1.saturating_add(packets);
    }
    counts
}

#[cfg(test)]
#[test]
fn diagnostic_counters_count_owned_hooks_and_queue_rules() {
    let listing = "\
[20:400] -A POSTROUTING -j R2O_OUT\n\
[30:600] -A FORWARD -j R2O_IN\n\
[17:340] -A PREROUTING -m comment --comment \"r2o-ppe\" -j PPE\n\
[11:220] -A R2O_IN -j NFQUEUE --queue-num 2000\n\
[3:60] -A R2O_OUT -j NFQUEUE --queue-num 2000\n\
[2:40] -A FORWARD -j NFQUEUE --queue-num 3000\n";
    assert_eq!(
        summarize_counters(listing),
        [(1, 20), (1, 30), (2, 14), (1, 17)]
    );
}

pub(super) fn install(
    platform: &Platform,
    ipv6: bool,
    leases: &Leases,
    exclusions: &str,
) -> Result<()> {
    let mut applied = Vec::new();
    let result = (|| {
        let mut ppe_error = None;
        for (version, table) in [(4, "nat"), (4, "mangle"), (6, "mangle")] {
            let listing = if version == 6 && !ipv6 {
                let Ok(text) = list(version, table) else {
                    continue;
                };
                text
            } else {
                list(version, table)?
            };
            let before = split_state(platform, table, &listing);
            let owners = if table == "mangle" && platform.kind == Kind::Keenetic {
                owner_rules(platform, version, &before)?
            } else {
                BTreeMap::new()
            };
            let sets = if table == "mangle" && (version == 4 || ipv6) {
                prepare_sets(version, leases)?
            } else {
                BTreeSet::new()
            };
            let mut features = OptionalMatches {
                ppe: true,
                late_stun: table == "mangle"
                    && (version == 4 || ipv6)
                    && platform.kind == Kind::Keenetic
                    && command(tool(version), &["-m", "u32", "--help"], None).is_ok(),
            };
            let make_mangle = |broadcast: &[IpAddr], features| {
                mangle(
                    platform, version, exclusions, &sets, broadcast, features, &owners,
                )
            };
            let desired = if table == "nat" {
                nat(platform, &before, &listing)
            } else if version == 6 && !ipv6 {
                Rules::default()
            } else {
                make_mangle(&[], features)
            };
            let backend = Iptables { version, table };
            let mut result = backend.apply(&render(&before, &desired));
            let mut addresses = Vec::new();
            if version == 4
                && table == "mangle"
                && result
                    .as_ref()
                    .is_err_and(|err| err.to_string().contains("addrtype"))
            {
                addresses = broadcast_addresses();
                let fallback = make_mangle(&addresses, features);
                result = backend.apply(&render(&before, &fallback));
            }
            if let Err(err) = result {
                let optional_ppe = desired
                    .hooks
                    .values()
                    .flatten()
                    .any(|(_, rule)| rule.contains(PPE_TAG));
                if table != "mangle" || !optional_ppe && !features.late_stun {
                    return Err(err);
                }
                let try_mangle =
                    |features| backend.apply(&render(&before, &make_mangle(&addresses, features)));
                if features.late_stun
                    && try_mangle(OptionalMatches {
                        late_stun: false,
                        ..features
                    })
                    .is_ok()
                {
                    eprintln!("r2o-platform: IPv{version} поздний STUN недоступен: {err}");
                } else if optional_ppe {
                    features.ppe = false;
                    if let Err(fallback) = try_mangle(features) {
                        if !features.late_stun {
                            return Err(error(format!("{err}; повтор без PPE: {fallback}")));
                        }
                        features.late_stun = false;
                        try_mangle(features).map_err(|fallback| {
                            error(format!("{err}; повтор без PPE и позднего STUN: {fallback}"))
                        })?;
                        eprintln!("r2o-platform: IPv{version} поздний STUN недоступен: {err}");
                    }
                    ppe_error = Some(format!("IPv{version} PPE: {err}"));
                    eprintln!("r2o-platform: IPv{version} без подтверждённой поддержки PPE: {err}");
                } else {
                    return Err(err);
                }
            }
            applied.push((version, table, before));
        }
        let signature = (platform.kind == Kind::Keenetic)
            .then(|| platform.fingerprint(ipv6))
            .transpose()?;
        let state = platform.run.join("platform.offload-error");
        match ppe_error {
            Some(reason) => atomic(&state, &reason),
            None => remove(&state),
        }?;
        if let Some(signature) = signature {
            atomic(&platform.run.join(RULES), &signature)?;
        }
        Ok(())
    })();
    if let Err(err) = result {
        let mut errors = vec![err.to_string()];
        for (version, table, before) in applied.into_iter().rev() {
            if let Err(rollback) = list(version, table).and_then(|listing| {
                Iptables { version, table }
                    .apply(&render(&split_state(platform, table, &listing), &before))
            }) {
                errors.push(format!("откат IPv{version} {table}: {rollback}"));
            }
        }
        return Err(error(errors.join("; ")));
    }
    Ok(())
}

pub(super) fn down(platform: &Platform) -> Result<()> {
    let mut errors = Vec::new();
    for (version, table) in [(4, "mangle"), (6, "mangle"), (4, "nat")] {
        if !available(tool(version)) {
            continue;
        }
        let result = list(version, table).and_then(|listing| {
            let before = split_state(platform, table, &listing);
            if table == "mangle" && platform.kind == Kind::Keenetic {
                owner_rules(platform, version, &before)?;
            }
            Iptables { version, table }.apply(&render(&before, &Rules::default()))
        });
        if let Err(err) = result
            && (version == 4 || platform.ipv6 && !err.to_string().contains("Table does not exist"))
        {
            errors.push(err.to_string());
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(error(errors.join("; ")))
    }
}

pub(super) fn clear_ppe() -> Result<()> {
    for version in [4, 6] {
        if !available(tool(version)) {
            continue;
        }
        let listing = match list(version, "mangle") {
            Ok(listing) => listing,
            Err(_) if version == 6 => continue,
            Err(err) => return Err(err),
        };
        let mut script = String::new();
        for line in listing.lines() {
            if let Some(rule) = line.strip_prefix("-A ")
                && rule
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .windows(2)
                    .any(|pair| pair[0] == "--comment" && pair[1].trim_matches('"') == PPE_TAG)
            {
                writeln!(script, "-D {rule}").unwrap();
            }
        }
        (Iptables {
            version,
            table: "mangle",
        })
        .apply(&script)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_wait_threshold_matches_iptables_tools() {
        assert!(!supports_wait("iptables v1.4.19"));
        assert!(supports_wait("iptables v1.4.21"));
        assert!(supports_wait("ip6tables v1.8.11 (legacy)"));
        assert!(!supports_wait("iptables: unknown vendor release"));
    }

    #[test]
    fn keenetic_skips_local_delivery_before_the_outbound_capture_window() {
        let mut platform = Platform::detect().unwrap();
        for kind in [Kind::Keenetic, Kind::OpenWrt] {
            platform.kind = kind;
            for version in [4, 6] {
                let rules = mangle(
                    &platform,
                    version,
                    "",
                    &BTreeSet::new(),
                    &[],
                    OptionalMatches {
                        ppe: false,
                        late_stun: false,
                    },
                    &BTreeMap::new(),
                );
                let out = &rules.chains["R2O_OUT"];
                let capture = out
                    .iter()
                    .position(|rule| rule.contains("-m connbytes") && rule.contains("-j NFQUEUE"))
                    .unwrap();
                assert_eq!(
                    out[..capture].iter().any(|rule| rule == "-o lo -j RETURN"),
                    kind == Kind::Keenetic
                );
            }
        }
    }

    #[test]
    fn ppe_matches_unknown_udp_and_only_extends_the_http_request_window() {
        let mut platform = Platform::detect().unwrap();
        platform.software_path.clear();
        platform.ppe_ports = Some(PpePorts {
            tcp: "443,8443".into(),
            udp: "0:65535".into(),
            http: "8080".into(),
        });
        for family in [4, 6] {
            let mut rules = Rules::default();
            ppe_rules(&platform, family, "PPE", &mut rules);
            assert_eq!(rules.hooks["PREROUTING"].len(), 3);
            assert_eq!(rules.hooks["FORWARD"].len(), 5);
            for chain in ["PREROUTING", "FORWARD"] {
                let rules: Vec<_> = rules.hooks[chain].iter().map(|(_, rule)| rule).collect();
                assert!(rules[0].starts_with("-p tcp -m multiport --dports 8080 -m connskip "));
                assert!(rules[0].contains("--connskip 1000000 "));
                assert!(
                    rules
                        .iter()
                        .any(|rule| rule.starts_with("-p tcp -m multiport --dports 443,8443 "))
                );
                assert!(
                    rules
                        .iter()
                        .any(|rule| rule.starts_with("-p udp -m multiport --dports 0:65535 "))
                );
                let reply = rules
                    .iter()
                    .any(|rule| rule.starts_with("-p udp -m multiport --sports 0:65535 "));
                assert_eq!(reply, chain == "FORWARD");
                assert!(rules.iter().all(|rule| !rule.contains("--sports 8080 ")));
            }
        }
    }
}
