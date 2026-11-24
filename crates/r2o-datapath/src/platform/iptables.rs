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

pub(super) fn list(version: u8, table: &str) -> Result<String> {
    static V4_WAIT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    static V6_WAIT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let binary = tool(version);
    let cache = if version == 4 { &V4_WAIT } else { &V6_WAIT };
    let wait = *cache
        .get_or_init(|| command(binary, &["--version"], None).is_ok_and(|s| supports_wait(&s)));
    let args = ["-w", "-t", table, "-S"];
    command(binary, &args[usize::from(!wait)..], None)
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
            && fields.get(5).and_then(|v| mark(v).ok()) == Some(platform.raw)
            && fields.len() == 8)
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

fn mangle(
    platform: &Platform,
    version: u8,
    sources: &str,
    sets: &BTreeSet<DnsSet>,
    broadcast: &[IpAddr],
    ppe: bool,
) -> Rules {
    let mut rules = Rules::default();
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
            rules.push(
                chain,
                format!(
                    "-p {proto} -m multiport {selector} {} -j RETURN",
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
    if ppe
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
    if platform.kind != Kind::Keenetic {
        return None;
    }
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
    let early = number::<u32>(&value("R2O_PPE_CONNSKIP", "30"))
        .unwrap_or(30)
        .max(u32::from(platform.early));
    let http = number::<u32>(&value("R2O_PPE_HTTP_CONNSKIP", "1000000"))
        .unwrap_or(1000000)
        .max(early);
    let voice = early.max(u32::from(platform.voice_window.1));
    let emit = |rules: &mut Rules, matches: &str, depth| {
        let rule = format!(
            "{matches} -m connskip --connskip {depth} -m comment --comment {PPE_TAG} -j {ppe}"
        );
        rules.hook("PREROUTING", rule.clone());
        rules.hook("FORWARD", rule);
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
        let depth = if *protocol == "tcp" && has_port(&platform.http, *port) {
            http
        } else {
            voice
        };
        emit(
            rules,
            &format!("-p {protocol} -m conntrack --ctorigdst {address} --ctorigdstport {port}"),
            depth,
        );
    }
    // Правила ставятся до NFQUEUE в обоих hooks, как в прежнем адаптере PPE.
    // Для ответа проверяем исходный порт сервера, для запроса — порт назначения.
    let ports = [
        Some(("tcp", &platform.http, http)),
        Some(("tcp", &platform.ports, early)),
        Some(("udp", &platform.ports, early)),
        (platform.ports != "0:65535" || voice > early).then_some(("udp", &platform.voice, voice)),
    ];
    for (protocol, ports, depth) in ports.into_iter().flatten() {
        for (direction, field) in [("ORIGINAL", "dports"), ("REPLY", "sports")] {
            emit(
                rules,
                &format!(
                    "-p {protocol} -m conntrack ! --ctstate DNAT --ctdir {direction} -m multiport --{field} {ports} -m multiport ! --{field} {}",
                    platform.dns
                ),
                depth,
            );
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

fn nat(platform: &Platform) -> Rules {
    let mut rules = Rules::default();
    rules.hook(
        "POSTROUTING",
        format!(
            "-p udp -m mark --mark {} -m comment --comment {NAT_TAG} -j MASQUERADE",
            platform.raw
        ),
    );
    rules
}

pub(super) fn fingerprint(platform: &Platform, ipv6: bool, hash: &mut Sha256) -> Result<()> {
    for (version, table) in [(4, "mangle"), (4, "nat"), (6, "mangle")] {
        if version == 6 && !ipv6 {
            continue;
        }
        let state = split_state(platform, table, &list(version, table)?);
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

pub(super) fn ppe_installed(version: u8) -> Result<bool> {
    Ok(list(version, "mangle")?.lines().any(|line| {
        line.split_ascii_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|words| words[0] == "--comment" && words[1].trim_matches('"') == PPE_TAG)
    }))
}

pub(super) fn install(
    platform: &Platform,
    ipv6: bool,
    leases: &Leases,
    exclusions: &str,
) -> Result<()> {
    remove(&platform.run.join("platform.offload-error"))?;
    let mut applied = Vec::new();
    let result = (|| {
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
            let sets = if table == "mangle" && (version == 4 || ipv6) {
                prepare_sets(version, leases)?
            } else {
                BTreeSet::new()
            };
            let desired = if table == "nat" {
                nat(platform)
            } else if version == 6 && !ipv6 {
                Rules::default()
            } else {
                mangle(platform, version, exclusions, &sets, &[], true)
            };
            let result = (Iptables { version, table }).apply(&render(&before, &desired));
            if let Err(err) = result {
                let needs_broadcast = version == 4 && err.to_string().contains("addrtype");
                let optional_ppe = desired
                    .hooks
                    .values()
                    .flatten()
                    .any(|(_, rule)| rule.contains(PPE_TAG));
                if table != "mangle" || !(needs_broadcast || optional_ppe) {
                    return Err(err);
                }
                let addresses = if needs_broadcast {
                    broadcast_addresses()
                } else {
                    vec![]
                };
                let fallback = mangle(platform, version, exclusions, &sets, &addresses, false);
                Iptables { version, table }
                    .apply(&render(&before, &fallback))
                    .map_err(|fallback| error(format!("{err}; повтор без PPE: {fallback}")))?;
                if optional_ppe {
                    atomic(
                        &platform.run.join("platform.offload-error"),
                        &format!("IPv{version} PPE: {err}"),
                    )?;
                    eprintln!("r2o-platform: IPv{version} без подтверждённой поддержки PPE: {err}");
                }
            }
            applied.push((version, table, before));
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
            Iptables { version, table }.apply(&render(
                &split_state(platform, table, &listing),
                &Rules::default(),
            ))
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
                    .any(|pair| {
                        pair[0] == "--comment"
                            && matches!(pair[1].trim_matches('"'), PPE_TAG | "d2k-ppe")
                    })
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
    fn ppe_keeps_a_window_for_unknown_flows_in_both_directions() {
        let mut platform = Platform::detect().unwrap();
        platform.software_path.clear();
        platform.ports = "0:65535".into();
        let mut rules = Rules::default();
        ppe_rules(&platform, 4, "PPE", &mut rules);
        for chain in ["PREROUTING", "FORWARD"] {
            let rules = &rules.hooks[chain];
            for protocol in ["tcp", "udp"] {
                for (direction, field) in [("ORIGINAL", "dports"), ("REPLY", "sports")] {
                    assert!(rules.iter().any(|(_, rule)| {
                        rule.starts_with(&format!("-p {protocol} "))
                            && rule.contains(&format!(
                                "--ctdir {direction} -m multiport --{field} 0:65535"
                            ))
                            && rule.contains("-m connskip --connskip ")
                            && rule.ends_with("-j PPE")
                    }));
                }
            }
            assert!(rules.iter().all(|(_, rule)| !rule.contains("--ctorigdst")));
        }
    }
}
