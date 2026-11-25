use super::*;
use std::fmt::Write as _;

const OWNED: &str = "comment \"r2o-managed\"";
const OFFLOAD_CHAIN: &str = "r2o_offload";
const ADMISSION: &str = "meta l4proto { tcp, udp } flow add @ft";
const ADMISSION_ALTERNATE: &str = "meta l4proto { tcp, udp } flow offload @ft";
const OFFLOAD_JUMP: &str = "jump r2o_offload comment \"r2o-flowtable-admission\"";

fn table(name: &str) -> Result<Option<String>> {
    let args = ["-s", "-n", "list", "table", "inet", name];
    let output = invoke("nft", &args, None)?;
    if !output.status.success()
        && String::from_utf8_lossy(&output.stderr).contains("No such file or directory")
    {
        return Ok(None);
    }
    let text = checked("nft", &args, output)?;
    if text.lines().nth(1).map(str::trim) != Some(OWNED) {
        return Err(error(format!(
            "nft inet {name}: отсутствует метка владельца R2O"
        )));
    }
    Ok(Some(text))
}

struct Nft;

impl FirewallBackend for Nft {
    type Rule = str;

    fn apply(&self, rules: &str) -> Result<()> {
        command("nft", &["-f", "-"], Some(rules)).map(drop)
    }
}

pub(super) fn down(name: &str) -> Result<()> {
    if table(name)?.is_some() {
        Nft.apply(&format!("delete table inet {name}\n"))?;
    }
    Ok(())
}

fn structural(text: &str) -> String {
    let mut elements = false;
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("elements = {") || elements {
                elements = !line.ends_with('}');
                return None;
            }
            (!line.is_empty()).then_some(line)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn fingerprint(hash: &mut Sha256) -> Result<()> {
    for name in ["r2o", "r2o_rst"] {
        let content = table(name)?.ok_or_else(|| error(format!("таблица {name} отсутствует")))?;
        hash.update(structural(&content));
    }
    Ok(())
}

fn element(endpoint: Endpoint) -> (String, String) {
    let version = endpoint.version();
    let Endpoint {
        address,
        protocol,
        port,
        uid,
    } = endpoint;
    if let Some(uid) = uid {
        (
            format!("dns_h3_route{version}"),
            format!("{address} . {port} . {uid}"),
        )
    } else {
        (
            format!("dns_route{version}"),
            format!("{address} . {protocol} . {port}"),
        )
    }
}

pub(super) fn lease_present(endpoint: Endpoint) -> Result<bool> {
    let (set, key) = element(endpoint);
    let expression = format!("{{ {key} }}");
    let args = ["get", "element", "inet", "r2o", &set, &expression];
    let output = invoke("nft", &args, None)?;
    if !output.status.success()
        && String::from_utf8_lossy(&output.stderr).contains("No such file or directory")
    {
        return Ok(false);
    }
    checked("nft", &args, output).map(|_| true)
}

pub(super) fn leases_live(leases: &Leases, ipv6: bool) -> Result<bool> {
    let now = uptime()?;
    for (&endpoint, &until) in leases {
        if (endpoint.version() == 4 || ipv6)
            && ttl(until, now).is_some()
            && !lease_present(endpoint)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn route(endpoint: Endpoint, add: bool, seconds: u64) -> Result<()> {
    if table("r2o")?.is_none() {
        return if add {
            Err(error("таблица DNS отсутствует"))
        } else {
            Ok(())
        };
    }
    let (set, key) = element(endpoint);
    let mut rules = String::new();
    if lease_present(endpoint)? {
        writeln!(rules, "delete element inet r2o {set} {{ {key} }}").unwrap();
    }
    if add {
        writeln!(
            rules,
            "add element inet r2o {set} {{ {key} timeout {seconds}s }}"
        )
        .unwrap();
    }
    if !rules.is_empty() {
        Nft.apply(&rules)?;
    }
    Ok(())
}

fn nft_ports(ports: &str) -> String {
    ports.replace(':', "-").replace(',', ", ")
}

fn interval(low: u16, high: u16) -> String {
    let low = low.max(1);
    if low == high {
        low.to_string()
    } else {
        format!("{low}-{high}")
    }
}

fn rules(platform: &Platform, ipv6: bool) -> String {
    let mut plain_out = String::new();
    let mut plain_reply = String::new();
    let mut gate_out = String::new();
    let mut gate_in = String::new();
    let probe = platform.probe;
    for endpoint in &platform.plain {
        let version = endpoint.version();
        if version == 6 && !ipv6 {
            continue;
        }
        let family = if version == 4 { "ip" } else { "ip6" };
        let queue = platform.queue(version);
        let Endpoint {
            address,
            protocol,
            port,
            ..
        } = endpoint;
        writeln!(plain_out, "meta iif 0 meta mark 0 {family} daddr {address} {protocol} dport {port} ct direction original meta mark set {probe} comment \"r2o-dns-owner\"").unwrap();
        writeln!(plain_out, "meta mark {probe} {family} daddr {address} {protocol} dport {port} ct direction original queue num {queue} bypass").unwrap();
        if *protocol == "tcp" {
            writeln!(plain_reply, "{family} saddr {address} tcp sport {port} ct direction reply tcp flags & (syn | ack) == (syn | ack) queue num {queue} bypass").unwrap();
        }
    }
    if let Some((ip, port)) = platform.gate {
        gate_out = format!("ip daddr {ip} tcp dport {port} return");
        gate_in = format!("ip saddr {ip} tcp sport {port} return");
    }
    let measure = if platform.measure == 0 {
        String::new()
    } else {
        format!("meta mark {} return", platform.measure)
    };
    let q4 = platform.queue(4).to_string();
    let q6 = platform.queue(6).to_string();
    let config = [
        ("@MARK@", platform.raw.to_string()),
        ("@WINDOW@", interval(0, platform.early)),
        (
            "@LATE_WINDOW@",
            format!("{}-18446744073709551615", u32::from(platform.early) + 1),
        ),
        (
            "@VOICE_WINDOW@",
            interval(platform.voice_window.0, platform.voice_window.1),
        ),
        ("@PORTS@", nft_ports(&platform.ports)),
        ("@VOICE_PORTS@", nft_ports(&platform.voice)),
        ("@HTTP_PORTS@", nft_ports(&platform.http)),
        ("@DNS_PORTS@", nft_ports(&platform.dns)),
        ("@QUEUE4@", q4),
        ("@QUEUE6@", q6.clone()),
        ("@MEASURE@", measure),
        ("@PLAIN_OUT@", plain_out),
        ("@PLAIN_REPLY@", plain_reply),
        ("@GATE_OUT@", gate_out),
        ("@GATE_IN@", gate_in),
    ];
    let mut text = include_str!("firewall.nft").to_string();
    for (key, value) in config {
        text = text.replace(key, &value);
    }
    if !ipv6 {
        let queue = format!("queue num {q6} bypass");
        text = text
            .lines()
            .filter(|line| !line.contains(&queue))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
    }
    text
}

fn rst_rules(existing: Option<&str>) -> String {
    let existing = existing.unwrap_or_default();
    let mut rules = String::new();
    if existing.is_empty() {
        rules.push_str("add table inet r2o_rst { comment \"r2o-managed\"; }\n");
    }
    for (set, addr) in [("rst4", "ipv4_addr"), ("rst6", "ipv6_addr")] {
        if !existing
            .lines()
            .any(|line| line.trim_start().starts_with(&format!("set {set} {{")))
        {
            writeln!(rules, "add set inet r2o_rst {set} {{ type inet_service . {addr} . inet_service; flags timeout; timeout 30s; }}").unwrap();
        }
    }
    if existing
        .lines()
        .any(|line| line.trim_start().starts_with("chain output {"))
    {
        rules.push_str("flush chain inet r2o_rst output\n");
    } else {
        rules.push_str("add chain inet r2o_rst output { type filter hook output priority filter; policy accept; }\n");
    }
    rules.push_str("add rule inet r2o_rst output tcp flags & rst == rst tcp sport . ip daddr . tcp dport @rst4 drop\n");
    rules.push_str("add rule inet r2o_rst output tcp flags & rst == rst tcp sport . ip6 daddr . tcp dport @rst6 drop\n");
    rules
}

pub(super) fn install(platform: &Platform, ipv6: bool, leases: &Leases) -> Result<()> {
    let mut batch_rules = String::new();
    if table("r2o")?.is_some() {
        batch_rules.push_str("delete table inet r2o\n");
    }
    batch_rules.push_str(&rst_rules(table("r2o_rst")?.as_deref()));
    batch_rules.push_str(&rules(platform, ipv6));
    let now = uptime()?;
    for (&endpoint, &until) in leases {
        if (endpoint.version() == 4 || ipv6)
            && let Some(seconds) = ttl(until, now)
        {
            let (set, key) = element(endpoint);
            writeln!(
                batch_rules,
                "add element inet r2o {set} {{ {key} timeout {seconds}s }}"
            )
            .unwrap();
        }
    }
    // Таблицы, цепочки и оставшиеся DNS TTL вступают в силу одним коммитом nft.
    Nft.apply(&batch_rules)
}

fn fw4_object(kind: &str, name: &str) -> Result<Option<String>> {
    let args = ["-a", "list", kind, "inet", "fw4", name];
    let output = invoke("nft", &args, None)?;
    if !output.status.success()
        && String::from_utf8_lossy(&output.stderr).contains("No such file or directory")
    {
        Ok(None)
    } else {
        checked("nft", &args, output).map(Some)
    }
}

fn handle(rule: &str) -> Option<(&str, u64)> {
    let (body, id) = rule.trim().rsplit_once("# handle ")?;
    Some((body.trim_end(), id.parse().ok()?))
}

fn flowtable_definition(listing: &str) -> Option<String> {
    let mut lines = listing.lines().map(str::trim);
    lines.find(|line| {
        line.split_once('#')
            .map_or(*line, |(code, _)| code.trim_end())
            == "flowtable ft {"
    })?;
    let body: Vec<_> = lines.take_while(|line| *line != "}").collect();
    (!body.is_empty()).then(|| body.join("\n"))
}

#[derive(Clone, Copy)]
enum Fw4Admission {
    Absent,
    Suspended,
}

impl Fw4Admission {
    fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Suspended => "suspended",
        }
    }
}

fn offload_plan(remove_rules: bool) -> Result<(String, Fw4Admission)> {
    let Some(forward) = fw4_object("chain", "forward")? else {
        return Ok((String::new(), Fw4Admission::Absent));
    };
    let mut admissions = forward.lines().filter_map(handle).filter(|(rule, _)| {
        *rule == OFFLOAD_JUMP || rule.contains("flow add ") || rule.contains("flow offload ")
    });
    let own = fw4_object("chain", OFFLOAD_CHAIN)?;
    if let Some(ref chain) = own
        && !chain.lines().any(|line| line.trim() == OWNED)
    {
        return Err(error("fw4: цепочка r2o_offload принадлежит другой службе"));
    }
    if remove_rules {
        let mut rules = String::new();
        if let Some((_, id)) = forward
            .lines()
            .filter_map(handle)
            .find(|(rule, _)| *rule == OFFLOAD_JUMP)
        {
            if admissions.any(|(rule, _)| matches!(rule, ADMISSION | ADMISSION_ALTERNATE)) {
                writeln!(rules, "delete rule inet fw4 forward handle {id}").unwrap();
            } else {
                writeln!(
                    rules,
                    "replace rule inet fw4 forward handle {id} {ADMISSION}"
                )
                .unwrap();
            }
        }
        if own.is_some() {
            writeln!(rules, "delete chain inet fw4 {OFFLOAD_CHAIN}").unwrap();
        }
        return Ok((rules, Fw4Admission::Absent));
    }
    let Some((current, id)) = admissions.next() else {
        return Ok((String::new(), Fw4Admission::Absent));
    };
    if !matches!(current, ADMISSION | ADMISSION_ALTERNATE | OFFLOAD_JUMP)
        || admissions.next().is_some()
    {
        return Err(error("неподдерживаемая конфигурация admission fw4"));
    }
    // Пустая цепочка возвращает управление fw4 и сохраняет его штатные verdict.
    let empty = own.as_ref().is_some_and(|chain| {
        !chain
            .lines()
            .filter_map(handle)
            .any(|(rule, _)| !rule.ends_with('{'))
    });
    if current == OFFLOAD_JUMP && empty {
        return Ok((String::new(), Fw4Admission::Suspended));
    }

    let mut rules = if own.is_none() {
        format!("add chain inet fw4 {OFFLOAD_CHAIN} {{ {OWNED}; }}\n")
    } else {
        format!("flush chain inet fw4 {OFFLOAD_CHAIN}\n")
    };
    if current != OFFLOAD_JUMP {
        writeln!(
            rules,
            "replace rule inet fw4 forward handle {id} {OFFLOAD_JUMP}"
        )
        .unwrap();
    }
    // Как в flowoffload_off D2K, действующие ускоренные потоки тоже должны
    // вернуться в netfilter. Удаление и создание штатного ft атомарны.
    let table = fw4_object("flowtable", "ft")?
        .and_then(|listing| flowtable_definition(&listing))
        .ok_or_else(|| error("fw4: не удалось прочитать штатную flowtable ft"))?;
    writeln!(
        rules,
        "delete flowtable inet fw4 ft\nadd flowtable inet fw4 ft {{\n{table}\n}}"
    )
    .unwrap();
    Ok((rules, Fw4Admission::Suspended))
}

pub(super) fn offload(remove_rules: bool) -> Result<&'static str> {
    let (rules, admission) = offload_plan(remove_rules)?;
    if !rules.is_empty() {
        Nft.apply(&rules)?;
    }
    Ok(admission.as_str())
}

pub(super) fn admission_status() -> Result<&'static str> {
    let (edits, admission) = offload_plan(false)?;
    if !edits.is_empty() {
        return Err(error("допуск в flowtable fw4 не приостановлен"));
    }
    Ok(admission.as_str())
}

pub(super) fn restore_fw4(platform: &Platform) -> Result<()> {
    for name in ["flow-offloading.saved", "flow-offloading.runtime"] {
        let journal = platform.run.join(name);
        let Some(saved) = optional(&journal)? else {
            continue;
        };
        let key = "firewall.@defaults[0].flow_offloading";
        if saved.trim() == "1" {
            let actual = command("uci", &["-q", "get", key], None)?;
            if actual.trim() == "0" {
                let pending = command("uci", &["changes", "firewall"], None)?;
                if !pending.trim().is_empty() && pending.trim() != format!("{key}='1'") {
                    return Err(error("UCI firewall: есть несохранённые изменения"));
                }
                command("uci", &["set", &format!("{key}=1")], None)?;
            } else if actual.trim() != "1" {
                return Err(error("UCI firewall: неизвестное состояние offload"));
            }
            let pending = command("uci", &["changes", "firewall"], None)?;
            if pending.trim() == format!("{key}='1'") {
                command("uci", &["commit", "firewall"], None)?;
            } else if !pending.trim().is_empty() {
                return Err(error("UCI firewall: есть несохранённые изменения"));
            }
        } else if !matches!(saved.trim(), "selective" | "fallback" | "legacy") {
            return Err(error("неизвестный журнал восстановления fw4"));
        }
        let fw4 = value("R2O_FW4", "fw4");
        let init = value("R2O_FIREWALL_INIT", "/etc/init.d/firewall");
        command(&fw4, &["reload"], None).or_else(|first| {
            command(&init, &["reload"], None).map_err(|second| error(format!("{first}; {second}")))
        })?;
        if saved.trim() == "1" && command("uci", &["-q", "get", key], None)?.trim() != "1" {
            return Err(error("значение UCI offload не подтвердилось после reload"));
        }
        remove(&journal)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_native_flowtable_devices_priority_and_offload_flags() {
        let listing = "table inet fw4 { # handle 1\n\tflowtable ft { # handle 2\n\t\thook ingress priority filter\n\t\tdevices = { \"eth1\", \"lan1\" }\n\t\tflags offload\n\t\tcounter\n\t}\n}";
        assert_eq!(
            flowtable_definition(listing).as_deref(),
            Some(
                "hook ingress priority filter\ndevices = { \"eth1\", \"lan1\" }\nflags offload\ncounter"
            )
        );
        assert!(flowtable_definition("table inet fw4 {\n}").is_none());
    }

    #[test]
    fn signature_ignores_members_but_includes_rule_order() {
        let source = "table inet r2o {\n set routes {\n elements = { 1 timeout 10s,\n 2 timeout 4s }\n }\n chain output {\n queue num 2000 bypass\n }\n}";
        let expired = source.replace("2 timeout 4s", "3 timeout 7s");
        assert_eq!(structural(source), structural(&expired));
        assert_ne!(
            structural(source),
            structural(&expired.replace(" queue num", " return\n queue num"))
        );
    }
}
