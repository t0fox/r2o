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

fn get(endpoint: Endpoint) -> Result<bool> {
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
        if (endpoint.version() == 4 || ipv6) && ttl(until, now).is_some() && !get(endpoint)? {
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
    if get(endpoint)? {
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

fn fw4_chain(name: &str) -> Result<Option<String>> {
    let args = ["-a", "list", "chain", "inet", "fw4", name];
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

// Из nlink config::rules::longest_increasing (Marc Pardo, MIT).
// Нужна только упорядоченная ветка plan_chain для нашей собственной цепочки.
fn longest_increasing(seq: &[usize]) -> std::collections::BTreeSet<usize> {
    let mut tails: Vec<usize> = Vec::new();
    let mut prev: Vec<Option<usize>> = vec![None; seq.len()];
    for (i, &v) in seq.iter().enumerate() {
        let k = tails.partition_point(|&t| seq[t] < v);
        if k > 0 {
            prev[i] = Some(tails[k - 1]);
        }
        if k == tails.len() {
            tails.push(i);
        } else {
            tails[k] = i;
        }
    }
    let mut out = std::collections::BTreeSet::new();
    let mut cur = tails.last().copied();
    while let Some(i) = cur {
        out.insert(seq[i]);
        cur = prev[i];
    }
    out
}

fn offload_diff(existing: &str, desired: &[String]) -> String {
    let mut installed = BTreeMap::new();
    let mut order = Vec::new();
    let mut edits = String::new();
    for (rule, handle) in existing.lines().filter_map(handle) {
        if rule.ends_with('{') || rule.starts_with("comment ") {
            continue;
        }
        let rule = if rule == ADMISSION_ALTERNATE {
            ADMISSION
        } else {
            rule
        };
        if let Some(index) = desired.iter().position(|candidate| candidate == rule)
            && !installed.contains_key(&index)
        {
            installed.insert(index, handle);
            order.push(index);
        } else {
            writeln!(
                edits,
                "delete rule inet fw4 {OFFLOAD_CHAIN} handle {handle}"
            )
            .unwrap();
        }
    }
    let staying = longest_increasing(&order);
    for (&index, &handle) in &installed {
        if !staying.contains(&index) {
            writeln!(
                edits,
                "delete rule inet fw4 {OFFLOAD_CHAIN} handle {handle}"
            )
            .unwrap();
        }
    }
    for (index, rule) in desired.iter().enumerate() {
        if staying.contains(&index) {
            continue;
        }
        if let Some(anchor) = staying.range(index..).next() {
            let handle = installed[anchor];
            writeln!(
                edits,
                "insert rule inet fw4 {OFFLOAD_CHAIN} position {handle} {rule}"
            )
            .unwrap();
        } else {
            writeln!(edits, "add rule inet fw4 {OFFLOAD_CHAIN} {rule}").unwrap();
        }
    }
    edits
}

pub(super) fn offload(platform: &Platform, ipv6: bool, remove_rules: bool) -> Result<()> {
    let selected: Vec<_> = platform
        .software_path
        .iter()
        .filter(|endpoint| !remove_rules && (endpoint.version() == 4 || ipv6))
        .collect();
    let Some(forward) = fw4_chain("forward")? else {
        return Ok(());
    };
    let admission = forward
        .lines()
        .filter_map(handle)
        .find(|(rule, _)| matches!(*rule, ADMISSION | ADMISSION_ALTERNATE | OFFLOAD_JUMP));
    let own = fw4_chain(OFFLOAD_CHAIN)?;
    if let Some(ref chain) = own
        && !chain
            .lines()
            .any(|line| line.trim_start().starts_with("comment \"r2o-managed\""))
    {
        return Err(error("fw4: цепочка r2o_offload принадлежит другой службе"));
    }
    if selected.is_empty() {
        if let Some((OFFLOAD_JUMP, id)) = admission {
            Nft.apply(&format!(
                "replace rule inet fw4 forward handle {id} {ADMISSION}\ndelete chain inet fw4 {OFFLOAD_CHAIN}\n"
            ))?;
        } else if own.is_some() {
            Nft.apply(&format!("delete chain inet fw4 {OFFLOAD_CHAIN}\n"))?;
        }
        return Ok(());
    }
    let Some((current, id)) = admission else {
        if forward.contains("flow add") || forward.contains("flow offload") {
            return Err(error(
                "неподдерживаемое правило admission fw4, штатное ускорение сохранено",
            ));
        }
        return Ok(());
    };
    let mut desired = Vec::new();
    for endpoint in selected {
        let family = if endpoint.version() == 4 { "ip" } else { "ip6" };
        let Endpoint {
            address,
            protocol,
            port,
            ..
        } = endpoint;
        desired.push(format!("meta l4proto {protocol} ct original {family} daddr {address} ct original proto-dst {port} return"));
    }
    desired.push(ADMISSION.into());
    let mut rules = if own.is_none() {
        format!("add chain inet fw4 {OFFLOAD_CHAIN} {{ comment \"r2o-managed\"; }}\n")
    } else {
        String::new()
    };
    rules.push_str(&offload_diff(own.as_deref().unwrap_or_default(), &desired));
    if current != OFFLOAD_JUMP {
        writeln!(
            rules,
            "replace rule inet fw4 forward handle {id} {OFFLOAD_JUMP}"
        )
        .unwrap();
    }
    if rules.is_empty() {
        Ok(())
    } else {
        Nft.apply(&rules)
    }
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
    fn ordered_diff_keeps_matching_handles() {
        let live = "chain r2o_offload { # handle 5\n return # handle 7\n drop # handle 8\n accept # handle 9\n}";
        let desired = ["drop".into(), "return".into(), "accept".into()];
        let diff = offload_diff(live, &desired);
        assert_eq!(diff.lines().count(), 2);
        assert!(!diff.contains("handle 9"));
        assert_eq!(
            offload_diff(live, &["return".into(), "drop".into(), "accept".into()]),
            ""
        );
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
