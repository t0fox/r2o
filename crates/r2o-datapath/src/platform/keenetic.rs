use super::*;
use std::collections::BTreeSet;

pub(super) fn restore_fastnat(platform: &Platform) -> Result<()> {
    let journal = platform.run.join("fastnat.saved");
    let Some(previous) = optional(&journal)? else {
        return Ok(());
    };
    let previous: u32 = number(previous.trim())?;
    let sysctl = platform.proc.join("sys/net/netfilter/nf_conntrack_fastnat");
    let current: u32 = number(fs::read_to_string(&sysctl)?.trim())?;
    if current != previous {
        if current != 0 {
            return Err(error("FastNAT изменён вне R2O, журнал сохранён"));
        }
        fs::write(&sysctl, format!("{previous}\n"))?;
    }
    if fs::read_to_string(&sysctl)?.trim() != previous.to_string() {
        return Err(error("ядро не подтвердило восстановление FastNAT"));
    }
    remove(&journal)
}

pub(super) fn offload_status(platform: &Platform) {
    if platform.kind != Kind::Keenetic {
        println!("PPE: применяется к Keenetic");
        return;
    }
    let fastnat = fs::read_to_string(platform.proc.join("sys/net/netfilter/nf_conntrack_fastnat"))
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "unknown".into());
    let state = |version| {
        if value("R2O_PPE_DEOFFLOAD", "1") == "0" {
            return "disabled";
        }
        if iptables::ppe_target(platform, version).is_none() {
            return "unavailable";
        }
        match iptables::ppe_installed(version) {
            Ok(true) => "installed",
            Ok(false) => "missing",
            Err(_) => "unknown",
        }
    };
    let present = iptables::ppe_target(platform, 4).is_some();
    let v4 = state(4);
    let v6 = if platform.use_ipv6() {
        state(6)
    } else {
        "disabled"
    };
    println!(
        "PPE: target={} ipv4_rules={v4} ipv6_rules={v6} FastNAT={fastnat} lan_coverage=unverified",
        if present { "present" } else { "unavailable" }
    );
}

fn host_port(input: &str, default: u16) -> Option<(&str, u16)> {
    if let Ok(address) = input.parse::<IpAddr>()
        && !address.is_loopback()
    {
        return Some((input, default));
    }
    if let Some(bracketed) = input.strip_prefix('[') {
        let (host, trailing) = bracketed.split_once(']')?;
        if !matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
            return None;
        }
        let port = if trailing.is_empty() {
            default
        } else {
            trailing.strip_prefix(':')?.parse().ok()?
        };
        return (port > 0).then_some((host, port));
    }
    let (host, port) = match input.split_once(':') {
        Some((host, port)) => (host, port.parse().ok()?),
        None => (input, default),
    };
    (!host.is_empty()
        && !host.starts_with('-')
        && port > 0
        && host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_')))
    .then_some((host, port))
}

fn upstreams(text: &str) -> Result<BTreeSet<(&str, u16)>> {
    let mut endpoints = BTreeSet::new();
    let mut recognized = false;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if let ["dns_server", "=", primary, rest @ ..] = fields.as_slice() {
            recognized = true;
            let (host, port) = host_port(primary, 53)
                .ok_or_else(|| error("неизвестный формат адреса dns_server"))?;
            if !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
                endpoints.insert((host, port));
            }
            if let Some(candidate) = rest
                .windows(2)
                .find_map(|pair| (pair[0] == "#").then_some(pair[1]))
            {
                let candidate = candidate.split('@').next().unwrap_or(candidate);
                let (candidate, port) = if let Some(host) = candidate.strip_prefix("https://") {
                    (host.split('/').next().unwrap_or(host), 443)
                } else {
                    (candidate.strip_prefix("tls://").unwrap_or(candidate), 853)
                };
                endpoints.insert(
                    host_port(candidate, port)
                        .ok_or_else(|| error("неизвестный формат upstream Keenetic"))?,
                );
            }
        }
    }
    if !recognized {
        return Err(error("ndmc не вернул распознаваемые dns_server"));
    }
    if endpoints.len() > 32 {
        return Err(error("слишком много upstream Keenetic"));
    }
    Ok(endpoints)
}

fn addresses(text: &str) -> BTreeSet<IpAddr> {
    let mut answers = false;
    let mut result = BTreeSet::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with("Name:") {
            answers = true;
        }
        if answers
            && line.starts_with("Address")
            && let Some(ip) = line
                .split_whitespace()
                .filter_map(|word| word.parse::<IpAddr>().ok())
                .next()
            && !ip.is_loopback()
            && !ip.is_unspecified()
            && !ip.is_multicast()
        {
            result.insert(ip);
        }
    }
    result
}

pub(super) fn dns_exclusions(previous: &str) -> Result<String> {
    let dump = command("ndmc", &["-c", "more temp:ndnproxymain.conf"], None)
        .and_then(|text| {
            upstreams(&text)?;
            Ok(text)
        })
        .or_else(|_| command("ndmc", &["-c", "show dns-proxy"], None))?;
    let deadline = Instant::now() + Duration::from_secs(2);
    merge_exclusions(&dump, previous, |host| {
        bootstrap_addresses(host, &dump, |host, server| {
            let now = Instant::now();
            if now >= deadline {
                return BTreeSet::new();
            }
            let args = [host, &server.to_string()];
            invoke_before(
                "nslookup",
                &args,
                None,
                deadline.min(now + Duration::from_millis(500)),
            )
            .and_then(|output| checked("nslookup", &args, output))
            .map(|text| addresses(&text))
            .unwrap_or_default()
        })
    })
}

fn bootstrap_addresses(
    host: &str,
    dump: &str,
    mut lookup: impl FnMut(&str, IpAddr) -> BTreeSet<IpAddr>,
) -> BTreeSet<IpAddr> {
    // Для bootstrap используем только обычные глобальные DNS из NDM.
    // Доменные и зашифрованные upstream нельзя опрашивать как DNS на :53.
    let servers = dump.lines().filter_map(|line| {
        let mut words = line.split_whitespace();
        if words.next()? != "dns_server" || words.next()? != "=" {
            return None;
        }
        let (address, port) = host_port(words.next()?, 53)?;
        let address: IpAddr = address.parse().ok()?;
        (port == 53
            && words.next() == Some(".")
            && words.next().is_none()
            && !address.is_loopback()
            && !address.is_unspecified()
            && !address.is_multicast())
        .then_some(address)
    });
    std::iter::once(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .chain(servers.take(2))
        .find_map(|server| {
            let found = lookup(host, server);
            (!found.is_empty()).then_some(found)
        })
        .unwrap_or_default()
}

fn merge_exclusions(
    text: &str,
    previous: &str,
    mut resolve: impl FnMut(&str) -> BTreeSet<IpAddr>,
) -> Result<String> {
    let endpoints = upstreams(text)?;
    let mut updated = String::new();
    for (host, port) in endpoints {
        let found = match host.parse::<IpAddr>() {
            Ok(ip) => BTreeSet::from([ip]),
            Err(_) => resolve(host),
        };
        if found.is_empty() {
            for line in previous.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                if let [old_host, ip, old_port] = fields.as_slice()
                    && *old_host == host
                    && old_port.parse() == Ok(port)
                    && ip.parse::<IpAddr>().is_ok()
                {
                    updated.push_str(line);
                    updated.push('\n');
                }
            }
        } else {
            for ip in found {
                use std::fmt::Write;
                writeln!(updated, "{host} {ip} {port}").unwrap();
            }
        }
    }
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_failure_preserves_only_the_matching_host_and_port() {
        let old =
            "dns.example 192.0.2.1 443\ndns.example 192.0.2.2 853\nother.example 192.0.2.3 443\n";
        let dump = "dns_server = 127.0.0.1 # https://dns.example/dns-query";
        assert_eq!(
            merge_exclusions(dump, old, |_| BTreeSet::new()).unwrap(),
            "dns.example 192.0.2.1 443\n"
        );
        assert_eq!(
            merge_exclusions(dump, old, |_| BTreeSet::from(["192.0.2.8"
                .parse()
                .unwrap()]))
            .unwrap(),
            "dns.example 192.0.2.8 443\n"
        );
    }

    #[test]
    fn dead_loopback_resolver_uses_only_configured_global_plain_dns() {
        let dump = "dns_server = 192.0.2.1 example.lan\ndns_server = 192.0.2.2:853 .\n\
                    dns_server = 127.0.0.1 # https://dns.example/dns-query\n\
                    dns_server = 192.0.2.3 .\n";
        let mut calls = Vec::new();
        let assigned_ip: IpAddr = "198.51.100.2".parse().unwrap();
        let merged = merge_exclusions(dump, "", |host| {
            bootstrap_addresses(host, dump, |host, server| {
                calls.push((host.to_owned(), server));
                if server.is_loopback() {
                    BTreeSet::new()
                } else {
                    BTreeSet::from([assigned_ip])
                }
            })
        })
        .unwrap();
        assert_eq!(
            calls,
            vec![
                ("dns.example".into(), "127.0.0.1".parse().unwrap()),
                ("dns.example".into(), "192.0.2.3".parse().unwrap())
            ]
        );
        assert!(merged.contains("dns.example 198.51.100.2 443\n"));
    }

    #[test]
    fn rejects_unknown_ndm_and_untrusted_endpoints() {
        assert!(upstreams("error: management process unavailable").is_err());
        assert!(upstreams("dns_server = 127.0.0.1 # https://--quiet/dns").is_err());
        let parsed = upstreams("dns_server = 127.0.0.1 # https://dns.example/dns-query\ndns_server = [2001:db8::1]:5353").unwrap();
        assert_eq!(
            parsed,
            BTreeSet::from([("dns.example", 443), ("2001:db8::1", 5353)])
        );
        assert_eq!(
            addresses(
                "Server: 127.0.0.1\nAddress: 127.0.0.1\nName: dns.example\nAddress 1: 192.0.2.1"
            ),
            BTreeSet::from(["192.0.2.1".parse().unwrap()])
        );
    }
}
