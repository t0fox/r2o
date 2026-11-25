use super::*;
use std::collections::BTreeSet;

const FASTNAT: &str = "sys/net/netfilter/nf_conntrack_fastnat";
const FASTNAT_SAVED: &str = "fastnat.saved";

pub(super) fn fastnat(platform: &Platform) -> Result<Option<u32>> {
    optional(&platform.proc.join(FASTNAT))?
        .map(|value| number(value.trim()))
        .transpose()
}

// D2K fastnat_off: транзитный SNAT должен оставаться видимым через conntrack.
pub(super) fn suspend_fastnat(platform: &Platform) -> Result<()> {
    let journal = platform.run.join(FASTNAT_SAVED);
    let saved = optional(&journal)?;
    let Some(current) = fastnat(platform)? else {
        return if saved.is_some() {
            Err(error("FastNAT недоступен, исходное значение сохранено"))
        } else {
            Ok(())
        };
    };
    if let Some(saved) = saved {
        number::<u32>(saved.trim())?;
    } else {
        atomic(&journal, &format!("{current}\n"))?;
    }
    if current == 0 {
        return Ok(());
    }
    fs::write(platform.proc.join(FASTNAT), "0\n")?;
    if fastnat(platform)? != Some(0) {
        return Err(error("ядро не подтвердило приостановку FastNAT"));
    }
    Ok(())
}

pub(super) fn restore_fastnat(platform: &Platform) -> Result<()> {
    let journal = platform.run.join(FASTNAT_SAVED);
    let Some(previous) = optional(&journal)? else {
        return Ok(());
    };
    let previous: u32 = number(previous.trim())?;
    let current = fastnat(platform)?.ok_or_else(|| error("FastNAT недоступен"))?;
    if current != previous {
        if current != 0 {
            return Err(error("FastNAT изменён вне R2O, журнал сохранён"));
        }
        fs::write(platform.proc.join(FASTNAT), format!("{previous}\n"))?;
    }
    if fastnat(platform)? != Some(previous) {
        return Err(error("ядро не подтвердило восстановление FastNAT"));
    }
    remove(&journal)
}

pub(super) fn offload_status(platform: &Platform, ipv6: bool) -> String {
    if platform.kind != Kind::Keenetic {
        return "PPE: применяется к Keenetic\n".into();
    }
    let fastnat = match fastnat(platform) {
        Ok(Some(value)) => value.to_string(),
        Ok(None) => "unavailable".into(),
        Err(_) => "unknown".into(),
    };
    let state = |version| -> String {
        if value("R2O_PPE_DEOFFLOAD", "1") == "0" {
            return "disabled".into();
        }
        match iptables::ppe_coverage(platform, version) {
            Ok(None) => "unavailable".into(),
            Ok(Some((0, expected))) => format!("missing(0/{expected})"),
            Ok(Some((found, expected))) if found == expected => {
                format!("installed({found}/{expected})")
            }
            Ok(Some((found, expected))) => format!("partial({found}/{expected})"),
            Err(_) => "unknown".into(),
        }
    };
    let present = iptables::ppe_target(platform, 4).is_some();
    let v4 = state(4);
    let v6 = if ipv6 { state(6) } else { "disabled".into() };
    format!(
        "PPE: target={} ipv4_rules={v4} ipv6_rules={v6} FastNAT={fastnat} lan_coverage=unverified\n",
        if present { "present" } else { "unavailable" }
    )
}

pub(super) fn binds_status(platform: &Platform, address: Option<Ipv4Addr>) -> String {
    let file = platform.proc.join("driver/hw_nat/foe/binds");
    match File::open(file).and_then(|file| read_binds(BufReader::new(file), address)) {
        Ok((entries, found)) => match address {
            Some(address) => {
                format!("ppe_binds={entries}\nppe_bind_address={address} present={found}\n")
            }
            None => format!("ppe_binds={entries}\n"),
        },
        Err(err) if err.kind() == io::ErrorKind::NotFound => "ppe_binds=unavailable\n".into(),
        Err(err) => format!("ppe_binds=unknown ({err})\n"),
    }
}

fn read_binds(reader: impl BufRead, address: Option<Ipv4Addr>) -> Result<(usize, bool)> {
    let mut entries = 0;
    let mut found = false;
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty()
            || line
                .strip_prefix("PPE")
                .and_then(|s| s.strip_suffix(':'))
                .is_some_and(|s| s.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        entries += 1;
        if let Some(address) = address {
            found |= line
                .split(|c: char| !c.is_ascii_digit() && c != '.')
                .any(|part| part.parse::<Ipv4Addr>().ok() == Some(address));
        }
    }
    Ok((entries, found))
}

fn host_port(input: &str, default: u16) -> Option<(&str, u16)> {
    if default == 0 {
        return None;
    }
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
    let mut tls = None;
    let mut https = false;
    for line in text
        .lines()
        .map(str::trim)
        .chain(std::iter::once("proxy-end:"))
    {
        if line.starts_with("server-") || line.starts_with("proxy-") {
            if https {
                return Err(error("отсутствует uri DNS-over-HTTPS"));
            }
            if let Some((host, port)) = tls.take() {
                let (host, port) =
                    host_port(host, port).ok_or_else(|| error("неверный address DNS-over-TLS"))?;
                endpoints.insert((host, port));
                recognized = true;
            }
            if line == "server-tls:" {
                tls = Some(("", 853));
            }
            https = line == "server-https:";
        } else if let Some((host, port)) = &mut tls {
            if let Some(address) = line.strip_prefix("address:") {
                *host = address.trim();
            } else if let Some(value) = line.strip_prefix("port:") {
                *port = number(value.trim())?;
            }
        } else if https && let Some(uri) = line.strip_prefix("uri:") {
            endpoints.insert(
                https_endpoint(uri.trim()).ok_or_else(|| error("неверный uri DNS-over-HTTPS"))?,
            );
            recognized = true;
            https = false;
        }
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
                let endpoint = if candidate.starts_with("https://") {
                    https_endpoint(candidate)
                } else {
                    host_port(candidate.strip_prefix("tls://").unwrap_or(candidate), 853)
                };
                endpoints
                    .insert(endpoint.ok_or_else(|| error("неизвестный формат upstream Keenetic"))?);
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

fn https_endpoint(uri: &str) -> Option<(&str, u16)> {
    let host = uri
        .strip_prefix("https://")?
        .split(['/', '?', '#'])
        .next()?;
    host_port(host, 443)
}

fn secure_config_omitted(text: &str) -> bool {
    let mut loopback_upstream = false;
    for line in text.lines().map(str::trim) {
        if matches!(
            line,
            "proxy-tls:" | "proxy-https:" | "server-tls:" | "server-https:"
        ) {
            return false;
        }
        let mut words = line.split_whitespace();
        if words.next() == Some("dns_server")
            && words.next() == Some("=")
            && let Some((host, port)) = words.next().and_then(|value| host_port(value, 53))
            && port != 53
            && host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
            && !words.any(|word| word == "#")
        {
            loopback_upstream = true;
        }
    }
    loopback_upstream
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

pub(super) fn dns_exclusions(previous: &str) -> Result<(String, bool)> {
    let show = command("ndmc", &["-c", "show dns-proxy"], None).and_then(|text| {
        upstreams(&text)?;
        Ok(text)
    });
    let fallback = show
        .as_ref()
        .map_or(true, |dump| secure_config_omitted(dump));
    let dump = show.or_else(|_| command("ndmc", &["-c", "more temp:ndnproxymain.conf"], None))?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut unresolved = false;
    let updated = merge_exclusions(&dump, previous, |host| {
        let found = bootstrap_addresses(host, &dump, |host, server| {
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
        });
        unresolved |= found.is_empty();
        found
    })?;
    if !fallback {
        return Ok((updated, unresolved));
    }
    // A legacy proxy-config dump can omit secure upstreams represented by loopback sockets.
    let mut union = updated.lines().collect::<BTreeSet<_>>();
    union.extend(previous.lines());
    Ok((
        union.into_iter().map(|line| format!("{line}\n")).collect(),
        true,
    ))
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
    servers
        .take(2)
        .chain(std::iter::once(IpAddr::V4(Ipv4Addr::LOCALHOST)))
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
                assert!(!server.is_loopback());
                BTreeSet::from([assigned_ip])
            })
        })
        .unwrap();
        assert_eq!(
            calls,
            vec![("dns.example".into(), "192.0.2.3".parse().unwrap())]
        );
        assert!(merged.contains("dns.example 198.51.100.2 443\n"));
    }

    #[test]
    fn rejects_unknown_ndm_and_untrusted_endpoints() {
        assert!(upstreams("error: management process unavailable").is_err());
        assert!(upstreams("proxy-config:\nserver-https:\n").is_err());
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

    #[test]
    fn structured_dns_proxy_reports_secure_endpoints_without_local_resolution() {
        let dump = "proxy-status:\n  proxy-config:\ndns_server = 127.0.0.1:40500 .\n\
                    proxy-tls:\n  server-tls:\n    address: 2001:db8::53\n    port: 8853\n\
                    proxy-https:\n  server-https:\n    uri: https://192.0.2.53:444/dns-query?format=wire\n";
        assert_eq!(
            merge_exclusions(dump, "", |_| panic!("literal upstreams need no resolver")).unwrap(),
            "192.0.2.53 192.0.2.53 444\n2001:db8::53 2001:db8::53 8853\n"
        );
        assert!(!secure_config_omitted(dump));
        assert!(secure_config_omitted(
            "proxy-config:\ndns_server = 127.0.0.1:40500 .\n"
        ));
    }
}
