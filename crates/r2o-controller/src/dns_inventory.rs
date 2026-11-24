use r2k_core::dns_config::{self, DNS_SERVICE_MAX, DnsService, dns_uri_parse};
use serde_json::Value;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::process::{Command, Stdio};

use super::{r2o_ndmc_path, r2o_read_dns_config_file, r2o_read_ndmc_output, r2o_read_ndmc_status};

pub(super) struct Snapshot {
    pub services: Vec<DnsService>,
    pub active: Vec<Option<bool>>,
    pub journal_available: bool,
    pub keep_observed: bool,
    pub observed: Vec<bool>,
}

#[derive(Default)]
pub(super) struct Inventory {
    services: Vec<DnsService>,
    instances: Vec<Instance>,
    cursor: Cursor,
}

impl Inventory {
    pub fn read(&mut self) -> Option<Snapshot> {
        let openwrt = Path::new("/etc/openwrt_release").exists();
        let Some((services, active, instances)) = (if openwrt {
            openwrt_resolvers()
        } else if r2o_ndmc_path().is_some()
            || std::env::var("R2O_PLATFORM").as_deref() == Ok("keenetic")
        {
            keenetic_resolvers()
        } else {
            Some((Vec::new(), Vec::new(), Vec::new()))
        }) else {
            self.cursor = Cursor::default();
            return None;
        };
        let keep_observed = self.services == services && self.instances == instances;
        if !keep_observed {
            self.cursor = Cursor::default();
            self.services.clone_from(&services);
            self.instances = instances;
        }
        let mut observed = vec![false; services.len()];
        let mut journal_available = true;
        if active.contains(&Some(true)) {
            match read_journal(openwrt) {
                Some(records) => {
                    for record in self.cursor.advance(&records) {
                        for (index, service) in services.iter().enumerate() {
                            if active[index] == Some(true)
                                && record.observes(
                                    service,
                                    (openwrt || service.source == "doqd")
                                        .then_some(self.instances.as_slice()),
                                )
                            {
                                observed[index] = true;
                            }
                        }
                    }
                }
                None => {
                    self.cursor = Cursor::default();
                    journal_available = false;
                }
            }
        } else {
            self.cursor = Cursor::default();
        }
        Some(Snapshot {
            services,
            active,
            journal_available,
            keep_observed,
            observed,
        })
    }
}

type ResolverSnapshot = (Vec<DnsService>, Vec<Option<bool>>, Vec<Instance>);

fn openwrt_resolvers() -> Option<ResolverSnapshot> {
    let https = r2o_read_dns_config_file("/etc/config/https-dns-proxy").ok()?;
    let dnsproxy = r2o_read_dns_config_file("/etc/config/dnsproxy").ok()?;
    let doqd = r2o_read_dns_config_file("/etc/doqd.conf").ok()?;
    let mut services = Vec::new();
    if let Some(config) = &https {
        services.extend(dns_config::parse_https_dns_proxy(config));
    }
    if let Some(config) = &dnsproxy {
        services.extend(dns_config::parse_dnsproxy(config));
    }
    if let Some(config) = &doqd {
        services.extend(dns_config::parse_doqd(config, "doqd"));
    }

    // Один снимок procd включает все службы и их фактические аргументы.
    // Не связываем endpoint с процессом по имени службы, если upstream
    // не подтверждён её аргументом или явно загруженной конфигурацией.
    let request = ["call", "service", "list", r#"{"verbose":true}"#];
    let response = output("/bin/ubus", &request).or_else(|| output("/sbin/ubus", &request))?;
    let root: Value = serde_json::from_str(&response).ok()?;
    let procd = root.as_object()?;
    let instances: Vec<_> = procd.values().flat_map(read_procd_instances).collect();
    for upstream in instances.iter().flat_map(|instance| &instance.upstreams) {
        let managed = match upstream.source.as_str() {
            "https-dns-proxy" => https.is_some(),
            "dnsproxy" | "dnsproxy-http3" => dnsproxy.is_some(),
            "doqd" => doqd.is_some(),
            _ => false,
        };
        if !managed
            && services.len() < DNS_SERVICE_MAX
            && !services
                .iter()
                .any(|entry| entry.source == upstream.source && same_upstream(entry, upstream))
        {
            services.push(upstream.clone());
        }
    }
    services.truncate(DNS_SERVICE_MAX);
    let active = services
        .iter()
        .map(|entry| {
            let source = entry.source.strip_suffix("-http3").unwrap_or(&entry.source);
            if instances.iter().any(|instance| instance.matches(entry)) {
                Some(true)
            } else if let Some(service) = procd.get(source) {
                // A running instance with an unrecognized or changed upstream cannot
                // establish whether this configured endpoint is running.
                service
                    .get("instances")?
                    .as_object()?
                    .values()
                    .all(|instance| instance.get("running").and_then(Value::as_bool) == Some(false))
                    .then_some(false)
            } else {
                Some(false)
            }
        })
        .collect();
    Some((services, active, instances))
}

fn keenetic_resolvers() -> Option<ResolverSnapshot> {
    let status = r2o_read_ndmc_status()?;
    let mut services = dns_config::parse_keenetic(&status);
    let running = keenetic_proxy_running(&status);
    let mut active = vec![running; services.len()];
    let external = r2o_read_dns_config_file("/opt/etc/doqd.conf").ok()?;
    let listener = external.as_deref().and_then(doqd_listener);
    let bootstrap = plain_servers(
        keenetic_name_servers(&status)
            .filter_map(|(value, endpoint)| (Some(endpoint) != listener).then_some(value)),
    );
    for service in &mut services {
        service.bootstrap_dns.clone_from(&bootstrap);
    }
    let mut instances = Vec::new();
    if let Some(config) = external {
        let candidates = dns_config::parse_doqd(&config, "doqd");
        let routed_to_doqd = listener.is_some_and(|listener| {
            keenetic_name_servers(&status).any(|(_, endpoint)| endpoint == listener)
        });
        let pid = (routed_to_doqd && !candidates.is_empty())
            .then(keenetic_doqd_pid)
            .flatten();
        if let Some(pid) = pid {
            instances.push(Instance {
                source: "doqd".into(),
                pid: Some(pid),
                upstreams: candidates.clone(),
            });
        }
        services.extend(
            candidates
                .into_iter()
                .take(DNS_SERVICE_MAX - services.len()),
        );
        active.resize(services.len(), pid.map(|_| true));
    }
    Some((services, active, instances))
}

fn keenetic_proxy_running(status: &str) -> Option<bool> {
    let config = status
        .split_once("proxy-config:")?
        .1
        .split("proxy-stat:")
        .next()?;
    let mut ports = config
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(key, _)| matches!(key.trim(), "dns_udp_port" | "dns_tcp_port"))
        .filter_map(|(_, value)| value.trim().parse::<u16>().ok())
        .peekable();
    ports.peek()?;
    Some(ports.any(|port| port != 0))
}

fn keenetic_name_servers(status: &str) -> impl Iterator<Item = (&str, std::net::SocketAddr)> {
    status.lines().filter_map(|line| {
        let (key, value) = line.trim().split_once('=')?;
        let mut words = value.split_ascii_whitespace();
        let server = words.next()?;
        if key.trim() != "dns_server" || words.next().is_some_and(|scope| scope != ".") {
            return None;
        }
        Some((server, numeric_endpoint(server)?))
    })
}

fn doqd_listener(config: &str) -> Option<std::net::SocketAddr> {
    config.lines().find_map(|line| {
        let mut words = line.split('#').next()?.split_ascii_whitespace();
        if words.next()? != "listen" {
            return None;
        }
        words.next()?.trim_matches(['"', '\'']).parse().ok()
    })
}

fn keenetic_doqd_pid() -> Option<u64> {
    let pids = output("/bin/pidof", &["doqd"]).or_else(|| output("pidof", &["doqd"]))?;
    pids.split_ascii_whitespace()
        .filter_map(|pid| pid.parse::<u64>().ok().filter(|pid| *pid > 1))
        .find(|pid| {
            std::fs::read_link(format!("/proc/{pid}/exe"))
                .is_ok_and(|path| path == Path::new("/opt/sbin/doqd"))
                && r2o_read_dns_config_file(&format!("/proc/{pid}/cmdline"))
                    .ok()
                    .flatten()
                    .is_some_and(|command| {
                        command
                            .split('\0')
                            .skip(1)
                            .filter(|arg| !arg.is_empty())
                            .eq(["-c", "/opt/etc/doqd.conf"])
                    })
        })
}

pub(super) fn plain_bootstrap_servers() -> String {
    let configs = [
        "/tmp/resolv.conf.d/resolv.conf.auto",
        "/tmp/resolv.conf.auto",
        "/etc/resolv.conf",
    ]
    .map(|path| r2o_read_dns_config_file(path).ok().flatten());
    plain_servers(
        configs
            .iter()
            .filter_map(Option::as_deref)
            .flat_map(|text| {
                text.lines().filter_map(|line| {
                    let mut words = line.split_ascii_whitespace();
                    (words.next()? == "nameserver")
                        .then(|| words.next())
                        .flatten()
                })
            }),
    )
}

fn numeric_endpoint(server: &str) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr};
    server
        .parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, 53))
        .or_else(|_| server.parse::<SocketAddr>())
        .ok()
}

fn plain_servers<'a>(servers: impl Iterator<Item = &'a str>) -> String {
    let mut selected = String::new();
    for endpoint in servers.filter_map(numeric_endpoint).filter(|endpoint| {
        endpoint.port() != 0
            && !endpoint.ip().is_loopback()
            && !endpoint.ip().is_unspecified()
            && !endpoint.ip().is_multicast()
    }) {
        let value = endpoint.to_string();
        if selected.split(',').any(|saved| saved == value) {
            continue;
        }
        if !selected.is_empty() {
            selected.push(',');
        }
        selected.push_str(&value);
        if selected.contains(',') {
            break;
        }
    }
    selected
}

fn output(program: &str, args: &[&str]) -> Option<String> {
    let child = Command::new(program)
        .args(args)
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    r2o_read_ndmc_output(child)
}

fn same_upstream(service: &DnsService, upstream: &DnsService) -> bool {
    service.protocol == upstream.protocol
        && service.host.eq_ignore_ascii_case(&upstream.host)
        && service.port == upstream.port
        && service.path == upstream.path
        && (upstream.sni.is_empty() || service.sni.eq_ignore_ascii_case(&upstream.sni))
}

#[derive(PartialEq, Eq)]
struct Instance {
    source: String,
    pid: Option<u64>,
    upstreams: Vec<DnsService>,
}

impl Instance {
    fn matches(&self, service: &DnsService) -> bool {
        (self.source == service.source
            || self.source == "dnsproxy" && service.source == "dnsproxy-http3")
            && self
                .upstreams
                .iter()
                .any(|upstream| same_upstream(service, upstream))
    }
}

#[cfg(test)]
fn procd_instances(source: &str, response: &str) -> Option<Vec<Instance>> {
    let root: Value = serde_json::from_str(response).ok()?;
    Some(
        root.as_object()?
            .get(source)
            .map_or_else(Vec::new, read_procd_instances),
    )
}

fn read_procd_instances(service: &Value) -> Vec<Instance> {
    service
        .get("instances")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|instances| instances.values())
        .filter_map(procd_instance)
        .collect()
}

fn procd_instance(instance: &Value) -> Option<Instance> {
    if !instance.get("running")?.as_bool()? {
        return None;
    }
    let pid = instance.get("pid")?.as_u64().filter(|pid| *pid > 1)?;
    let command = instance.get("command")?.as_array()?;
    let executable = command.first()?.as_str()?.rsplit('/').next()?;
    let mut upstreams = Vec::new();
    for (index, arg) in command.iter().enumerate().skip(1) {
        let arg = arg.as_str()?;
        let (flag, target) = arg.split_once('=').map_or_else(
            || (arg, command.get(index + 1).and_then(Value::as_str)),
            |(flag, value)| (flag, Some(value)),
        );
        let upstream_flag = match executable {
            "https-dns-proxy" => matches!(flag, "-r" | "--resolver-url"),
            "dnsproxy" | "doqd" => matches!(flag, "-u" | "--upstream" | "-f" | "--fallback"),
            _ => flag == "--dns-upstream",
        };
        if upstream_flag
            && let Some(upstream) =
                target.and_then(|target| dns_uri_parse(target, Some(executable)))
        {
            if executable == "dnsproxy"
                && upstream.protocol == "doh"
                && command
                    .iter()
                    .any(|arg| matches!(arg.as_str(), Some("--http3" | "--http3=true")))
            {
                let mut http3 = upstream.clone();
                http3.protocol = "doh3".into();
                upstreams.push(http3);
            }
            upstreams.push(upstream);
        }
    }
    let config = command.windows(2).find_map(|args| {
        let flag = if executable == "stubby" { "-C" } else { "-c" };
        (args[0].as_str() == Some(flag))
            .then(|| args[1].as_str())
            .flatten()
            .filter(|path| path.starts_with('/'))
    });
    if let Some(path) = config
        && matches!(executable, "doqd" | "stubby" | "unbound")
        && let Ok(Some(text)) = r2o_read_dns_config_file(path)
    {
        upstreams.extend(match executable {
            "stubby" => stubby_upstreams(&text),
            "unbound" => unbound_upstreams(&text),
            _ => dns_config::parse_doqd(&text, "doqd"),
        });
    }
    if upstreams.is_empty() {
        return None;
    }
    upstreams.truncate(DNS_SERVICE_MAX);
    Some(Instance {
        source: executable.into(),
        pid: Some(pid),
        upstreams,
    })
}

fn dot_forwarder(value: &str, port: &str, sni: &str, source: &str) -> Option<DnsService> {
    let address: std::net::IpAddr = value.parse().ok()?;
    let endpoint = std::net::SocketAddr::new(address, port.parse().ok()?);
    let mut service = dns_uri_parse(&format!("tls://{endpoint}"), Some(source))?;
    if !sni.is_empty() {
        let sni = dns_uri_parse(&format!("tls://{sni}"), Some(source))?;
        service.sni = sni.host;
    }
    Some(service)
}

fn stubby_upstreams(text: &str) -> Vec<DnsService> {
    // OpenWrt generates this flat section of stubby.yml from UCI.
    let Some((_, transports)) = config_sections(text).find(|(key, _)| *key == "dns_transport_list")
    else {
        return Vec::new();
    };
    if !transports
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .eq(["- GETDNS_TRANSPORT_TLS"])
    {
        return Vec::new();
    }
    let Some((_, body)) =
        config_sections(text).find(|(key, _)| *key == "upstream_recursive_servers")
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let (mut address, mut port, mut sni) = ("", "853", "");
    for line in body.lines().chain(std::iter::once("- address_data:")) {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().trim_matches(['"', '\'']);
        match key {
            "- address_data" => {
                if let Some(service) = dot_forwarder(address, port, sni, "stubby") {
                    out.push(service);
                }
                (address, port, sni) = (value, "853", "");
            }
            "tls_port" => port = value,
            "tls_auth_name" => sni = value,
            _ => {}
        }
    }
    out
}

fn config_sections(text: &str) -> impl Iterator<Item = (&str, &str)> {
    let mut headers = std::iter::once(0)
        .chain(text.match_indices('\n').map(|(index, _)| index + 1))
        .filter_map(|start| {
            let line = text[start..].lines().next()?;
            line.split_once(':')
                .map(|(key, _)| key)
                .filter(|key| {
                    !key.is_empty()
                        && key
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                })
                .map(|key| (start, key))
        })
        .peekable();
    std::iter::from_fn(move || {
        let (start, key) = headers.next()?;
        let end = headers.peek().map_or(text.len(), |(index, _)| *index);
        Some((key, &text[start + key.len() + 1..end]))
    })
}

fn unbound_upstreams(text: &str) -> Vec<DnsService> {
    let port = config_sections(text)
        .filter(|(key, _)| *key == "server")
        .flat_map(|(_, body)| body.lines())
        .filter_map(|line| line.trim().strip_prefix("tls-port:"))
        .map(str::trim)
        .last()
        .unwrap_or("853");
    config_sections(text)
        .filter(|(key, _)| *key == "forward-zone")
        .flat_map(|(_, zone)| {
            let tls = zone.lines().any(|line| {
                matches!(
                    line.trim(),
                    "forward-tls-upstream: yes" | "forward-ssl-upstream: yes"
                )
            });
            zone.lines().filter_map(move |line| {
                let endpoint = line
                    .trim()
                    .strip_prefix("forward-addr:")?
                    .trim()
                    .trim_matches('"');
                let (address, sni) = endpoint.split_once('#').unwrap_or((endpoint, ""));
                let (address, port) = address.split_once('@').unwrap_or((address, port));
                tls.then(|| dot_forwarder(address, port, sni, "unbound"))
                    .flatten()
            })
        })
        .collect()
}

// D2K 741e036a/044ea4ef: снимок procd/NDM публикуется атомарно, курсор
// инициализируется на первом снимке, потерянный якорь никогда не переигрывает журнал.
#[derive(Default)]
struct Cursor {
    anchor: Option<(Option<u64>, u64)>,
    primed: bool,
}

impl Cursor {
    fn advance<'a>(&mut self, records: &'a [Record]) -> &'a [Record] {
        if records.is_empty() && self.anchor.is_some() {
            *self = Self::default();
            return records;
        }
        let start = match self.anchor {
            Some((id, hash)) => records
                .iter()
                .rposition(|record| {
                    record.hash == hash && (id.is_none() || record.id.is_none() || record.id == id)
                })
                .map(|index| index + 1),
            None => self.primed.then_some(0),
        };
        self.primed = true;
        self.anchor = records.last().map(|record| (record.id, record.hash));
        &records[start.unwrap_or(records.len())..]
    }
}

struct Record {
    id: Option<u64>,
    hash: u64,
    source: String,
    pid: Option<u64>,
    severity: char,
    body: String,
}

impl Record {
    fn new(id: Option<u64>, stamp: &str, tag: &str, severity: char, body: &str) -> Self {
        let mut hasher = DefaultHasher::new();
        [stamp, tag, body].into_iter().for_each(|part| {
            part.bytes()
                .filter(|byte| !byte.is_ascii_whitespace())
                .for_each(|byte| byte.hash(&mut hasher));
        });
        severity.hash(&mut hasher);
        let (source, pid) = tag.split_once('[').map_or((tag, None), |(name, pid)| {
            (name, pid.strip_suffix(']').and_then(|pid| pid.parse().ok()))
        });
        Self {
            id,
            hash: hasher.finish(),
            source: source.into(),
            pid,
            severity,
            body: body.into(),
        }
    }

    fn observes(&self, service: &DnsService, instances: Option<&[Instance]>) -> bool {
        let body = self.body.to_ascii_lowercase();
        if [
            "bootstrap",
            "health check",
            "self-test",
            "healthcheck",
            "probe",
        ]
        .iter()
        .any(|word| body.contains(word))
        {
            return false;
        }
        let failure = matches!(self.severity, 'W' | 'E' | 'F')
            && ["error", "failed", "timed out", "unexpectedly"]
                .iter()
                .any(|word| body.contains(word))
            && body
                .split_ascii_whitespace()
                .map(|word| word.trim_matches(|c: char| !c.is_ascii_alphabetic()))
                .any(|word| matches!(word, "query" | "response"));
        let reply = [
            "query succeeded",
            "received dns response",
            "dns query completed",
        ]
        .iter()
        .any(|phrase| body.contains(phrase));
        if !failure && !reply {
            return false;
        }
        let mut uris = self.body.split_ascii_whitespace().filter_map(|word| {
            let uri = word.trim_matches(['"', '\'', '(', ')', ',', ';']);
            dns_uri_parse(uri, Some(&self.source))
        });
        let uri = uris.next();
        if uris.next().is_some() {
            return false;
        }
        if let Some(instances) = instances {
            return instances.iter().any(|instance| {
                instance.pid == self.pid
                    && instance.source == self.source
                    && instance.matches(service)
                    && !(service.protocol == "doh"
                        && instance.upstreams.iter().any(|candidate| {
                            candidate.protocol == "doh3"
                                && candidate.host == service.host
                                && candidate.port == service.port
                                && candidate.path == service.path
                        }))
                    && uri.as_ref().map_or(
                        instance.source == "https-dns-proxy" && instance.upstreams.len() == 1,
                        |uri| same_upstream(service, uri),
                    )
            });
        }
        let protocol = match self.source.as_str() {
            "https-dns-proxy" => "doh",
            "tls-dns-proxy" => "dot",
            "quic-dns-proxy" | "doqd" | "doq-web" => "doq",
            _ => return false,
        };
        (service.source.starts_with("keenetic-")
            || service.source == "doqd" && self.source == "doqd")
            && service.protocol == protocol
            && uri.is_some_and(|uri| same_upstream(service, &uri))
    }
}

fn read_journal(openwrt: bool) -> Option<Vec<Record>> {
    if openwrt {
        let text = output("/sbin/logread", &["-l", "128"])?;
        return Some(text_records(&text, true));
    }
    if let Some(records) = output(
        "curl",
        &[
            "-q",
            "-fs",
            "--noproxy",
            "*",
            "--max-time",
            "0.2",
            "-H",
            "Content-Type: application/json",
            "-d",
            r#"{"once":true,"max-lines":128}"#,
            "http://127.0.0.1:79/rci/show/log",
        ],
    )
    .and_then(|text| rci_records(&text))
    {
        return Some(records);
    }
    let text = output(r2o_ndmc_path()?, &["-c", "show log"])?;
    let records = text_records(&text, false);
    (!records.is_empty()).then_some(records)
}

fn rci_records(text: &str) -> Option<Vec<Record>> {
    let root: Value = serde_json::from_str(text).ok()?;
    let mut records = Vec::new();
    for (id, value) in root.get("log")?.as_object()? {
        let message = value.get("message")?;
        records.push(Record::new(
            Some(id.parse().ok()?),
            value.get("timestamp")?.as_str()?,
            value.get("ident")?.as_str()?,
            message.get("label")?.as_str()?.chars().next()?,
            message.get("message")?.as_str()?,
        ));
    }
    records.sort_unstable_by_key(|record| record.id);
    Some(records)
}

fn text_records(text: &str, openwrt: bool) -> Vec<Record> {
    if openwrt {
        return text
            .lines()
            .filter_map(|line| {
                let (header, body) = line.split_once(": ")?;
                let mut fields = header.split_ascii_whitespace();
                let stamp = fields.by_ref().take(5).collect::<Vec<_>>().join(" ");
                let level = fields.next()?.split_once('.')?.1;
                let tag = fields.next()?;
                let severity = body
                    .strip_prefix('[')
                    .and_then(|body| {
                        let (label, _) = body.split_once(']')?;
                        (label.len() == 1).then(|| label.chars().next()).flatten()
                    })
                    .unwrap_or(match level {
                        "warn" | "warning" => 'W',
                        "err" | "error" | "crit" | "alert" | "emerg" => 'E',
                        _ => 'I',
                    });
                Some(Record::new(None, &stamp, tag, severity, body))
            })
            .collect();
    }
    // В ndmc длинное сообщение переносится на строку с отступом.
    let mut lines: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_start_matches("\x1b[K");
        if line.as_bytes().get(1..3) == Some(b" [") {
            lines.push(line.into());
        } else if line.starts_with(char::is_whitespace)
            && let Some(previous) = lines.last_mut()
        {
            previous.push(' ');
            previous.push_str(line.trim());
        }
    }
    lines
        .iter()
        .filter_map(|line| {
            let (stamp, record) = line.get(3..)?.split_once("] ")?;
            let (source, body) = record.split_once(": ")?;
            Some(Record::new(None, stamp, source, line.chars().next()?, body))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_cursor_ignores_initial_and_rotated_snapshots() {
        let mut cursor = Cursor::default();
        let rci = r#"{"log":{"3":{"timestamp":"Oct 10 14:00:01","ident":"ndm","message":{"label":"I","message":"Ready"}},"1":{"timestamp":"Oct 10 13:00:00","ident":"https-dns-proxy","message":{"label":"W","message":"query failed https://old.example/dns-query"}}}}"#;
        let records = rci_records(rci).unwrap();
        assert!(cursor.advance(&records).is_empty());
        let cli = "I [Oct 10 14:00:01] ndm: Ready\nW [Oct 10 14:00:02] https-dns-proxy: query failed\n  https://dns.example/dns-query\n";
        let first =
            dns_uri_parse("https://dns.example/dns-query", Some("keenetic-system")).unwrap();
        let records = text_records(cli, false);
        assert!(cursor.advance(&records)[0].observes(&first, None));
        assert!(cursor.advance(&records).is_empty());
        let rotated = text_records(
            "W [Oct 10 14:00:03] https-dns-proxy: query failed https://dns.example/dns-query\n",
            false,
        );
        assert!(cursor.advance(&rotated).is_empty());
    }

    #[test]
    fn only_running_openwrt_instance_with_the_current_upstream_counts() {
        let service = dns_uri_parse(
            "https://dns.example/dns-query?profile=current",
            Some("https-dns-proxy"),
        )
        .unwrap();
        let config = r#"{"https-dns-proxy":{"instances":{"one":{"running":true,"pid":222,"command":["/usr/sbin/https-dns-proxy","-r","https://dns.example/dns-query?profile=current"]},"disabled":{"running":false,"command":["/usr/sbin/https-dns-proxy","-r","https://dns.example/dns-query?profile=old"]}}}}"#;
        let instances = procd_instances("https-dns-proxy", config).unwrap();
        assert_eq!(instances.len(), 1);
        assert!(instances[0].matches(&service));
        let records = text_records(
            concat!(
                "Mon Nov  9 12:00:00 2026 daemon.err curl[222]: query failed https://dns.example/dns-query?profile=current\n",
                "Mon Nov  9 12:00:00 2026 daemon.err https-dns-proxy[111]: query failed https://dns.example/dns-query?profile=current\n",
                "Mon Nov  9 12:00:00 2026 daemon.err https-dns-proxy[222]: setup failed https://dns.example/dns-query?profile=current\n",
                "Mon Nov  9 12:00:00 2026 daemon.err https-dns-proxy[222]: query failed https://dns.example/dns-query?profile=old\n",
                "Mon Nov  9 12:00:00 2026 daemon.info https-dns-proxy[222]: [E] DNS query failed\n",
            ),
            true,
        );
        assert_eq!(records.len(), 5);
        assert!(
            records[..4]
                .iter()
                .all(|record| !record.observes(&service, Some(&instances)))
        );
        assert!(records[4].observes(&service, Some(&instances)));
        assert!(!records[4].observes(&service, Some(&[])));
    }

    #[test]
    fn dnsproxy_distinguishes_plain_dns_and_encrypted_upstream_protocols() {
        let response = r#"{"dnsproxy":{"instances":{"dnsproxy":{"running":true,"pid":80,"command":["/usr/bin/dnsproxy","--upstream","9.9.9.9","--upstream","https://shared.example/dns-query","--upstream","tls://dot.example","--fallback","quic://doq.example","--http3"]}}}}"#;
        let instances = procd_instances("dnsproxy", response).unwrap();
        assert_eq!(instances[0].upstreams.len(), 4);
        for (url, word) in [
            ("https://shared.example/dns-query", "doh"),
            ("h3://shared.example/dns-query", "doh3"),
            ("tls://dot.example", "dot"),
            ("quic://doq.example", "doq"),
        ] {
            let service = dns_uri_parse(url, Some("dnsproxy")).unwrap();
            assert_eq!(service.protocol, word);
            let record = Record::new(
                None,
                "",
                "dnsproxy[80]",
                'I',
                &format!("received DNS response {url}"),
            );
            assert_eq!(record.observes(&service, Some(&instances)), word != "doh");
            let unrelated = Record::new(
                None,
                "",
                "quic-client[80]",
                'I',
                &format!("received DNS response {url}"),
            );
            assert!(!unrelated.observes(&service, Some(&instances)));
        }
        let router_plain = r#"{"dnsproxy":{"instances":{"dnsproxy":{"running":true,"pid":80,"command":["dnsproxy","--upstream","9.9.9.9"]}}}}"#;
        assert!(
            procd_instances("dnsproxy", router_plain)
                .unwrap()
                .is_empty()
        );
        let mixed = r#"{"dnsproxy":{"instances":{"dnsproxy":{"running":true,"pid":80,"command":["dnsproxy","-u","9.9.9.9","-u","tls://dot.example"]}}}}"#;
        let instances = procd_instances("dnsproxy", mixed).unwrap();
        let dot = &instances[0].upstreams[0];
        let unspecified = Record::new(None, "", "dnsproxy[80]", 'W', "DNS query failed");
        assert!(!unspecified.observes(dot, Some(&instances)));
    }

    #[test]
    fn dns_forwarders_require_explicit_tls_configuration() {
        let stubby = "dns_transport_list:\n- GETDNS_TRANSPORT_TLS\nidle_timeout: 1000\n\
                      upstream_recursive_servers:\n- address_data: 2001:db8::53\n  tls_auth_name: dot.example\n";
        let services = stubby_upstreams(stubby);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].host, "2001:db8::53");
        assert_eq!(services[0].sni, "dot.example");
        assert!(stubby_upstreams(&stubby.replace("TRANSPORT_TLS", "TRANSPORT_UDP")).is_empty());
        let unbound = concat!(
            "server:\n  tls-port: 8853\n",
            "# forward-zone:\n  # forward-tls-upstream: yes\n",
            "forward-zone:\n  forward-tls-upstream: yes\n  forward-addr: 192.0.2.53#dot.example\n",
            "forward-zone:\n  forward-addr: 192.0.2.54\n"
        );
        let services = unbound_upstreams(unbound);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].port, 8853);
        assert_eq!(services[0].sni, "dot.example");
    }

    #[test]
    fn dns_keenetic_requires_runtime_listener_and_exact_external_resolver_route() {
        assert_eq!(keenetic_proxy_running("proxy-status:\n"), None);
        assert_eq!(
            keenetic_proxy_running("proxy-config:\n  dns_udp_port = 0\n"),
            Some(false)
        );
        let status = concat!(
            "proxy-status:\n",
            "    dns_server = 192.0.2.1:5354 .\n",
            "    dns_server = 192.0.2.2 restricted.example\n",
            "    dns_server = 192.0.2.53 .\n",
            "proxy-config:\n    dns_udp_port = 53\n    dns_tcp_port = 53\n"
        );
        assert_eq!(keenetic_proxy_running(status), Some(true));
        let listener = doqd_listener("listen 192.0.2.1:5354\n").unwrap();
        assert!(keenetic_name_servers(status).any(|(_, endpoint)| endpoint == listener));
        assert_eq!(
            plain_servers(
                keenetic_name_servers(status)
                    .filter_map(|(value, endpoint)| { (endpoint != listener).then_some(value) })
            ),
            "192.0.2.53:53"
        );
    }
}
