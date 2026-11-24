use r2k_core::dns_config::{DnsService, dns_uri_parse};
use serde_json::Value;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::process::{Command, Stdio};

use super::{r2o_ndmc_path, r2o_read_ndmc_output, r2o_read_system_dns_services};

pub(super) struct Snapshot {
    pub services: Vec<DnsService>,
    pub active: Vec<Option<bool>>,
    pub journal_available: bool,
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
        let Some(services) = r2o_read_system_dns_services() else {
            self.cursor = Cursor::default();
            return None;
        };
        if self.services != services {
            self.cursor = Cursor::default();
            self.services.clone_from(&services);
        }
        let openwrt = Path::new("/etc/openwrt_release").exists();
        let instances = if openwrt && !services.is_empty() {
            let Some(instances) = openwrt_instances(&services) else {
                self.cursor = Cursor::default();
                return None;
            };
            instances
        } else {
            Vec::new()
        };
        if self.instances != instances {
            self.cursor = Cursor::default();
            self.instances = instances;
        }
        let instances = &self.instances;
        let mut active: Vec<_> = services
            .iter()
            .map(|service| {
                openwrt.then(|| instances.iter().any(|instance| instance.matches(service)))
            })
            .collect();
        let mut observed = vec![false; services.len()];
        if !services.is_empty() {
            let records = read_journal(openwrt);
            // После недоступности источника устанавливаем новую точку отсчёта.
            // События за время отсутствия актуальной конфигурации не считаются свежими.
            let Some(records) = records else {
                self.cursor = Cursor::default();
                return Some(Snapshot {
                    services,
                    active,
                    observed,
                    journal_available: false,
                });
            };
            for record in self.cursor.advance(&records) {
                for (index, service) in services.iter().enumerate() {
                    if record.observes(service, openwrt.then_some(instances.as_slice())) {
                        active[index] = Some(true);
                        observed[index] = true;
                    }
                }
            }
        }
        Some(Snapshot {
            services,
            active,
            observed,
            journal_available: true,
        })
    }
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

fn openwrt_instances(services: &[DnsService]) -> Option<Vec<Instance>> {
    let mut instances = Vec::new();
    for service in ["https-dns-proxy", "dnsproxy", "doqd"] {
        if !services.iter().any(|entry| {
            entry.source == service || service == "dnsproxy" && entry.source == "dnsproxy-http3"
        }) {
            continue;
        }
        let request = format!(r#"{{"name":"{service}","verbose":true}}"#);
        let response = output("/bin/ubus", &["call", "service", "list", &request])
            .or_else(|| output("/sbin/ubus", &["call", "service", "list", &request]))?;
        instances.extend(procd_instances(service, &response)?);
    }
    Some(instances)
}

fn procd_instances(source: &str, response: &str) -> Option<Vec<Instance>> {
    let root: Value = serde_json::from_str(response).ok()?;
    let Some(service) = root.as_object()?.get(source) else {
        return Some(Vec::new());
    };
    let mut result = Vec::new();
    for instance in service.get("instances")?.as_object()?.values() {
        if !instance.get("running")?.as_bool()? {
            continue;
        }
        let pid = instance.get("pid")?.as_u64().filter(|pid| *pid > 1)?;
        let command: Vec<&str> = instance
            .get("command")?
            .as_array()?
            .iter()
            .map(Value::as_str)
            .collect::<Option<_>>()?;
        if command.first().and_then(|arg| arg.rsplit('/').next()) != Some(source) {
            continue;
        }
        let mut upstreams = Vec::new();
        for args in command.windows(2) {
            let upstream_flag = match source {
                "https-dns-proxy" => matches!(args[0], "-r" | "--resolver-url"),
                _ => matches!(args[0], "-u" | "--upstream" | "--fallback"),
            };
            if upstream_flag && let Some(upstream) = dns_uri_parse(args[1], Some(source)) {
                if source == "dnsproxy"
                    && upstream.protocol == "doh"
                    && command.contains(&"--http3")
                {
                    let mut http3 = upstream.clone();
                    http3.protocol = "doh3".into();
                    upstreams.push(http3);
                }
                upstreams.push(upstream);
            }
        }
        result.push(Instance {
            source: source.into(),
            pid: Some(pid),
            upstreams,
        });
    }
    Some(result)
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
        let failure = matches!(self.severity, 'W' | 'E' | 'F')
            && ["error", "failed", "timed out", "unexpectedly"]
                .iter()
                .any(|word| body.contains(word))
            && body
                .split_ascii_whitespace()
                .map(|word| word.trim_matches(|c: char| !c.is_ascii_alphabetic()))
                .any(|word| matches!(word, "query" | "response" | "request"));
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
                    && uri.as_ref().map_or(instance.upstreams.len() == 1, |uri| {
                        same_upstream(service, uri)
                    })
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
            assert!(record.observes(&service, Some(&instances)));
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
            procd_instances("dnsproxy", router_plain).unwrap()[0]
                .upstreams
                .is_empty()
        );
    }
}
