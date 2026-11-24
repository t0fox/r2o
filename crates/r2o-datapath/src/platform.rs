use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

mod iptables;
mod keenetic;
mod linux;
mod nft;

type Result<T> = io::Result<T>;
type Leases = BTreeMap<Endpoint, u64>;

// Адаптация FirewallBackend::apply из DFW (Pit Kleyersburg, MIT).
// Тип правил определяется backend. Применение получает только подготовленный план.
trait FirewallBackend {
    type Rule: ?Sized;
    fn apply(&self, rules: &Self::Rule) -> Result<()>;
}

const ACCT: &str = "sys/net/netfilter/nf_conntrack_acct";
const ACTIVE: &str = "platform.active";
const RULES: &str = "platform.rules";
const LEASES: &str = "platform.dns";
const EVENT: &str = "platform.sock";
const LOCK: &str = "platform.lock";

fn error(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn remove(path: &Path) -> Result<()> {
    fs::remove_file(path).or_else(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(err)
        }
    })
}

fn atomic(path: &Path, contents: &str) -> Result<()> {
    let mut temp = path.as_os_str().to_owned();
    temp.push(".pending");
    let temp = PathBuf::from(temp);
    remove(&temp)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(contents.as_bytes())?;
    fs::rename(temp, path)
}

pub fn write_health(path: &Path, health: &serde_json::Value) -> Result<()> {
    atomic(path, &health.to_string())
}

fn value(name: &str, default: &str) -> String {
    env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default.into())
}

fn path(name: &str, default: &Path) -> PathBuf {
    env::var_os(name)
        .filter(|v| !v.is_empty())
        .map_or_else(|| default.into(), Into::into)
}

fn number<T: std::str::FromStr>(s: &str) -> Result<T> {
    s.parse()
        .map_err(|_| error(format!("недопустимое число: {s}")))
}

fn mark(s: &str) -> Result<u32> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).map_err(|_| error("неверная метка")),
        None => number(s),
    }
}

fn ports(text: &str) -> Result<String> {
    let mut slots = 0;
    let mut items = Vec::new();
    for item in text.split(',') {
        if let Some((start, end)) = item.split_once(':') {
            let (start, end) = (number::<u16>(start)?, number::<u16>(end)?);
            if start >= end {
                return Err(error("неверный диапазон портов"));
            }
            slots += 2;
            items.push(format!("{start}:{end}"));
        } else {
            slots += 1;
            items.push(number::<u16>(item)?.to_string());
        }
    }
    if slots > 15 {
        return Err(error("список портов превышает 15 полей multiport"));
    }
    Ok(items.join(","))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Keenetic,
    OpenWrt,
    Linux,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Iptables,
    Nft,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Endpoint {
    address: IpAddr,
    protocol: &'static str,
    port: u16,
    uid: Option<u32>,
}

impl Endpoint {
    fn parse(address: &str, proto: &str, port: &str, uid: Option<&str>) -> Result<Self> {
        let address: IpAddr = number(address)?;
        let port = number(port)?;
        let protocol = match proto {
            "tcp" => "tcp",
            "udp" => "udp",
            _ => return Err(error("ожидается tcp или udp")),
        };
        let uid = uid.map(number::<u32>).transpose()?;
        if port == 0
            || address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || matches!(address, IpAddr::V4(ip) if ip.octets()[0] == 0 || ip.octets()[0] == 255)
            || matches!(address, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
            || uid.is_some_and(|id| id == 0 || id == u32::MAX || protocol != "udp")
        {
            return Err(error("недопустимый адрес, порт или UID"));
        }
        Ok(Self {
            address,
            protocol,
            port,
            uid,
        })
    }

    fn targets(text: &str) -> Result<Vec<Self>> {
        let mut endpoints = Vec::new();
        for target in text.split_whitespace() {
            let (protocol, target) = target.split_once("://").unwrap_or(("udp", target));
            let address: SocketAddr = number(target)?;
            endpoints.push(Self::parse(
                &address.ip().to_string(),
                protocol,
                &address.port().to_string(),
                None,
            )?);
            if endpoints.len() > 16 {
                return Err(error("ожидается до 16 endpoint"));
            }
        }
        endpoints.sort_unstable();
        endpoints.dedup();
        Ok(endpoints)
    }

    fn version(self) -> u8 {
        if self.address.is_ipv4() { 4 } else { 6 }
    }
}

#[derive(Debug)]
struct Platform {
    kind: Kind,
    backend: Backend,
    run: PathBuf,
    proc: PathBuf,
    ipv6: bool,
    queues: [u16; 2],
    raw: u32,
    probe: u32,
    measure: u32,
    ports: String,
    voice: String,
    http: String,
    dns: String,
    early: u16,
    voice_window: (u16, u16),
    plain: Vec<Endpoint>,
    gate: Option<(Ipv4Addr, u16)>,
    software_path: Vec<Endpoint>,
    interval: Duration,
}

impl Platform {
    fn detect() -> Result<Self> {
        let root = path("R2O_DIR", Path::new("/opt/r2o"));
        let kind = match value("R2O_PLATFORM", "").as_str() {
            "keenetic" => Kind::Keenetic,
            "openwrt" => Kind::OpenWrt,
            "" if Path::new("/opt/etc/ndm").is_dir() || Path::new("/bin/ndmc").exists() => {
                Kind::Keenetic
            }
            "" if path("R2O_OPENWRT_RELEASE", Path::new("/etc/openwrt_release")).is_file() => {
                Kind::OpenWrt
            }
            _ => Kind::Linux,
        };
        let backend = match value("FW_BACKEND", "auto").as_str() {
            "nft" => Backend::Nft,
            "iptables" => Backend::Iptables,
            "auto" if kind == Kind::OpenWrt && available("nft") => Backend::Nft,
            "auto" => Backend::Iptables,
            _ => return Err(error("FW_BACKEND должен быть auto, nft или iptables")),
        };
        let queues = [
            number(&value("QUEUE_NUM", "2000"))?,
            number(&value("QUEUE_NUM6", "2001"))?,
        ];
        if queues[0] == queues[1] {
            return Err(error("номера очередей IPv4 и IPv6 должны различаться"));
        }
        let (raw, probe, measure) = (
            mark(&value("MARK", "45"))?,
            mark(&value("PROBE_MARK", "46"))?,
            mark(&value("MEASURE_MARK", "47"))?,
        );
        if measure != 0 && (measure == raw || measure == probe) {
            return Err(error("MEASURE_MARK должна отличаться от MARK и PROBE_MARK"));
        }
        let ipv6 = match value("R2O_IPV6_ENABLED_RUNTIME", &value("IPV6_ENABLED", "1")).as_str() {
            "0" => false,
            "1" => true,
            _ => return Err(error("IPV6_ENABLED должен быть 0 или 1")),
        };
        let connbytes = value("CONNBYTES", "0:8");
        let early = if connbytes == "auto" {
            8
        } else {
            number(
                connbytes
                    .strip_prefix("0:")
                    .ok_or_else(|| error("CONNBYTES ожидает 0:N или auto"))?,
            )?
        };
        let voice_window = value("VOICE_CONNBYTES", "0:4");
        let (minimum, maximum) = voice_window
            .split_once(':')
            .ok_or_else(|| error("VOICE_CONNBYTES ожидает N:M"))?;
        let voice_window = (number(minimum)?, number(maximum)?);
        if voice_window.0 > voice_window.1 {
            return Err(error("неверное окно VOICE_CONNBYTES"));
        }
        let plain = if probe == 0 || probe == raw || measure == 0 {
            Vec::new()
        } else {
            Endpoint::targets(&value("DNS_DISCOVERY_ENDPOINTS", "")).unwrap_or_else(|err| {
                eprintln!("r2o-platform: DNS Discovery: {err}");
                Vec::new()
            })
        };
        let gate_text = value("D2K_GATE", "");
        let gate = gate_text
            .strip_prefix("http://")
            .unwrap_or(&gate_text)
            .split('/')
            .next()
            .and_then(|address| address.parse::<std::net::SocketAddrV4>().ok())
            .map(|addr| (*addr.ip(), addr.port()));
        let interval = number::<u64>(&value("HEAL_EVERY", "60"))
            .ok()
            .filter(|n| (1..=3600).contains(n))
            .unwrap_or(60);
        Ok(Self {
            kind,
            backend,
            run: path("R2O_RUN_DIR", &root.join("run")),
            proc: path("R2O_PROC_DIR", Path::new("/proc")),
            ipv6,
            queues,
            raw,
            probe,
            measure,
            ports: ports(&value("PORTS", "0:65535"))?,
            voice: ports(&value(
                "VOICE_PORTS",
                "50000:50099,1400,3478:3481,5349,19294:19344",
            ))?,
            http: ports(&value("HTTP_KEEPALIVE_PORTS", "80"))?,
            dns: ports(&value("DNS_PORTS", "53,853"))?,
            early,
            voice_window,
            plain,
            gate,
            software_path: Endpoint::targets(&value("R2O_SOFTWARE_PATH_ENDPOINTS", ""))?,
            interval: Duration::from_secs(interval),
        })
    }

    fn queue(&self, version: u8) -> u16 {
        self.queues[usize::from(version == 6)]
    }

    fn setup_run(&self) -> Result<()> {
        fs::create_dir_all(&self.run)?;
        if fs::symlink_metadata(&self.run)?.file_type().is_symlink() {
            return Err(error("каталог run не должен быть ссылкой"));
        }
        Ok(())
    }

    fn lock(&self) -> Result<File> {
        self.setup_run()?;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.run.join(LOCK))?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            // Дескриптор удерживает блокировку между снимком и применением.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(file);
            }
            let err = io::Error::last_os_error();
            if !matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) || Instant::now() >= deadline
            {
                return Err(err);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn load_modules(&self) {
        let mut modules = vec!["nfnetlink_queue", "nf_conntrack", "nf_conntrack_netlink"];
        if self.backend == Backend::Nft {
            modules.push("nft_queue");
        } else {
            modules.extend([
                "xt_NFQUEUE",
                "xt_conntrack",
                "xt_connbytes",
                "xt_multiport",
                "xt_mark",
                "xt_addrtype",
                "xt_comment",
                "ip6table_mangle",
            ]);
        }
        let sys = path("R2O_SYS_MODULE_DIR", Path::new("/sys/module"));
        let lib = path("R2O_MODULES_DIR", Path::new("/lib/modules"));
        let version = command("uname", &["-r"], None).unwrap_or_default();
        for module in modules {
            if sys.join(module).exists() || command("modprobe", &[module], None).is_ok() {
                continue;
            }
            let file = format!("{module}.ko");
            for candidate in [lib.join(version.trim()).join(&file), lib.join(&file)] {
                if candidate.is_file()
                    && command("insmod", &[&candidate.to_string_lossy()], None).is_ok()
                {
                    break;
                }
            }
        }
    }

    fn use_ipv6(&self) -> bool {
        self.ipv6
            && linux::ipv6_enabled(&self.proc).is_ok()
            && (self.backend == Backend::Nft
                || available("ip6tables-restore") && iptables::list(6, "mangle").is_ok())
    }

    fn queue_evidence(&self, version: u8) -> Result<QueueEvidence> {
        let status = path(
            "R2O_NFQUEUE_STATUS",
            &self.proc.join("net/netfilter/nfnetlink_queue"),
        );
        let queues = fs::read_to_string(status)?;
        queue_evidence(&queues, self.queue(version)).ok_or_else(|| {
            error(format!(
                "IPv{version}: очередь {} без слушателя в режиме COPY_PACKET",
                self.queue(version)
            ))
        })
    }

    fn peer(&self, version: u8) -> Result<u32> {
        Ok(self.queue_evidence(version)?.peer)
    }

    fn peers(&self, ipv6: bool) -> Result<()> {
        self.peer(4)?;
        if ipv6 {
            self.peer(6)?;
        }
        Ok(())
    }

    fn accounting(&self, repair: bool) -> Result<()> {
        let module = (self.kind == Kind::Keenetic).then(|| {
            path("R2O_SYS_MODULE_DIR", Path::new("/sys/module"))
                .join("nf_conntrack/parameters/acct")
        });
        linux::accounting(&self.proc.join(ACCT), module.as_deref(), repair)
    }

    fn accounting_sample(&self) -> Result<(usize, usize, bool)> {
        let table = File::open(self.proc.join("net/nf_conntrack")).or_else(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                File::open(self.proc.join("net/ip_conntrack"))
            } else {
                Err(err)
            }
        })?;
        sample_accounting(BufReader::new(table))
    }

    fn dns_uid_ready(&self, version: u8) -> Result<bool> {
        if self.backend != Backend::Nft {
            return Ok(false);
        }
        let flag = optional(
            &self
                .run
                .join(format!("platform.uid.{}", self.queue(version))),
        )?;
        let advertised = flag.and_then(|value| value.trim().parse::<u32>().ok());
        Ok(advertised.is_some() && advertised == Some(self.peer(version)?))
    }

    fn boot(&self) -> Result<String> {
        let boot = fs::read_to_string(self.proc.join("sys/kernel/random/boot_id"))?;
        Ok(boot.trim().to_owned())
    }

    fn leases(&self) -> Result<Leases> {
        let Some(text) = optional(&self.run.join(LEASES))? else {
            return Ok(Leases::new());
        };
        let mut lines = text.lines();
        if lines.next() != Some(self.boot()?.as_str()) {
            return Ok(Leases::new());
        }
        let now = uptime()?;
        lines
            .filter(|line| !line.is_empty())
            .map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                let [ip, protocol, port, uid, until] = fields.as_slice() else {
                    return Err(error("повреждён журнал DNS"));
                };
                Ok((
                    Endpoint::parse(ip, protocol, port, (*uid != "-").then_some(*uid))?,
                    number::<u64>(until)?,
                ))
            })
            .filter(|entry| entry.as_ref().map_or(true, |(_, deadline)| *deadline > now))
            .collect()
    }

    fn save_leases(&self, leases: &Leases) -> Result<()> {
        let mut contents = self.boot()? + "\n";
        for (endpoint, until) in leases {
            use std::fmt::Write;
            let uid = endpoint.uid.map(|id| id.to_string()).unwrap_or("-".into());
            writeln!(
                contents,
                "{} {} {} {uid} {until}",
                endpoint.address, endpoint.protocol, endpoint.port
            )
            .unwrap();
        }
        atomic(&self.run.join(LEASES), &contents)
    }

    fn fingerprint(&self, ipv6: bool) -> Result<String> {
        let mut hash = Sha256::new();
        match self.backend {
            Backend::Iptables => iptables::fingerprint(self, ipv6, &mut hash)?,
            Backend::Nft => nft::fingerprint(&mut hash)?,
        }
        Ok(format!("{:x}", hash.finalize()))
    }

    fn status(&self, ipv6: bool) -> Result<()> {
        self.peers(ipv6)?;
        self.accounting(false)?;
        let expected = optional(&self.run.join(RULES))?.unwrap_or_default();
        if expected != self.fingerprint(ipv6)? {
            return Err(error("порядок, hooks или состав firewall изменились"));
        }
        Ok(())
    }

    fn install(&self, ipv6: bool, leases: &Leases, exclusions: &str) -> Result<()> {
        match self.backend {
            Backend::Nft => nft::install(self, ipv6, leases)?,
            Backend::Iptables => iptables::install(self, ipv6, leases, exclusions)?,
        }
        atomic(&self.run.join(RULES), &self.fingerprint(ipv6)?)
    }

    fn reconcile(&self, start: bool, refresh_dns: bool) -> Result<()> {
        let active_path = self.run.join(ACTIVE);
        let exclusions_path = self.run.join("dns-excl");
        let dns_sample =
            if self.kind == Kind::Keenetic && self.backend == Backend::Iptables && refresh_dns {
                // ndmc и bootstrap могут ждать сеть дольше, чем down ждёт flock.
                // Открытый маркер отличает этот запуск от последующего down/up.
                let activation = File::open(&active_path).ok();
                if !start && activation.is_none() {
                    return Ok(());
                }
                let previous = optional(&exclusions_path)?.unwrap_or_default();
                let sample = keenetic::dns_exclusions(&previous);
                Some((activation, previous, sample))
            } else {
                None
            };
        let _lock = self.lock()?;
        if !start && !active_path.is_file() {
            return Ok(());
        }
        if start {
            self.load_modules();
        }
        let ipv6 = self.use_ipv6();
        self.peers(ipv6)?;
        self.accounting(true)?;
        self.restore_legacy_offload()?;

        let exclusions = optional(&exclusions_path)?.unwrap_or_default();
        let desired = if let Some((activation, previous, sample)) = dns_sample
            && previous == exclusions
            && activation
                .and_then(|file| file.metadata().ok())
                .map(|metadata| (metadata.dev(), metadata.ino()))
                == fs::metadata(&active_path)
                    .ok()
                    .map(|metadata| (metadata.dev(), metadata.ino()))
        {
            let health = self.run.join("platform.dns-excl-degraded");
            match sample {
                Ok((updated, degraded)) => {
                    if degraded {
                        atomic(&health, "не все DNS upstream подтверждены\n")?;
                    } else {
                        remove(&health)?;
                    }
                    updated
                }
                Err(err) => {
                    atomic(&health, &err.to_string())?;
                    eprintln!("r2o-platform: прежние исключения DNS сохранены: {err}");
                    exclusions.clone()
                }
            }
        } else {
            exclusions.clone()
        };
        let mut leases = self.leases()?;
        let mut live = true;
        if self.backend == Backend::Nft {
            for version in [4, 6].into_iter().filter(|v| *v == 4 || ipv6) {
                let endpoints: Vec<_> = leases
                    .keys()
                    .copied()
                    .filter(|e| e.version() == version && e.uid.is_some())
                    .collect();
                if !endpoints.is_empty() && !self.dns_uid_ready(version)? {
                    for endpoint in endpoints {
                        leases.remove(&endpoint);
                        live &= !nft::lease_present(endpoint)?;
                    }
                }
            }
        }
        live &= match self.backend {
            Backend::Nft => nft::leases_live(&leases, ipv6)?,
            Backend::Iptables => iptables::leases_live(&leases, ipv6)?,
        };
        if start || desired != exclusions || !live || self.status(ipv6).is_err() {
            self.install(ipv6, &leases, &desired)?;
            if desired != exclusions {
                atomic(&exclusions_path, &desired)?;
            }
        }
        self.status(ipv6)?;
        if start {
            atomic(&active_path, "1\n")?;
        }
        if self.kind == Kind::OpenWrt && self.backend == Backend::Nft {
            let state = self.run.join("platform.offload-error");
            match nft::offload(self, ipv6, false) {
                Ok(()) => remove(&state)?,
                Err(err) => {
                    atomic(&state, &err.to_string())?;
                    if !start {
                        return Err(err);
                    }
                    eprintln!("r2o-platform: fw4, ограниченное покрытие: {err}");
                }
            }
        }
        Ok(())
    }

    fn reconcile_reported(&self, start: bool, refresh_dns: bool) -> Result<()> {
        use serde_json::json;
        let result = self.reconcile(start, refresh_dns);
        let active = self.run.join(ACTIVE).is_file();
        let state = env::var_os("R2O_META_STATE_DIR")
            .map(PathBuf::from)
            .map(|path| path.join("diagnostics"));
        if (start || active)
            && state
                .is_some_and(|dir| dir.join("enabled").is_file() && !dir.join("paused").is_file())
        {
            let sample = self.accounting_sample().ok().map(|(with, without, bounded)| {
                json!({"with_counters": with, "without_full_counters": without, "bounded": bounded})
            });
            let firewall = json!({
                "platform": match self.kind { Kind::Keenetic => "keenetic", Kind::OpenWrt => "openwrt", Kind::Linux => "linux" },
                "backend": match self.backend { Backend::Iptables => "iptables", Backend::Nft => "nft" },
                "active": active,
                "verified": active && result.is_ok(),
                "adapter_error": result.as_ref().err().map(|error| limit_health_error(&error.to_string())),
                "offload_error": optional(&self.run.join("platform.offload-error")).ok().flatten().map(|s| limit_health_error(&s)),
                "dns_adapter_error": optional(&self.run.join("platform.dns-excl-degraded")).ok().flatten().map(|s| limit_health_error(&s)),
                "fastnat": optional(&self.proc.join("sys/net/netfilter/nf_conntrack_fastnat")).ok().flatten().and_then(|s| s.trim().parse::<u32>().ok()),
                "rules": (self.backend == Backend::Iptables).then(|| {
                    let evidence = |family| iptables::diagnostic_counters(self, family);
                    json!({"ipv4": evidence(4), "ipv6": self.ipv6.then(|| evidence(6))})
                }),
                "conntrack_accounting": self.accounting(false).is_ok(),
                "conntrack_entries": sample,
            });
            let name = if start {
                "platform-start-health.json"
            } else {
                "platform-health.json"
            };
            let dir = path("R2O_RUNTIME_DIR", &self.run);
            if let Err(error) = write_health(&dir.join(name), &firewall) {
                eprintln!("r2o-platform: запись снимка диагностики: {error}");
            }
        }
        result
    }

    fn down(&self) -> Result<()> {
        let _lock = self.lock()?;
        remove(&self.run.join(ACTIVE))?;
        let rules = match self.backend {
            Backend::Nft => nft::down("r2o"),
            Backend::Iptables => iptables::down(self),
        };
        let offload = if self.kind == Kind::OpenWrt && self.backend == Backend::Nft {
            nft::offload(self, false, true)
        } else {
            Ok(())
        };
        let legacy = self.restore_legacy_offload();
        rules.and(offload).and(legacy)?;
        remove(&self.run.join(RULES))
    }

    fn dns_route(&self, args: &[String]) -> Result<()> {
        let [action, address, protocol, port, seconds, trailing @ ..] = args else {
            return Err(error(
                "ожидается dns-route add|del адрес протокол порт TTL [UID]",
            ));
        };
        let add = match action.as_str() {
            "add" => true,
            "del" => false,
            _ => return Err(error("ожидается add или del")),
        };
        if trailing.len() > 1 {
            return Err(error("ожидается один UID"));
        }
        let endpoint = Endpoint::parse(
            address,
            protocol,
            port,
            trailing.first().map(String::as_str),
        )?;
        let seconds: u64 = number(seconds)?;
        if endpoint.port == 53 || seconds > 300 || add && seconds == 0 {
            return Err(error("недопустимый TTL или порт DNS"));
        }
        let _lock = self.lock()?;
        let version = endpoint.version();
        let ipv6 = self.use_ipv6();
        if version == 6 && !ipv6 {
            return Err(error("IPv6 NFQUEUE недоступна"));
        }
        if endpoint.uid.is_some() && add && !self.dns_uid_ready(version)? {
            return Err(error(
                "привязка DNS по UID недоступна на этом backend или NFQUEUE",
            ));
        }
        let old = self.leases()?;
        let mut leases = old.clone();
        if add {
            if !self.run.join(ACTIVE).is_file() {
                return Err(error("правила платформы не активны"));
            }
            leases.insert(endpoint, uptime()? + seconds * 1000);
            if leases
                .keys()
                .filter(|e| e.version() == version && e.uid.is_some() == endpoint.uid.is_some())
                .count()
                > 64
            {
                return Err(error("достигнут лимит 64 привязок DNS"));
            }
        } else {
            leases.remove(&endpoint);
        }
        self.save_leases(&leases)?;
        let result = (|| match self.backend {
            Backend::Nft => nft::route(endpoint, add, seconds),
            Backend::Iptables if endpoint.uid.is_none() => {
                let exclusions = optional(&self.run.join("dns-excl"))?.unwrap_or_default();
                if !add {
                    iptables::forget(endpoint)?;
                }
                if self.run.join(ACTIVE).exists() {
                    self.install(ipv6, &leases, &exclusions)?;
                }
                Ok(())
            }
            Backend::Iptables => Ok(()),
        })();
        if let Err(err) = result {
            let journal = self.save_leases(&old);
            let kernel = (|| {
                if self.backend == Backend::Iptables && endpoint.uid.is_none() {
                    if add && !old.contains_key(&endpoint) {
                        iptables::forget(endpoint)?;
                    }
                    if self.run.join(ACTIVE).exists() {
                        let exclusions = optional(&self.run.join("dns-excl"))?.unwrap_or_default();
                        self.install(ipv6, &old, &exclusions)?;
                    }
                }
                Ok(())
            })();
            if let Err(rollback) = journal.and(kernel) {
                return Err(error(format!("DNS: {err}; откат: {rollback}")));
            }
            return Err(err);
        }
        Ok(())
    }

    fn restore_legacy_offload(&self) -> Result<()> {
        keenetic::restore_fastnat(self)?;
        if env::var("R2O_FLOWOFFLOAD_SKIP_RESTORE").as_deref() != Ok("1") {
            nft::restore_fw4(self)?;
        }
        Ok(())
    }
}

fn limit_health_error(error: &str) -> String {
    error.trim().chars().take(256).collect()
}

#[derive(Debug, PartialEq, Eq)]
struct QueueEvidence {
    peer: u32,
    kernel_drops: u64,
    user_drops: u64,
    sequence: u32,
}

fn sample_accounting(reader: impl BufRead) -> Result<(usize, usize, bool)> {
    const MAX_ENTRIES: usize = 256;
    let mut counted = 0;
    let mut missing = 0;
    for (index, line) in reader.lines().enumerate() {
        if index == MAX_ENTRIES {
            return Ok((counted, missing, true));
        }
        let line = line?;
        let fields = line.split_whitespace();
        // Both formats have a source field for each direction. Ignore non-flow rows.
        if fields.clone().filter(|f| f.starts_with("src=")).count() != 2 {
            continue;
        }
        let packets = fields
            .filter_map(|field| field.strip_prefix("packets="))
            .filter(|value| value.parse::<u64>().is_ok())
            .count();
        if packets == 2 {
            counted += 1;
        } else {
            missing += 1;
        }
    }
    Ok((counted, missing, false))
}

fn queue_evidence(text: &str, queue: u16) -> Option<QueueEvidence> {
    text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let number = fields.next()?.parse::<u16>().ok()?;
        let peer = fields.next()?.parse::<u32>().ok()?;
        let _queued = fields.next()?;
        let mode = fields.next()?;
        let range = fields.next()?.parse::<u32>().ok()?;
        let kernel_drops = fields.next()?.parse().ok()?;
        let user_drops = fields.next()?.parse().ok()?;
        let sequence = fields.next()?.parse().ok()?;
        (number == queue && peer != 0 && mode == "2" && range >= 64).then_some(QueueEvidence {
            peer,
            kernel_drops,
            user_drops,
            sequence,
        })
    })
}

fn uptime() -> Result<u64> {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_MONOTONIC доступен на Linux 3.4 и не зависит от коррекции часов.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timestamp) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(timestamp.tv_sec as u64 * 1000 + timestamp.tv_nsec as u64 / 1_000_000)
}

fn ttl(until: u64, now: u64) -> Option<u64> {
    // Округление вниз не продлевает действие привязки после rebuild.
    let seconds = until.saturating_sub(now) / 1000;
    (seconds != 0).then_some(seconds)
}

fn available(binary: &str) -> bool {
    env::var_os("PATH").is_some_and(|paths| {
        env::split_paths(&paths).any(|dir| {
            fs::metadata(dir.join(binary)).is_ok_and(|m| {
                use std::os::unix::fs::PermissionsExt;
                m.is_file() && m.permissions().mode() & 0o111 != 0
            })
        })
    })
}

fn command(binary: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    checked(binary, args, invoke(binary, args, input)?)
}

fn checked(binary: &str, args: &[&str], output: Output) -> Result<String> {
    if !output.status.success() {
        return Err(error(format!(
            "{binary} {}: {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout).map_err(|err| error(err.to_string()))
}

fn invoke(binary: &str, args: &[&str], input: Option<&str>) -> Result<Output> {
    invoke_before(binary, args, input, Instant::now() + Duration::from_secs(2))
}

fn invoke_before(
    binary: &str,
    args: &[&str],
    input: Option<&str>,
    deadline: Instant,
) -> Result<Output> {
    let mut command = Command::new(binary);
    if binary == "ndmc" {
        command
            .env_remove("LD_LIBRARY_PATH")
            .env_remove("LD_PRELOAD");
    }
    command
        .args(args)
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .process_group(0);
    let mut child = command.spawn()?;
    // На старых роутерах ndmc или resolver могут зависнуть после смены WAN.
    let done = std::sync::atomic::AtomicBool::new(false);
    let pid = child.id() as i32;
    std::thread::scope(|scope| {
        let timer = scope.spawn(|| {
            while !done.load(std::sync::atomic::Ordering::Acquire) {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    // У команды отдельная группа, включая детей, удерживающих pipe.
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                    break;
                }
                std::thread::park_timeout(remaining);
            }
        });
        let result = (|| {
            if let Some(input) = input
                && let Some(mut stdin) = child.stdin.take()
            {
                // Ошибка парсинга может закрыть stdin раньше, детали находятся в stderr.
                if let Err(err) = stdin.write_all(input.as_bytes())
                    && err.kind() != io::ErrorKind::BrokenPipe
                {
                    return Err(err);
                }
            }
            child.wait_with_output()
        })();
        done.store(true, std::sync::atomic::Ordering::Release);
        timer.thread().unpark();
        result
    })
}

pub fn cli(args: &[String]) -> Result<()> {
    let platform = Platform::detect()?;
    match args.first().map(String::as_str) {
        Some("backend") => println!(
            "{}",
            if platform.backend == Backend::Nft {
                "nft"
            } else {
                "iptables"
            }
        ),
        Some("ipv6-enabled") => {
            if platform.ipv6 && platform.backend == Backend::Iptables && !platform.use_ipv6() {
                platform.load_modules();
            }
            println!("{}", u8::from(platform.use_ipv6()));
        }
        Some("up") => platform.reconcile_reported(true, true)?,
        Some("down") => platform.down()?,
        Some("event" | "dns-ensure" | "flowoffload-ensure") => {
            let socket = UnixDatagram::unbound()?;
            match socket.send_to(b"event", platform.run.join(EVENT)) {
                Ok(_) => (),
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) && !platform.run.join(ACTIVE).exists() =>
                {
                    ()
                }
                Err(err) => return Err(err),
            }
        }
        Some("flowoffload-restore") => {
            let _lock = platform.lock()?;
            platform.restore_legacy_offload()?;
        }
        Some("rst-down") => {
            let _lock = platform.lock()?;
            if available("nft") {
                nft::down("r2o_rst")?;
            }
        }
        Some("status") => {
            let _lock = platform.lock()?;
            let ipv6 = platform.use_ipv6();
            platform.status(ipv6)?;
            println!(
                "firewall=installed nfqueue=bound conntrack_accounting=enabled lan_coverage=unverified"
            );
            match platform.accounting_sample() {
                Ok((counted, missing, bounded)) => println!(
                    "conntrack_entries=sampled with_counters={counted} without_full_counters={missing} bounded={bounded}"
                ),
                Err(err) => println!("conntrack_entries=unavailable ({err})"),
            }
            for version in [4, 6].into_iter().filter(|version| *version == 4 || ipv6) {
                let queue = platform.queue(version);
                let evidence = platform.queue_evidence(version)?;
                println!(
                    "ipv{version} queue={queue} peer={} sequence={} kernel_drops={} user_drops={} dns_uid={}",
                    evidence.peer,
                    evidence.sequence,
                    evidence.kernel_drops,
                    evidence.user_drops,
                    if platform.dns_uid_ready(version)? {
                        "socket_flag"
                    } else {
                        "unavailable"
                    }
                );
            }
            if platform.ipv6 {
                if ipv6 {
                    println!(
                        "ipv6=available policy_routing={}",
                        if linux::ipv6_policy(&platform.proc) {
                            "available"
                        } else {
                            "unconfirmed"
                        }
                    );
                } else {
                    println!("ipv6=unavailable");
                }
            }
            if platform.kind == Kind::Keenetic {
                keenetic::offload_status(&platform);
                if let Some(reason) = optional(&platform.run.join("platform.dns-excl-degraded"))? {
                    println!("dns_exclusions=degraded ({})", reason.trim());
                }
            } else if platform.kind == Kind::OpenWrt && platform.backend == Backend::Nft {
                match nft::admission_status(&platform, ipv6) {
                    Ok(status) => println!("fw4_admission={status}"),
                    Err(err) => return Err(err),
                }
            }
            if let Some(reason) = optional(&platform.run.join("platform.offload-error"))? {
                println!("offload=limited ({reason})");
            }
        }
        Some("dns-route") => platform.dns_route(&args[1..])?,
        Some("ppe") => match args.get(1).map(String::as_str) {
            Some("status") => keenetic::offload_status(&platform),
            Some("ensure") => platform.reconcile(false, false)?,
            Some("remove") => {
                let _lock = platform.lock()?;
                if platform.backend == Backend::Iptables {
                    iptables::clear_ppe()?;
                }
            }
            _ => return Err(error("ожидается ppe ensure|remove|status")),
        },
        _ => return Err(error("неизвестная операция firewall")),
    }
    Ok(())
}

pub struct Worker(UnixDatagram);

impl Worker {
    pub fn start(queue: u16, family: u16, owner: bool, port_id: u32) -> Result<Option<Self>> {
        if env::var("R2O_PLATFORM_RUNTIME").as_deref() != Ok("1") {
            return Ok(None);
        }
        let platform = Platform::detect()?;
        let version = if family == libc::AF_INET as u16 { 4 } else { 6 };
        if queue != platform.queue(version) {
            return Err(error("очередь платформы не соответствует очереди datapath"));
        }
        platform.setup_run()?;
        let capability = platform.run.join(format!("platform.uid.{queue}"));
        atomic(
            &capability,
            &if owner {
                port_id.to_string()
            } else {
                String::new()
            },
        )?;
        if version != 4 {
            if let Ok(sender) = UnixDatagram::unbound() {
                let _ = sender.send_to(b"event", platform.run.join(EVENT));
            }
            return Ok(None);
        }
        let path = platform.run.join(EVENT);
        remove(&path)?;
        let listener = UnixDatagram::bind(&path)?;
        let sender = UnixDatagram::unbound()?;
        sender.connect(&path)?;
        sender.set_nonblocking(true)?;
        std::thread::Builder::new()
            .name("r2o-platform".into())
            .stack_size(192 * 1024)
            .spawn(move || run_worker(&platform, &listener))?;
        Ok(Some(Self(sender)))
    }

    pub fn notify(&self) {
        let _ = self.0.send(b"event");
    }
}

// Адаптация Backoff::delay из nlink (Marc Pardo, MIT).
fn retry_delay(attempt: u32, interval: Duration) -> Duration {
    let factor = 2u32.saturating_pow(attempt.saturating_sub(1));
    Duration::from_secs(1)
        .saturating_mul(factor)
        .min(interval.min(Duration::from_secs(5)))
}

fn run_worker(platform: &Platform, listener: &UnixDatagram) {
    let mut bytes = [0; 32];
    let mut previous = None;
    let mut attempt = 0u32;
    loop {
        let delay = if attempt == 0 {
            platform.interval
        } else {
            retry_delay(attempt, platform.interval)
        };
        if listener.set_read_timeout(Some(delay)).is_err() {
            return;
        }
        match listener.recv(&mut bytes) {
            Ok(_) => {
                // NDM шлёт несколько событий за одну смену WAN. Ограничиваем задержку
                // даже при непрерывном потоке уведомлений.
                let deadline = Instant::now() + Duration::from_millis(400);
                while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                    if remaining.is_zero()
                        || listener.set_read_timeout(Some(remaining)).is_err()
                        || listener.recv(&mut bytes).is_err()
                    {
                        break;
                    }
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                ()
            }
            Err(err) => {
                eprintln!("r2o-platform: сокет событий: {err}");
                return;
            }
        }
        let current = platform
            .reconcile_reported(false, true)
            .err()
            .map(|err| err.to_string());
        attempt = if current.is_some() {
            attempt.saturating_add(1)
        } else {
            0
        };
        if current != previous {
            if let Some(err) = &current {
                eprintln!("r2o-platform: согласование firewall: {err}");
            } else {
                eprintln!("r2o-platform: состояние firewall восстановлено");
            }
            previous = current;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_conntrack_entries_created_without_accounting() {
        let tracked =
            "ipv4 2 tcp 6 100 ESTABLISHED src=192.0.2.2 packets=1 src=198.18.0.2 packets=0\n";
        let no_extension = "tcp 6 100 ESTABLISHED src=192.0.2.2 src=198.18.0.2\n";
        let mixed = format!("{tracked}{no_extension}header\n");
        assert_eq!(sample_accounting(mixed.as_bytes()).unwrap(), (1, 1, false));
        assert_eq!(
            sample_accounting(tracked.repeat(257).as_bytes()).unwrap(),
            (256, 0, true)
        );
    }

    #[test]
    fn retry_is_bounded() {
        assert_eq!(
            retry_delay(1, Duration::from_secs(60)),
            Duration::from_secs(1)
        );
        assert_eq!(
            retry_delay(3, Duration::from_secs(60)),
            Duration::from_secs(4)
        );
        assert_eq!(
            retry_delay(500, Duration::from_secs(60)),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn requires_a_peer_and_packet_copy() {
        assert_eq!(
            queue_evidence("2000 123 0 2 1600 4 5 95 1\n", 2000),
            Some(QueueEvidence {
                peer: 123,
                kernel_drops: 4,
                user_drops: 5,
                sequence: 95
            })
        );
        assert_eq!(queue_evidence("2000 0 0 2 1600 0 0 95 1\n", 2000), None);
        assert_eq!(queue_evidence("2000 123 0 1 1600 0 0 95 1\n", 2000), None);
        assert_eq!(queue_evidence("2001 123 0 2 1600 0 0 95 1\n", 2000), None);
    }

    #[test]
    fn endpoints_are_literal_and_lease_rebuild_never_extends_ttl() {
        assert!(Endpoint::targets("tcp://[2001:db8::1]:443 udp://192.0.2.1:853").is_ok());
        assert!(Endpoint::targets("tcp://192.0.2.1:443;").is_err());
        assert!(Endpoint::parse("192.0.2.1", "tcp", "443", Some("123")).is_err());
        assert_eq!(ttl(31_001, 21_002), Some(9));
        assert_eq!(ttl(31_001, 30_002), None);
    }
}
