//! Real DNS data-path verification. This module is appended to an unmodified
//! copy of the production adapter; only service discovery/signal IPC is injected.
use super::*;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::MetadataExt;
use std::process::Child;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

static NEXT_QUERY: AtomicUsize = AtomicUsize::new(1);

fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn query(port: u16, name: &str, qtype: u16, tcp: bool) -> Result<Vec<IpAddr>, String> {
    let id = NEXT_QUERY.fetch_add(1, Ordering::Relaxed) as u16;
    let mut packet = Vec::from(id.to_be_bytes());
    packet.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&[0, 1]);
    let bytes = if tcp {
        let address = format!("127.0.0.1:{port}").parse().unwrap();
        let mut socket =
            TcpStream::connect_timeout(&address, Duration::from_secs(1)).map_err(error)?;
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(error)?;
        socket
            .set_write_timeout(Some(Duration::from_secs(1)))
            .map_err(error)?;
        socket
            .write_all(&(packet.len() as u16).to_be_bytes())
            .map_err(error)?;
        socket.write_all(&packet).map_err(error)?;
        let mut size = [0; 2];
        socket.read_exact(&mut size).map_err(error)?;
        let mut bytes = vec![0; u16::from_be_bytes(size) as usize];
        socket.read_exact(&mut bytes).map_err(error)?;
        bytes
    } else {
        let socket = UdpSocket::bind("127.0.0.1:0").map_err(error)?;
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(error)?;
        socket.connect((Ipv4Addr::LOCALHOST, port)).map_err(error)?;
        socket.send(&packet).map_err(error)?;
        let mut bytes = vec![0; 4096];
        let size = socket.recv(&mut bytes).map_err(error)?;
        bytes.truncate(size);
        bytes
    };
    if bytes.len() < 12 || bytes[..2] != id.to_be_bytes() {
        return Err("invalid DNS response header".into());
    }
    if bytes[3] & 0x0f != 0 {
        return Err(format!("DNS rcode {}", bytes[3] & 0x0f));
    }
    fn skip_name(bytes: &[u8], offset: &mut usize) -> Result<(), String> {
        loop {
            let b = *bytes.get(*offset).ok_or("truncated DNS name")?;
            *offset += 1;
            if b & 0xc0 == 0xc0 {
                *offset += 1;
                return (*offset <= bytes.len())
                    .then_some(())
                    .ok_or("truncated DNS pointer".into());
            }
            if b == 0 {
                return Ok(());
            }
            if b > 63 {
                return Err("invalid DNS label".into());
            }
            *offset += b as usize;
            if *offset > bytes.len() {
                return Err("truncated DNS label".into());
            }
        }
    }
    let mut offset = 12;
    let questions = u16::from_be_bytes([bytes[4], bytes[5]]);
    for _ in 0..questions {
        skip_name(&bytes, &mut offset)?;
        offset += 4;
    }
    let answers = u16::from_be_bytes([bytes[6], bytes[7]]);
    let mut result = Vec::new();
    for _ in 0..answers {
        skip_name(&bytes, &mut offset)?;
        if offset + 10 > bytes.len() {
            return Err("truncated DNS answer".into());
        }
        let kind = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let length = u16::from_be_bytes([bytes[offset + 8], bytes[offset + 9]]) as usize;
        offset += 10;
        if offset + length > bytes.len() {
            return Err("truncated DNS data".into());
        }
        match (kind, length) {
            (1, 4) => result.push(IpAddr::V4(Ipv4Addr::new(
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ))),
            (28, 16) => result.push(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&bytes[offset..offset + 16]).unwrap(),
            ))),
            _ => {}
        }
        offset += length;
    }
    result.sort();
    Ok(result)
}

fn available_port() -> u16 {
    loop {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return port;
        }
    }
}

struct Daemon {
    child: Child,
    port: u16,
    instance: Instance,
    log: PathBuf,
    start: String,
}

fn process_start(pid: u32) -> String {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    stat.rsplit_once(") ")
        .unwrap()
        .1
        .split_ascii_whitespace()
        .nth(19)
        .unwrap()
        .to_owned()
}

impl Daemon {
    fn spawn(work: &Path, name: &str, extra: &str) -> Self {
        let port = available_port();
        let config = work.join(format!("{name}.conf"));
        let log = work.join(format!("{name}.log"));
        fs::write(&config, format!("port={port}\nlisten-address=127.0.0.1\nbind-interfaces\nno-hosts\nno-resolv\ncache-size=256\nlocal-ttl=0\n{extra}\n")).unwrap();
        let binary = std::env::var("DNSMASQ_BIN")
            .expect("DNSMASQ_BIN must point to an isolated test executable");
        let mut child = Command::new(binary)
            .arg("--no-daemon")
            .arg("-C")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        let pid = child.id();
        let start = process_start(pid);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut ready = false;
        while Instant::now() < deadline {
            assert!(
                child.try_wait().unwrap().is_none(),
                "dnsmasq exited: {}",
                fs::read_to_string(&log).unwrap()
            );
            if query(port, "ordinary.example", 1, false)
                .is_ok_and(|answer| answer == ["203.0.113.80".parse::<IpAddr>().unwrap()])
            {
                ready = true;
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        if !ready {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "dnsmasq did not answer its readiness query: {}",
                fs::read_to_string(&log).unwrap()
            );
        }
        Self {
            child,
            port,
            instance: Instance {
                name: name.into(),
                pid,
                config,
            },
            log,
            start,
        }
    }
    fn assert_unchanged(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "dnsmasq terminated"
        );
        assert_eq!(
            self.start,
            process_start(self.instance.pid),
            "dnsmasq identity changed"
        );
    }
    fn reload_count(&self, path: &Path) -> usize {
        let pattern = format!("read {} -", path.display());
        fs::read_to_string(&self.log)
            .unwrap()
            .lines()
            .filter(|line| line.contains(&pattern))
            .count()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.instance.pid as i32, libc::SIGTERM);
        }
        let _ = self.child.wait();
    }
}

struct HostRuntime {
    target: Instance,
    other: Instance,
    calls: usize,
    delivered: usize,
    snapshots: usize,
    fail_signals: usize,
    fail_snapshot: bool,
}

impl Runtime for HostRuntime {
    fn snapshot(&mut self) -> Result<Instances, String> {
        self.snapshots += 1;
        if self.fail_snapshot {
            return Err("injected service discovery outage".into());
        }
        for instance in [&self.target, &self.other] {
            if unsafe { libc::kill(instance.pid as i32, 0) } != 0 {
                return Err("isolated dnsmasq is gone".into());
            }
        }
        Ok(Instances {
            running: vec![self.target.clone(), self.other.clone()],
            eligible: vec![self.target.clone()],
        })
    }
    fn signal(&mut self, instance: &Instance) -> Result<(), String> {
        self.calls += 1;
        assert_eq!(
            instance, &self.target,
            "adapter tried to signal an unrelated dnsmasq"
        );
        if self.fail_signals > 0 {
            self.fail_signals -= 1;
            return Err("injected failure before SIGHUP delivery".into());
        }
        if unsafe { libc::kill(instance.pid as i32, libc::SIGHUP) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        self.delivered += 1;
        Ok(())
    }
}

fn pairs(index: usize) -> BTreeSet<PinPair> {
    BTreeSet::from([
        (
            "www.instagram.com".into(),
            format!("192.0.2.{}", index % 200 + 10),
        ),
        (
            "www.instagram.com".into(),
            format!("2001:db8::{:x}", index + 10),
        ),
    ])
}

fn assert_records(port: u16, desired: &BTreeSet<PinPair>) {
    for qtype in [1, 28] {
        let expected: Vec<IpAddr> = desired
            .iter()
            .map(|(_, ip)| ip.parse::<IpAddr>().unwrap())
            .filter(|ip| ip.is_ipv4() == (qtype == 1))
            .collect();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let answer = query(port, "www.instagram.com", qtype, false);
            if answer.as_ref().is_ok_and(|value| value == &expected) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "wanted {expected:?}, got {answer:?}"
            );
            thread::sleep(Duration::from_millis(2));
        }
    }
}

#[test]
fn real_dnsmasq_atomic_updates_preserve_normal_dns() {
    let dnsmasq_version = Command::new(std::env::var("DNSMASQ_BIN").unwrap())
        .arg("--version")
        .output()
        .unwrap();
    assert!(dnsmasq_version.status.success());
    let dnsmasq_version = String::from_utf8_lossy(&dnsmasq_version.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    let work =
        PathBuf::from(std::env::var("DNSMASQ_TEST_WORK").expect("DNSMASQ_TEST_WORK is required"));
    fs::create_dir_all(&work).unwrap();
    let directory = work.join("hosts");
    fs::create_dir(&directory).unwrap();
    let fixture = directory.join("fixture");
    fs::write(&fixture, "192.0.2.3 r2o-fixture.lan\n").unwrap();
    let upstream_hosts = work.join("upstream.hosts");
    fs::write(&upstream_hosts, "203.0.113.80 ordinary.example\n198.51.100.222 www.instagram.com\n2001:db8::feed www.instagram.com\n").unwrap();
    let mut upstream = Daemon::spawn(
        &work,
        "isolated_upstream",
        &format!(
            "addn-hosts={}\naddress=/ordinary.example/203.0.113.80",
            upstream_hosts.display()
        ),
    );
    let mut target = Daemon::spawn(
        &work,
        "isolated_target",
        &format!(
            "addn-hosts={}\nserver=127.0.0.1#{}",
            directory.display(),
            upstream.port
        ),
    );
    let hosts = DnsmasqHosts {
        path: directory.join("r2o-meta"),
    };
    let mut runtime = HostRuntime {
        target: target.instance.clone(),
        other: upstream.instance.clone(),
        calls: 0,
        delivered: 0,
        snapshots: 0,
        fail_signals: 0,
        fail_snapshot: false,
    };
    assert_eq!(
        query(target.port, "ordinary.example", 1, false).unwrap(),
        vec!["203.0.113.80".parse::<IpAddr>().unwrap()]
    );
    let upstream_reloads = upstream.reload_count(&upstream_hosts);

    // A process killed before rename leaves this partial hidden file. It must
    // never become an addn-hosts record, including during every following HUP.
    fs::write(
        hosts.test_staging_path(),
        "203.0.113.111 www.instagram.com\n203.0.113.112 r2o-fixture.lan\n",
    )
    .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let udp_count = Arc::new(AtomicUsize::new(0));
    let tcp_count = Arc::new(AtomicUsize::new(0));
    let failures = Arc::new(Mutex::new(Vec::new()));
    let mut workers = Vec::new();
    for worker in 0..4 {
        let (stop, udp_count, tcp_count, failures) = (
            stop.clone(),
            udp_count.clone(),
            tcp_count.clone(),
            failures.clone(),
        );
        let port = target.port;
        workers.push(thread::spawn(move || {
            let mut index = 0;
            while !stop.load(Ordering::Relaxed) {
                let tcp = index % 20 == 0;
                let name = if index % 2 == 0 {
                    format!("n{worker}-{index}.ordinary.example")
                } else {
                    "r2o-fixture.lan".into()
                };
                let expected = if index % 2 == 0 {
                    "203.0.113.80"
                } else {
                    "192.0.2.3"
                }
                .parse::<IpAddr>()
                .unwrap();
                let result = query(port, &name, 1, tcp);
                if !result.as_ref().is_ok_and(|answer| answer == &[expected]) {
                    let mut errors = failures.lock().unwrap();
                    if errors.len() < 20 {
                        errors.push(format!("{name} tcp={tcp}: {result:?}"));
                    }
                }
                if tcp {
                    tcp_count.fetch_add(1, Ordering::Relaxed);
                } else {
                    udp_count.fetch_add(1, Ordering::Relaxed);
                }
                index += 1;
                thread::sleep(Duration::from_micros(500));
            }
        }));
    }
    let started = Instant::now();
    let mut samples = Vec::new();
    for index in 0..250 {
        let desired = pairs(index);
        let old_inode = fs::metadata(&hosts.path).ok().map(|m| m.ino());
        let before = runtime.delivered;
        let update_started = Instant::now();
        hosts
            .publish_with(&desired, 1000 + index as u64, &mut runtime)
            .unwrap();
        assert_eq!(
            runtime.delivered,
            before + 1,
            "a batch must issue exactly one target HUP"
        );
        assert!(!hosts.notification_pending());
        let new_inode = fs::metadata(&hosts.path).unwrap().ino();
        assert_ne!(
            old_inode,
            Some(new_inode),
            "changed file was not atomically replaced"
        );
        assert_records(target.port, &desired);
        samples.push(update_started.elapsed().as_micros());
        let reload_count = target.reload_count(&hosts.path);
        let snapshot_count = runtime.snapshots;
        hosts
            .publish_with(&desired, 1000 + index as u64, &mut runtime)
            .unwrap();
        assert_eq!(
            runtime.delivered,
            before + 1,
            "identical contents caused another HUP"
        );
        assert_eq!(
            runtime.snapshots, snapshot_count,
            "idle identical contents retried backend discovery"
        );
        assert_eq!(fs::metadata(&hosts.path).unwrap().ino(), new_inode);
        assert_eq!(target.reload_count(&hosts.path), reload_count);
        target.assert_unchanged();
        thread::sleep(Duration::from_millis(5));
    }

    // Invalid new input and unavailable service inspection preserve the last
    // published generation and do not send a signal.
    let previous = fs::read(&hosts.path).unwrap();
    let delivered = runtime.delivered;
    assert!(
        hosts
            .publish_with(
                &BTreeSet::from([("example.org".into(), "192.0.2.8".into())]),
                2000,
                &mut runtime
            )
            .is_err()
    );
    runtime.fail_snapshot = true;
    assert!(hosts.publish_with(&pairs(300), 2001, &mut runtime).is_err());
    runtime.fail_snapshot = false;
    assert_eq!(previous, fs::read(&hosts.path).unwrap());
    assert_eq!(delivered, runtime.delivered);
    assert_records(target.port, &pairs(249));

    // Failed delivery persists pending state. A fresh adapter instance respects
    // the saved backoff and recovers with one HUP after the retry boundary.
    runtime.fail_signals = 1;
    assert!(hosts.publish_with(&pairs(301), 3000, &mut runtime).is_err());
    assert!(hosts.notification_pending());
    assert_records(target.port, &pairs(249));
    let recovered = DnsmasqHosts {
        path: hosts.path.clone(),
    };
    let calls = runtime.calls;
    assert!(recovered.resume_with(3001, &mut runtime).is_err());
    assert!(recovered.resume_with(3059, &mut runtime).is_err());
    assert_eq!(
        runtime.calls, calls,
        "persisted backoff did not stop repeated signals"
    );
    recovered.resume_with(3060, &mut runtime).unwrap();
    assert_eq!(runtime.calls, calls + 1);
    assert!(!recovered.notification_pending());
    assert_records(target.port, &pairs(301));

    // Model the on-disk boundary after atomic rename but before signal IPC.
    let desired = pairs(302);
    let mut body = format!("{HEADER}\n");
    for (host, ip) in &desired {
        body.push_str(&format!("{ip} {host}\n"));
    }
    recovered.prepare_notification(&body, false).unwrap();
    write_hosts(&recovered.path, body.as_bytes()).unwrap();
    assert_records(target.port, &pairs(301));
    let restarted_writer = DnsmasqHosts {
        path: recovered.path.clone(),
    };
    restarted_writer.resume_with(3100, &mut runtime).unwrap();
    assert_records(target.port, &desired);

    // A user disabling protection must remove overrides even while an earlier
    // failed update is backed off. Normal upstream data then becomes visible.
    runtime.fail_signals = 1;
    assert!(
        restarted_writer
            .publish_with(&pairs(303), 4000, &mut runtime)
            .is_err()
    );
    restarted_writer
        .publish_with(&BTreeSet::new(), 4001, &mut runtime)
        .unwrap();
    let fallback = BTreeSet::from([
        ("www.instagram.com".into(), "198.51.100.222".into()),
        ("www.instagram.com".into(), "2001:db8::feed".into()),
    ]);
    assert_records(target.port, &fallback);
    assert!(restarted_writer.records().unwrap().is_empty());
    let calls = runtime.calls;
    restarted_writer
        .publish_with(&BTreeSet::new(), 4002, &mut runtime)
        .unwrap();
    assert_eq!(runtime.calls, calls);
    thread::sleep(Duration::from_millis(100));
    stop.store(true, Ordering::Relaxed);
    for worker in workers {
        worker.join().unwrap();
    }
    let failures = failures.lock().unwrap().clone();
    assert!(failures.is_empty(), "ordinary DNS failures: {failures:?}");
    target.assert_unchanged();
    upstream.assert_unchanged();
    assert_eq!(
        upstream.reload_count(&upstream_hosts),
        upstream_reloads,
        "unrelated dnsmasq was reloaded"
    );
    assert_eq!(
        target.reload_count(&hosts.path),
        runtime.delivered,
        "actual dnsmasq read log and delivered HUP count differ"
    );
    samples.sort_unstable();
    let metrics = json!({
        "dnsmasq_version": dnsmasq_version,
        "changed_publications": 250,
        "identical_publications": 251,
        "primary_cycle_A_AAAA_assertions": 500,
        "normal_udp_queries": udp_count.load(Ordering::Relaxed),
        "normal_tcp_queries": tcp_count.load(Ordering::Relaxed),
        "normal_dns_failures": 0,
        "target_pid": target.instance.pid,
        "upstream_pid": upstream.instance.pid,
        "pid_changes": 0,
        "delivered_HUP": runtime.delivered,
        "injected_signal_failures": 2,
        "unrelated_HUP": 0,
        "publication_p50_us": samples[124],
        "publication_p95_us": samples[237],
        "publication_p99_us": samples[247],
        "elapsed_ms": started.elapsed().as_millis(),
        "environment": std::env::var("R2O_DNSMASQ_TEST_ENV").unwrap_or_else(|_| "native host".into()),
        "scope": "real dnsmasq process integration; Runtime IPC injected; OpenWrt procd/ujail is not exercised"
    });
    println!("{}", serde_json::to_string_pretty(&metrics).unwrap());
    fs::write(
        work.join("result.json"),
        serde_json::to_vec_pretty(&metrics).unwrap(),
    )
    .unwrap();
}
