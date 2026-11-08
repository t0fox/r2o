use std::collections::HashMap;
use std::ffi::CString;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Mutex as AsyncMutex;

use crate::default_domains::http::{
    build_doh_tls_config, https_post_h2_with_tls_config, https_post_with_tls_config_timeout,
};
use crate::default_domains::valid_domain;
use crate::outbound::OutboundConnector;

/// C `TG_ROUTE_DOH_TIMEOUT_MS`: deadline одного DoH-запроса.
const DOH_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
/// Верхняя граница всего DoH-этапа: 4 endpoint × (A + AAAA) × 2 c.
const DOH_TOTAL_TIMEOUT: Duration = Duration::from_secs(16);
const CF_DNS_TIMEOUT: Duration = Duration::from_millis(500);
const CF_DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const MAX_CF_DNS_CACHE_ENTRIES: usize = 256;
type CachedCfIpLists = HashMap<String, (Vec<IpAddr>, Instant)>;
type CfDomainLocks = HashMap<String, Arc<AsyncMutex<()>>>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum SystemDnsLookup {
    Addresses(Vec<IpAddr>),
    Negative,
    Failed,
}

/// Один DoH endpoint D2O `route_dns.c` (порядок и транспорт важны).
struct DohEndpoint {
    host: &'static str,
    ip: &'static str,
    http2: bool,
}

const DOH_ENDPOINTS: &[DohEndpoint] = &[
    DohEndpoint {
        host: "d.webshiftvpn.ru",
        ip: "31.31.207.68",
        http2: true,
    },
    DohEndpoint {
        host: "cloudflare-dns.com",
        ip: "1.1.1.1",
        http2: false,
    },
    DohEndpoint {
        host: "dns.google",
        ip: "8.8.8.8",
        http2: false,
    },
    DohEndpoint {
        host: "dns.sb",
        ip: "185.222.222.222",
        http2: true,
    },
];

/// TLS-профили DoH: отдельный для h1 (без ALPN) и h2 (ALPN h2), как C.
pub(crate) struct DohTls {
    pub(crate) h1: Arc<rustls::ClientConfig>,
    pub(crate) h2: Arc<rustls::ClientConfig>,
}

static DOH_TLS_CACHE: LazyLock<Mutex<HashMap<Option<PathBuf>, Result<Arc<DohTls>, String>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn doh_tls(ca_bundle: Option<&Path>) -> Result<Arc<DohTls>, String> {
    let key = ca_bundle.map(Path::to_path_buf);
    let mut cache = DOH_TLS_CACHE.lock().expect("кэш TLS DoH повреждён");
    if let Some(cached) = cache.get(&key) {
        return cached.clone();
    }
    if cache.len() >= 8 {
        cache.clear();
    }
    let built = (|| {
        Ok::<_, String>(Arc::new(DohTls {
            h1: build_doh_tls_config(key.as_deref(), false)?,
            h2: build_doh_tls_config(key.as_deref(), true)?,
        }))
    })();
    cache.insert(key, built.clone());
    built
}

static CF_IP_LIST_CACHE: LazyLock<Mutex<CachedCfIpLists>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static CF_IP_LOCKS: LazyLock<Mutex<CfDomainLocks>> = LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
fn clear_cf_ip(domain: &str) {
    CF_IP_LIST_CACHE
        .lock()
        .expect("повреждена блокировка кэша списка DNS Cloudflare")
        .remove(domain);
}

/// Получить ограниченный набор IPv4/IPv6 адресов CF/Worker домена.
/// Системный DNS пробуется первым, DoH используется только как резерв.
pub(crate) async fn resolve_cf_ips(
    domain: &str,
    outbound: &OutboundConnector,
    ca_bundle: Option<&Path>,
) -> Result<Vec<IpAddr>, String> {
    let system_domain = domain.to_string();
    let doh_domain = domain.to_string();
    // Как C: при недоступном CA/TLS DoH просто не используется, а системный
    // DNS остаётся рабочим путём.
    let tls = doh_tls(ca_bundle).ok();
    resolve_cf_ips_with_status(
        domain,
        move || async move { system_dns_lookup(system_domain).await },
        move || async move {
            let tls = tls?;
            resolve_doh_ips(&doh_domain, outbound, &tls).await
        },
    )
    .await
    .ok_or_else(|| format!("не удалось разрешить CF-хост {domain} через системный DNS и DoH"))
}

#[cfg(test)]
async fn resolve_cf_ips_with<S, SFut, D, DFut>(
    domain: &str,
    system_lookup: S,
    doh_lookup: D,
) -> Option<Vec<IpAddr>>
where
    S: FnOnce() -> SFut,
    SFut: Future<Output = Option<Vec<IpAddr>>>,
    D: FnOnce() -> DFut,
    DFut: Future<Output = Option<Vec<IpAddr>>>,
{
    resolve_cf_ips_with_status(
        domain,
        move || async move {
            system_lookup()
                .await
                .map(SystemDnsLookup::Addresses)
                .unwrap_or(SystemDnsLookup::Failed)
        },
        doh_lookup,
    )
    .await
}

async fn resolve_cf_ips_with_status<S, SFut, D, DFut>(
    domain: &str,
    system_lookup: S,
    doh_lookup: D,
) -> Option<Vec<IpAddr>>
where
    S: FnOnce() -> SFut,
    SFut: Future<Output = SystemDnsLookup>,
    D: FnOnce() -> DFut,
    DFut: Future<Output = Option<Vec<IpAddr>>>,
{
    resolve_cf_ips_with_status_and_timeouts(
        domain,
        system_lookup,
        doh_lookup,
        CF_DNS_TIMEOUT,
        DOH_TOTAL_TIMEOUT,
    )
    .await
}

#[cfg(test)]
async fn resolve_cf_ips_with_timeouts<S, SFut, D, DFut>(
    domain: &str,
    system_lookup: S,
    doh_lookup: D,
    system_timeout: Duration,
    doh_timeout: Duration,
) -> Option<Vec<IpAddr>>
where
    S: FnOnce() -> SFut,
    SFut: Future<Output = Option<Vec<IpAddr>>>,
    D: FnOnce() -> DFut,
    DFut: Future<Output = Option<Vec<IpAddr>>>,
{
    resolve_cf_ips_with_status_and_timeouts(
        domain,
        move || async move {
            system_lookup()
                .await
                .map(SystemDnsLookup::Addresses)
                .unwrap_or(SystemDnsLookup::Failed)
        },
        doh_lookup,
        system_timeout,
        doh_timeout,
    )
    .await
}

async fn resolve_cf_ips_with_status_and_timeouts<S, SFut, D, DFut>(
    domain: &str,
    system_lookup: S,
    doh_lookup: D,
    system_timeout: Duration,
    doh_timeout: Duration,
) -> Option<Vec<IpAddr>>
where
    S: FnOnce() -> SFut,
    SFut: Future<Output = SystemDnsLookup>,
    D: FnOnce() -> DFut,
    DFut: Future<Output = Option<Vec<IpAddr>>>,
{
    if !valid_domain(domain) {
        return None;
    }
    if let Some(ips) = cached_cf_ips(domain) {
        return Some(ips);
    }
    let domain_lock = domain_resolution_lock(domain);
    let _single_flight = domain_lock.lock().await;
    if let Some(ips) = cached_cf_ips(domain) {
        return Some(ips);
    }

    let mut ips = match tokio::time::timeout(system_timeout, system_lookup()).await {
        Ok(SystemDnsLookup::Addresses(addresses)) => addresses,
        Ok(SystemDnsLookup::Negative) => return None,
        Ok(SystemDnsLookup::Failed) | Err(_) => Vec::new(),
    };
    ips.retain(is_usable_edge_ip);
    if ips.is_empty() {
        ips = tokio::time::timeout(doh_timeout, doh_lookup())
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        ips.retain(is_usable_edge_ip);
    }
    ips.sort_by_key(|ip| match ip {
        IpAddr::V4(_) => 0,
        IpAddr::V6(_) => 1,
    });
    ips.dedup();
    ips.truncate(8);
    if ips.is_empty() {
        return None;
    }
    cache_cf_ips(domain, ips.clone(), CF_DNS_CACHE_TTL);
    Some(ips)
}

async fn system_dns_lookup(domain: String) -> SystemDnsLookup {
    tokio::task::spawn_blocking(move || system_dns_lookup_blocking(&domain))
        .await
        .unwrap_or(SystemDnsLookup::Failed)
}

fn system_dns_lookup_blocking(domain: &str) -> SystemDnsLookup {
    let Ok(domain) = CString::new(domain) else {
        return SystemDnsLookup::Failed;
    };
    let service = c"443";
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_UNSPEC;
    hints.ai_socktype = libc::SOCK_STREAM;
    hints.ai_protocol = libc::IPPROTO_TCP;
    let mut results = ptr::null_mut();
    let status =
        unsafe { libc::getaddrinfo(domain.as_ptr(), service.as_ptr(), &hints, &mut results) };
    if status != 0 {
        return system_dns_error_result(status);
    }

    let mut addresses = Vec::new();
    let mut current = results;
    while !current.is_null() {
        let item = unsafe { &*current };
        if !item.ai_addr.is_null() {
            if item.ai_family == libc::AF_INET
                && item.ai_addrlen >= std::mem::size_of::<libc::sockaddr_in>() as _
            {
                let address = unsafe { &*(item.ai_addr.cast::<libc::sockaddr_in>()) };
                addresses.push(IpAddr::V4(Ipv4Addr::from(
                    address.sin_addr.s_addr.to_ne_bytes(),
                )));
            } else if item.ai_family == libc::AF_INET6
                && item.ai_addrlen >= std::mem::size_of::<libc::sockaddr_in6>() as _
            {
                let address = unsafe { &*(item.ai_addr.cast::<libc::sockaddr_in6>()) };
                addresses.push(IpAddr::V6(std::net::Ipv6Addr::from(
                    address.sin6_addr.s6_addr,
                )));
            }
        }
        current = item.ai_next;
    }
    unsafe { libc::freeaddrinfo(results) };
    SystemDnsLookup::Addresses(addresses)
}

fn system_dns_error_result(status: libc::c_int) -> SystemDnsLookup {
    if status == libc::EAI_NONAME || status == libc::EAI_NODATA {
        SystemDnsLookup::Negative
    } else {
        SystemDnsLookup::Failed
    }
}

fn domain_resolution_lock(domain: &str) -> Arc<AsyncMutex<()>> {
    let mut locks = CF_IP_LOCKS
        .lock()
        .expect("повреждена блокировка списка DNS Cloudflare");
    retain_active_domain_locks(&mut locks);
    if let Some(lock) = locks.get(domain) {
        return Arc::clone(lock);
    }
    let lock = Arc::new(AsyncMutex::new(()));
    if locks.len() < MAX_CF_DNS_CACHE_ENTRIES {
        locks.insert(domain.to_string(), Arc::clone(&lock));
    }
    lock
}

fn retain_active_domain_locks(locks: &mut CfDomainLocks) {
    locks.retain(|_, lock| Arc::strong_count(lock) > 1);
}

fn cached_cf_ips(domain: &str) -> Option<Vec<IpAddr>> {
    let mut cache = CF_IP_LIST_CACHE
        .lock()
        .expect("повреждена блокировка кэша списка DNS Cloudflare");
    cache.retain(|_, (_, expires_at)| Instant::now() < *expires_at);
    cache.get(domain).map(|(ips, _)| ips.clone())
}

fn cache_cf_ips(domain: &str, ips: Vec<IpAddr>, ttl: Duration) {
    let mut cache = CF_IP_LIST_CACHE
        .lock()
        .expect("повреждена блокировка кэша списка DNS Cloudflare");
    cache.retain(|_, (_, expires_at)| Instant::now() < *expires_at);
    while cache.len() >= MAX_CF_DNS_CACHE_ENTRIES && !cache.contains_key(domain) {
        let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, (_, expires_at))| *expires_at)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        cache.remove(&oldest);
    }
    cache.insert(domain.to_string(), (ips, Instant::now() + ttl));
}

pub(crate) fn is_usable_edge_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ipv4_public(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return ipv4_public(&mapped);
            }
            let octets = ip.octets();
            (octets[0] & 0xe0) == 0x20
                && !(octets[0] == 0x20 && octets[1] == 0x01 && octets[2] <= 0x01)
                && !(octets[0] == 0x20 && octets[1] == 0x02)
                && !(octets[0] == 0x20
                    && octets[1] == 0x01
                    && octets[2] == 0x0d
                    && octets[3] == 0xb8)
        }
    }
}

fn ipv4_public(ip: &Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    a != 0
        && a != 10
        && a != 127
        && a < 224
        && !(a == 100 && (b & 0xc0) == 0x40)
        && !(a == 169 && b == 254)
        && !(a == 172 && (16..=31).contains(&b))
        && !(a == 192 && b == 168)
        && !(a == 192 && b == 0 && c == 0)
        && !(a == 192 && b == 0 && c == 2)
        && !(a == 192 && b == 88 && c == 99)
        && !(a == 198 && (b == 18 || b == 19))
        && !(a == 198 && b == 51 && c == 100)
        && !(a == 203 && b == 0 && c == 113)
}

/// C `doh_query_endpoint`: POST DNS-wire на IP endpoint с SNI/Host хоста.
async fn query_endpoint(
    tls: &DohTls,
    endpoint: &DohEndpoint,
    domain: &str,
    qtype: u16,
    outbound: &OutboundConnector,
) -> Result<Vec<IpAddr>, String> {
    let query_id: u16 = rand::random();
    let query = crate::doh_wire::encode_question(domain, qtype, query_id)?;
    let body = if endpoint.http2 {
        https_post_h2_with_tls_config(
            endpoint.ip,
            endpoint.host,
            "/dns-query",
            &[],
            "application/dns-message",
            &query,
            outbound,
            Arc::clone(&tls.h2),
            DOH_REQUEST_TIMEOUT,
        )
        .await?
    } else {
        https_post_with_tls_config_timeout(
            endpoint.ip,
            endpoint.host,
            "/dns-query",
            &[],
            "application/dns-message",
            &query,
            outbound,
            Arc::clone(&tls.h1),
            DOH_REQUEST_TIMEOUT,
        )
        .await?
    };
    crate::doh_wire::parse_response(&body, query_id)
}

/// Проверить CA bundle до старта, как C `tg_tls_client_context` в main.c:
/// при явно заданном, но нечитаемом/пустом файле запуск прекращается.
pub fn validate_doh_ca_bundle(path: &Path) -> Result<(), String> {
    doh_tls(Some(path)).map(|_| ())
}

/// DoH-only разрешение (production `doh_lookup`) для диагностики и
/// differential-проверок транспорта. Системный DNS не используется.
pub async fn resolve_cf_ips_via_doh(
    domain: &str,
    outbound: &OutboundConnector,
    ca_bundle: Option<&Path>,
) -> Result<Vec<IpAddr>, String> {
    let tls = doh_tls(ca_bundle)?;
    resolve_doh_ips(domain, outbound, &tls)
        .await
        .ok_or_else(|| format!("DoH не вернул публичных адресов для {domain}"))
}

/// C `doh_lookup`: endpoint по порядку, внутри A затем AAAA, первый
/// endpoint с публичными адресами выигрывает.
pub(crate) async fn resolve_doh_ips(
    domain: &str,
    outbound: &OutboundConnector,
    tls: &DohTls,
) -> Option<Vec<IpAddr>> {
    let domain = domain.trim();
    if !valid_domain(domain) {
        return None;
    }
    let mut addresses = Vec::new();
    for endpoint in DOH_ENDPOINTS {
        for qtype in [1u16, 28u16] {
            let Ok(found) = query_endpoint(tls, endpoint, domain, qtype, outbound).await else {
                continue;
            };
            for address in found {
                if !addresses.contains(&address) && addresses.len() < crate::doh_wire::MAX_ADDRESSES
                {
                    addresses.push(address);
                }
            }
        }
        if !addresses.is_empty() {
            return Some(addresses);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use super::{
        CfDomainLocks, SystemDnsLookup, cache_cf_ips, cached_cf_ips, clear_cf_ip,
        is_usable_edge_ip, resolve_cf_ips_with, resolve_cf_ips_with_status,
        resolve_cf_ips_with_timeouts, retain_active_domain_locks, system_dns_error_result,
    };

    #[test]
    fn doh_ca_bundle_validation_matches_c_startup() {
        let missing = std::env::temp_dir().join("r2o-tg14-missing-ca.pem");
        let _ = std::fs::remove_file(&missing);
        assert!(super::validate_doh_ca_bundle(&missing).is_err());

        let params = rcgen::CertificateParams::new(Vec::new());
        let ca = rcgen::Certificate::from_params(params).unwrap();
        let path = std::env::temp_dir().join(format!(
            "r2o-tg14-ca-{}-{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, ca.serialize_pem().unwrap()).unwrap();
        assert!(super::validate_doh_ca_bundle(&path).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn doh_endpoint_order_and_transport_match_d2o() {
        // Зафиксированный порядок и h1/h2 из C `doh_endpoints`.
        assert_eq!(
            super::DOH_ENDPOINTS
                .iter()
                .map(|endpoint| (endpoint.host, endpoint.ip, endpoint.http2))
                .collect::<Vec<_>>(),
            [
                ("d.webshiftvpn.ru", "31.31.207.68", true),
                ("cloudflare-dns.com", "1.1.1.1", false),
                ("dns.google", "8.8.8.8", false),
                ("dns.sb", "185.222.222.222", true),
            ]
        );
        assert_eq!(super::DOH_REQUEST_TIMEOUT, Duration::from_secs(2));
        assert_eq!(super::DOH_TOTAL_TIMEOUT, Duration::from_secs(16));
    }

    #[tokio::test]
    async fn d2o_route_dns_public_ip_filter_matches_shared_vectors() {
        let mut output = String::new();
        for line in include_str!("../tests/fixtures/d2o_route_dns_public_ips.tsv").lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let name = fields.next().expect("имя fixture");
            let address = fields
                .next()
                .expect("адрес fixture")
                .parse::<IpAddr>()
                .expect("IP fixture");
            let expected = fields.next().expect("ожидание fixture") == "1";
            assert!(fields.next().is_none(), "лишнее поле в fixture {name}");

            let actual = is_usable_edge_ip(&address);
            assert_eq!(actual, expected, "{name}: {address}");
            use std::fmt::Write as _;
            writeln!(&mut output, "{name}={}", u8::from(actual)).unwrap();
        }

        let negative_domain = "kws2.negative-system-dns.example";
        clear_cf_ip(negative_domain);
        assert_eq!(
            system_dns_error_result(libc::EAI_NONAME),
            SystemDnsLookup::Negative
        );
        assert_eq!(
            system_dns_error_result(libc::EAI_NODATA),
            SystemDnsLookup::Negative
        );
        let negative_doh_calls = Arc::new(AtomicUsize::new(0));
        let negative_doh_calls_for_lookup = Arc::clone(&negative_doh_calls);
        let negative = resolve_cf_ips_with_status(
            negative_domain,
            || async { system_dns_error_result(libc::EAI_NONAME) },
            move || async move {
                negative_doh_calls_for_lookup.fetch_add(1, Ordering::Relaxed);
                Some(vec!["188.114.97.1".parse().unwrap()])
            },
        )
        .await;
        assert!(negative.is_none());
        assert_eq!(negative_doh_calls.load(Ordering::Relaxed), 0);
        output.push_str("system-negative=skip\n");

        let transient_domain = "kws2.transient-system-dns.example";
        clear_cf_ip(transient_domain);
        assert_eq!(
            system_dns_error_result(libc::EAI_AGAIN),
            SystemDnsLookup::Failed
        );
        let transient_doh_calls = Arc::new(AtomicUsize::new(0));
        let transient_doh_calls_for_lookup = Arc::clone(&transient_doh_calls);
        let transient = resolve_cf_ips_with_status(
            transient_domain,
            || async { system_dns_error_result(libc::EAI_AGAIN) },
            move || async move {
                transient_doh_calls_for_lookup.fetch_add(1, Ordering::Relaxed);
                Some(vec!["188.114.97.1".parse().unwrap()])
            },
        )
        .await;
        assert_eq!(
            transient,
            Some(vec!["188.114.97.1".parse::<IpAddr>().unwrap()])
        );
        assert_eq!(transient_doh_calls.load(Ordering::Relaxed), 1);
        output.push_str("system-transient=fallback\n");

        if let Some(path) = std::env::var_os("R2O_TELEGRAM_ROUTE_DNS_DIFF_OUTPUT") {
            std::fs::write(path, output).expect("записать C/Rust route-DNS результат");
        }
    }

    #[tokio::test]
    async fn doh_отклоняет_некорректное_имя_до_сетевого_запроса() {
        let result = resolve_cf_ips_with(
            "edge.example?name=evil",
            || async {
                panic!("некорректное имя не должно вызывать системный DNS")
            },
            || async {
                panic!("некорректное имя не должно вызывать DoH")
            },
        )
        .await;
        assert!(result.is_none());
    }

    #[test]
    fn cf_dns_cache_хранит_список_адресов_и_очищается() {
        let domain = "kws2.cache-check.example";
        let addresses = [
            "188.114.97.1".parse().unwrap(),
            "2606:4700::1".parse().unwrap(),
        ];
        cache_cf_ips(domain, addresses.to_vec(), Duration::from_secs(60));

        assert_eq!(cached_cf_ips(domain), Some(addresses.to_vec()));

        clear_cf_ip(domain);
        assert!(cached_cf_ips(domain).is_none());
    }

    #[tokio::test]
    async fn cf_dns_сохраняет_несколько_системных_адресов_и_не_вызывает_doh() {
        let domain = "kws2.system-dns.example";
        let doh_calls = Arc::new(AtomicUsize::new(0));
        let doh_calls_for_lookup = Arc::clone(&doh_calls);

        let result = resolve_cf_ips_with(
            domain,
            || async {
                Some(vec![
                    "2606:4700:4700::1111".parse().unwrap(),
                    "104.21.75.42".parse().unwrap(),
                    "127.0.0.1".parse().unwrap(),
                    "104.21.75.42".parse().unwrap(),
                ])
            },
            move || async move {
                doh_calls_for_lookup.fetch_add(1, Ordering::Relaxed);
                Some(vec!["188.114.97.1".parse().unwrap()])
            },
        )
        .await;

        assert_eq!(
            result.unwrap(),
            [
                "104.21.75.42".parse::<IpAddr>().unwrap(),
                "2606:4700:4700::1111".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(doh_calls.load(Ordering::Relaxed), 0);
        clear_cf_ip(domain);
    }

    #[tokio::test]
    async fn cf_dns_переходит_на_doh_если_системные_адреса_непригодны() {
        let domain = "kws2.doh-fallback.example";
        clear_cf_ip(domain);
        let system_calls = Arc::new(AtomicUsize::new(0));
        let doh_calls = Arc::new(AtomicUsize::new(0));
        let system_calls_for_lookup = Arc::clone(&system_calls);
        let doh_calls_for_lookup = Arc::clone(&doh_calls);

        let result = resolve_cf_ips_with(
            domain,
            move || async move {
                system_calls_for_lookup.fetch_add(1, Ordering::Relaxed);
                Some(vec!["10.0.0.8".parse().unwrap()])
            },
            move || async move {
                doh_calls_for_lookup.fetch_add(1, Ordering::Relaxed);
                Some(vec!["188.114.97.1".parse().unwrap()])
            },
        )
        .await;

        assert_eq!(result.unwrap(), ["188.114.97.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(system_calls.load(Ordering::Relaxed), 1);
        assert_eq!(doh_calls.load(Ordering::Relaxed), 1);
        clear_cf_ip(domain);
    }

    #[tokio::test]
    async fn cf_dns_timeout_системного_resolver_переходит_на_doh() {
        let domain = "kws2.timeout-fallback.example";
        clear_cf_ip(domain);
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            resolve_cf_ips_with_timeouts(
                domain,
                || async { std::future::pending::<Option<Vec<IpAddr>>>().await },
                || async { Some(vec!["188.114.97.1".parse().unwrap()]) },
                Duration::from_millis(10),
                Duration::from_millis(50),
            ),
        )
        .await
        .expect("тайм-аут DNS не должен блокировать резервный DoH");

        assert_eq!(result, Some(vec!["188.114.97.1".parse().unwrap()]));
        clear_cf_ip(domain);
    }

    #[tokio::test]
    async fn cf_dns_после_истечения_ttl_заменяет_устаревший_ip() {
        let domain = "kws2.changed-edge.example";
        clear_cf_ip(domain);
        let old_ip = "188.114.97.1".parse().unwrap();
        let new_ip = "188.114.97.2".parse().unwrap();
        cache_cf_ips(domain, vec![old_ip], Duration::from_millis(1));
        tokio::time::sleep(Duration::from_millis(5)).await;

        let result = resolve_cf_ips_with(
            domain,
            || async { Some(vec![new_ip]) },
            || async {
                panic!("пригодный системный DNS не должен вызывать DoH")
            },
        )
        .await;

        assert_eq!(result, Some(vec![new_ip]));
        assert_eq!(cached_cf_ips(domain), Some(vec![new_ip]));
        clear_cf_ip(domain);
    }

    #[test]
    fn cf_dns_lock_cache_retains_only_active_requests() {
        let idle = Arc::new(tokio::sync::Mutex::new(()));
        let active = Arc::new(tokio::sync::Mutex::new(()));
        let active_request = Arc::clone(&active);
        let mut locks = CfDomainLocks::from([
            ("idle.example".into(), idle),
            ("active.example".into(), active),
        ]);

        retain_active_domain_locks(&mut locks);

        assert!(!locks.contains_key("idle.example"));
        assert!(locks.contains_key("active.example"));
        drop(active_request);
    }

    #[tokio::test]
    async fn cf_dns_single_flight_разрешает_имя_один_раз_для_параллельных_сессий() {
        let domain = "kws2.single-flight.example";
        let system_calls = Arc::new(AtomicUsize::new(0));

        let resolve = || {
            let system_calls = Arc::clone(&system_calls);
            resolve_cf_ips_with(
                domain,
                move || async move {
                    system_calls.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Some(vec!["188.114.97.1".parse().unwrap()])
                },
                || async { Some(vec!["188.114.97.2".parse().unwrap()]) },
            )
        };

        let (first, second) = tokio::join!(resolve(), resolve());

        assert_eq!(first, Some(vec!["188.114.97.1".parse().unwrap()]));
        assert_eq!(second, Some(vec!["188.114.97.1".parse().unwrap()]));
        assert_eq!(system_calls.load(Ordering::Relaxed), 1);
    }
}
