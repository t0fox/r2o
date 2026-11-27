//! HTTP/2 /api для Telegram media. По одному POST на MTProto-пакет.

use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use cipher::StreamCipher;
use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, SemaphorePermit, mpsc};
use tokio::task::JoinHandle;

use crate::bridge::{PayloadActivity, SESSION_IDLE_TIMEOUT};
use crate::crypto::{AesCtr256, HANDSHAKE_LEN, ProtoTag, direct_server_stream_cipher};
use crate::dc_discovery::{plain_probe_request, validate_res_pq_probe_response};
use crate::memory_budget::{BudgetReservation, MemoryBudget};
use crate::runtime::Runtime;
use crate::stats::ConnectionTelemetry;
use crate::ws_client::{CooldownMap, race_ws_candidates, verifying_rustls_config};

const MAX_PACKET: usize = 4 * 1024 * 1024;
const CHUNK: usize = 16 * 1024;
const MAX_REQUESTS: usize = 3;
const MEDIA_STREAM_WINDOW: usize = 128 * 1024;
const WINDOW: usize = 512 * 1024;
const SMALL_WINDOW: usize = 64 * 1024;
const SETUP_TIMEOUT: Duration = Duration::from_secs(3);
const FIRST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(4);
const RESPONSE_IDLE_TIMEOUT: Duration = Duration::from_secs(8);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIA_RETRY_DELAY: Duration = Duration::from_secs(60);
const WS_FALLBACK_DELAY: Duration = Duration::from_secs(60);
const MAX_WS_FALLBACK_DELAY: Duration = Duration::from_secs(300);
const TRIAL_LEASE: Duration = Duration::from_secs(15);
const CANCELLED_TRIAL_DELAY: Duration = Duration::from_secs(5);
const MAX_REPOST_BYTES: usize = 64 * 1024;

static CONNECTIONS: Semaphore = Semaphore::const_new(4);
static FAILED: CooldownMap<(u32, String)> = CooldownMap::new();
static MEDIA_RETRIES: [Mutex<MediaRetry>; 5] = [const { Mutex::new(MediaRetry::new()) }; 5];
static TLS_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let mut config = (*verifying_rustls_config()).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    // У WSS и HTTP/2 разные ALPN и состояние возобновления сеанса.
    config.resumption = rustls::client::Resumption::in_memory_sessions(16);
    Arc::new(config)
});

pub(crate) struct MediaClient {
    pub(crate) host: String,
    pub(crate) peer: SocketAddr,
    sender: h2::client::SendRequest<Bytes>,
    driver: JoinHandle<()>,
    buffers: Option<Arc<MemoryBudget>>,
}

struct MediaRetry {
    generation: u64,
    ready: bool,
    next_trial: Option<tokio::time::Instant>,
    fallback_delay: Duration,
}

impl MediaRetry {
    const fn new() -> Self {
        Self {
            generation: 0,
            ready: false,
            next_trial: None,
            fallback_delay: WS_FALLBACK_DELAY,
        }
    }
}

pub(crate) struct LiveRoute {
    dc: u32,
    state: &'static Mutex<MediaRetry>,
    generation: u64,
    trial: bool,
}

impl LiveRoute {
    pub(crate) fn admit(dc: u32) -> Option<Self> {
        let state = MEDIA_RETRIES.get(dc.checked_sub(1)? as usize)?;
        let mut retry = state.lock().unwrap_or_else(|error| error.into_inner());
        let trial = !retry.ready;
        if trial {
            let now = tokio::time::Instant::now();
            if retry.next_trial.is_some_and(|deadline| deadline > now) {
                return None;
            }
            retry.generation = retry.generation.wrapping_add(1);
            retry.next_trial = Some(now + TRIAL_LEASE);
        }
        Some(Self {
            dc,
            state,
            generation: retry.generation,
            trial,
        })
    }

    fn confirmed(&mut self) {
        if !self.trial {
            return;
        }
        let mut retry = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if retry.generation == self.generation {
            retry.ready = true;
            retry.next_trial = None;
            retry.fallback_delay = WS_FALLBACK_DELAY;
        }
        self.trial = false;
    }

    pub(crate) fn failed(&self, zone: &str) {
        let mut retry = self.state.lock().unwrap_or_else(|error| error.into_inner());
        // Сбой старого соединения не меняет состояние новой попытки восстановления.
        if retry.generation != self.generation {
            return;
        }
        FAILED.set((self.dc, zone.to_owned()), MEDIA_RETRY_DELAY);
        retry.generation = retry.generation.wrapping_add(1);
        retry.ready = false;
        retry.next_trial = Some(tokio::time::Instant::now() + retry.fallback_delay);
        retry.fallback_delay = retry
            .fallback_delay
            .saturating_mul(2)
            .min(MAX_WS_FALLBACK_DELAY);
    }
}

impl Drop for LiveRoute {
    fn drop(&mut self) {
        if self.trial {
            let mut retry = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if retry.generation == self.generation {
                retry.next_trial = Some(tokio::time::Instant::now() + CANCELLED_TRIAL_DELAY);
            }
        }
    }
}

struct ResetOnDrop(h2::SendStream<Bytes>);

impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        self.0.send_reset(h2::Reason::CANCEL);
    }
}

impl Drop for MediaClient {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[derive(Debug)]
pub(crate) struct MediaError {
    pub(crate) stage: &'static str,
    pub(crate) reason: String,
    pub(crate) http_status: Option<u16>,
    pub(crate) ip: Option<IpAddr>,
}

impl MediaError {
    pub(crate) fn is_upstream_failure(&self) -> bool {
        !matches!(self.stage, "client" | "capacity" | "memory")
    }

    fn new(stage: &'static str, reason: impl ToString) -> Self {
        Self {
            stage,
            reason: reason.to_string(),
            http_status: None,
            ip: None,
        }
    }
}

pub(crate) fn cooling(dc: u32, zone: &str) -> bool {
    FAILED.active(&(dc, zone.to_owned()))
}

pub(crate) fn clear_cooldown(dc: u32, zone: &str) {
    FAILED.clear(&(dc, zone.to_owned()));
}

pub(crate) async fn connect(
    runtime: &Runtime,
    dc: u32,
    zone: &str,
) -> Result<Option<(MediaClient, Duration)>, MediaError> {
    if CONNECTIONS.available_permits() == 0 {
        return Ok(None);
    }
    let budget = runtime.stats().memory_budget();
    let host = format!("kws{dc}.{zone}");
    let deadline = tokio::time::Instant::now() + SETUP_TIMEOUT;
    let ips = if runtime.cf_ips().is_empty() {
        tokio::time::timeout_at(
            deadline,
            crate::cf_proxy_doh::resolve_cf_ips(&host, runtime.outbound(), runtime.ca_bundle()),
        )
        .await
        .map_err(|_| MediaError::new("dns", "тайм-аут DNS для /api"))?
        .map_err(|error| MediaError::new("dns", error))?
    } else {
        runtime.cf_ips().to_vec()
    };
    let candidates = ips.into_iter().take(3).map(|ip| ip.to_string()).collect();
    let (winner, failures) = race_ws_candidates(
        candidates,
        Duration::from_millis(125),
        |ip| {
            let host = &host;
            let budget = &budget;
            async move {
                let result = connect_edge(runtime, &ip, host, zone, deadline, budget.clone()).await;
                result.map_err(|mut error| {
                    error.ip = ip.parse().ok();
                    error
                })
            }
        },
        |_| false,
    )
    .await;
    match winner {
        Some((_, client)) => Ok(Some(client)),
        None if !failures.is_empty()
            && failures.iter().all(|(_, error)| error.stage == "capacity") =>
        {
            Ok(None)
        }
        None => Err(failures
            .into_iter()
            .filter(|(_, error)| error.stage != "capacity")
            .last()
            .map_or_else(
                || MediaError::new("dns", "нет IP для /api"),
                |(_, error)| error,
            )),
    }
}

async fn connect_edge(
    runtime: &Runtime,
    ip: &str,
    host: &str,
    zone: &str,
    deadline: tokio::time::Instant,
    buffers: Option<Arc<MemoryBudget>>,
) -> Result<(MediaClient, Duration), MediaError> {
    let permit = CONNECTIONS
        .try_acquire()
        .map_err(|e| MediaError::new("capacity", e))?;
    let window = reserve_media_window(&buffers).map_err(|e| MediaError::new("capacity", e))?;
    let timeout = SETUP_TIMEOUT;
    let tcp = tokio::time::timeout_at(deadline, runtime.outbound().connect(ip, 443, timeout))
        .await
        .map_err(|_| MediaError::new("tcp", "тайм-аут TCP для /api"))?
        .map_err(|e| MediaError::new("tcp", e))?;
    open(
        tcp,
        host,
        zone,
        deadline,
        buffers,
        permit,
        window,
        TLS_CONFIG.clone(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn open(
    tcp: TcpStream,
    host: &str,
    zone: &str,
    deadline: tokio::time::Instant,
    buffers: Option<Arc<MemoryBudget>>,
    permit: SemaphorePermit<'static>,
    window: (usize, Option<BudgetReservation>),
    tls_config: Arc<rustls::ClientConfig>,
) -> Result<(MediaClient, Duration), MediaError> {
    let peer = tcp.peer_addr().map_err(|e| MediaError::new("tcp", e))?;
    let _ = tcp.set_nodelay(true);
    let sni = rustls_pki_types::ServerName::try_from(zone.to_owned())
        .map_err(|error| MediaError::new("tls", error))?;
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let tls = tokio::time::timeout_at(deadline, connector.connect(sni, tcp))
        .await
        .map_err(|_| MediaError::new("tls", "тайм-аут TLS для /api"))?
        .map_err(|error| MediaError::new("tls", error))?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(MediaError::new("http", "сервер не согласовал ALPN h2"));
    }
    let (connection_window, reservation) = window;
    let stream_window = if connection_window == WINDOW {
        MEDIA_STREAM_WINDOW
    } else {
        CHUNK
    };
    let handshake = h2::client::Builder::new()
        .initial_window_size(stream_window as u32)
        .initial_connection_window_size(connection_window as u32)
        .max_header_list_size(8 * 1024)
        .max_send_buffer_size(CHUNK)
        .handshake(tls);
    let (sender, connection) = tokio::time::timeout_at(deadline, handshake)
        .await
        .map_err(|_| MediaError::new("http", "тайм-аут установки HTTP/2"))?
        .map_err(|error| MediaError::new("http", error))?;
    let driver = tokio::spawn(async move {
        let _permit = permit;
        let _window = reservation;
        let _ = connection.await;
    });
    let client = MediaClient {
        host: host.to_owned(),
        peer,
        sender,
        driver,
        buffers,
    };
    let (nonce, request) = plain_probe_request().map_err(|e| MediaError::new("mtproto", e))?;
    let started = Instant::now();
    let reply = tokio::time::timeout_at(
        deadline,
        client.post(Bytes::copy_from_slice(request.as_ref()), 1024),
    )
    .await
    .map_err(|_| MediaError::new("mtproto", "тайм-аут req_pq_multi/resPQ через /api"))??;
    validate_res_pq_probe_response(&reply.bytes, nonce)
        .map_err(|e| MediaError::new("mtproto", e))?;
    Ok((client, started.elapsed()))
}

fn reserve_media_window(
    buffers: &Option<Arc<MemoryBudget>>,
) -> io::Result<(usize, Option<BudgetReservation>)> {
    // При дефиците памяти сохраняем прежние окна HTTP/2.
    reserve(buffers, WINDOW * 2)
        .map(|reservation| (WINDOW, reservation))
        .or_else(|_| {
            reserve(buffers, SMALL_WINDOW * 2).map(|reservation| (SMALL_WINDOW, reservation))
        })
}

struct Reply {
    bytes: Vec<u8>,
    _memory: Option<BudgetReservation>,
}

fn reserve(
    budget: &Option<Arc<MemoryBudget>>,
    size: usize,
) -> io::Result<Option<BudgetReservation>> {
    budget
        .as_ref()
        .map(|budget| {
            BudgetReservation::acquire(budget, size).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "исчерпан бюджет буферов Telegram",
                )
            })
        })
        .transpose()
}

impl MediaClient {
    async fn post(&self, mut data: Bytes, limit: usize) -> Result<Reply, MediaError> {
        let http_error = |e: h2::Error| MediaError::new("http", e);
        let request = http::Request::post(format!("https://{}/api", self.host))
            .header("content-type", "application/octet-stream")
            .header("accept-encoding", "identity")
            .header("content-length", data.len())
            .body(())
            .map_err(|e| MediaError::new("http", e))?;
        let mut sender = self.sender.clone().ready().await.map_err(http_error)?;
        let (response, send) = sender.send_request(request, false).map_err(http_error)?;
        let mut send = ResetOnDrop(send);
        while !data.is_empty() {
            send.0.reserve_capacity(data.len().min(CHUNK));
            let capacity = poll_fn(|cx| send.0.poll_capacity(cx))
                .await
                .ok_or_else(|| MediaError::new("http", "поток загрузки HTTP/2 закрыт"))?
                .map_err(http_error)?;
            if capacity == 0 {
                continue;
            }
            let chunk = data.split_to(capacity.min(data.len()).min(CHUNK));
            send.0
                .send_data(chunk, data.is_empty())
                .map_err(http_error)?;
        }
        let response = tokio::time::timeout(RESPONSE_IDLE_TIMEOUT, response)
            .await
            .map_err(|_| MediaError::new("http", "тайм-аут заголовков POST /api"))?
            .map_err(http_error)?;
        if response.status() != http::StatusCode::OK {
            let status = response.status().as_u16();
            let mut error = MediaError::new("http", format!("POST /api: HTTP {status}"));
            error.http_status = Some(status);
            return Err(error);
        }
        if response
            .headers()
            .get("content-encoding")
            .is_some_and(|value| value != "identity")
        {
            return Err(MediaError::new("http", "сжатый ответ /api"));
        }
        let declared = response
            .headers()
            .get("content-length")
            .map(|n| {
                n.to_str()
                    .ok()
                    .and_then(|n| n.parse::<usize>().ok())
                    .ok_or_else(|| MediaError::new("http", "некорректный Content-Length"))
            })
            .transpose()?;
        let capacity = declared.unwrap_or(limit);
        if capacity > limit {
            return Err(MediaError::new("http", "ответ /api превышает лимит"));
        }
        let mut memory = reserve(&self.buffers, 0).map_err(|e| MediaError::new("memory", e))?;
        let mut bytes = Vec::new();
        let mut body = response.into_body();
        let mut deadline = tokio::time::Instant::now() + RESPONSE_IDLE_TIMEOUT;
        while let Some(chunk) = tokio::time::timeout_at(deadline, body.data())
            .await
            .map_err(|_| MediaError::new("http", "тайм-аут передачи тела POST /api"))?
        {
            let chunk = chunk.map_err(http_error)?;
            if !chunk.is_empty() {
                deadline = tokio::time::Instant::now() + RESPONSE_IDLE_TIMEOUT;
            }
            if chunk.len() > capacity - bytes.len() {
                return Err(MediaError::new(
                    "http",
                    "ответ /api превышает объявленный размер",
                ));
            }
            let len = bytes.len() + chunk.len();
            if len > bytes.capacity() {
                let next_capacity = len.next_power_of_two().min(capacity);
                if let Some(memory) = memory.as_mut()
                    && !memory.grow(next_capacity - bytes.capacity())
                {
                    return Err(MediaError::new("memory", "исчерпан бюджет ответа /api"));
                }
                bytes.reserve_exact(next_capacity - bytes.len());
            }
            bytes.extend_from_slice(&chunk);
            body.flow_control()
                .release_capacity(chunk.len())
                .map_err(http_error)?;
        }
        if declared.is_some_and(|n| n != bytes.len()) {
            return Err(MediaError::new(
                "http",
                "ответ /api не соответствует Content-Length",
            ));
        }
        Ok(Reply {
            bytes,
            _memory: memory,
        })
    }

    async fn post_media(&self, packet: Bytes) -> Result<Reply, MediaError> {
        let may_repost = packet.len() <= MAX_REPOST_BYTES && packet[..8] != [0; 8];
        let backup = may_repost.then(|| packet.clone());
        let reply = self.post(packet, MAX_PACKET).await?;
        if let Some(packet) = backup
            && reply.bytes.is_empty()
        {
            // Один повтор пустого ответа для уже зашифрованного msg_id; Telegram удаляет дубликаты.
            tokio::time::sleep(Duration::from_secs(1)).await;
            return self.post(packet, MAX_PACKET).await;
        }
        Ok(reply)
    }

    pub(crate) async fn relay(
        self,
        stream: TcpStream,
        init: [u8; HANDSHAKE_LEN],
        proto: ProtoTag,
        route: &mut LiveRoute,
        telemetry: &ConnectionTelemetry,
    ) -> Result<(), MediaError> {
        let (mut reader, mut writer) = stream.into_split();
        let (mut decrypt, _) = crate::transparent::direct_stream_ciphers(&init);
        let mut encrypt = direct_server_stream_cipher(&init);
        let mut observer = crate::response_observer::MtprotoResponseObserver::new(&init, proto);
        let (send, mut receive) = mpsc::channel(1);
        let buffers = &self.buffers;
        let activity = PayloadActivity::new();
        let upload_activity = &activity;
        let upload = async move {
            loop {
                let Some((bytes, reservation)) =
                    read_packet(&mut reader, &mut decrypt, proto, buffers)
                        .await
                        .map_err(|error| {
                            let stage = if error.kind() == io::ErrorKind::OutOfMemory {
                                "memory"
                            } else {
                                "client"
                            };
                            MediaError::new(stage, error)
                        })?
                else {
                    return Ok(());
                };
                telemetry.record_client_bytes(bytes.len() as u64);
                upload_activity.touch();
                if send.send((bytes, reservation)).await.is_err() {
                    return Ok(());
                }
            }
        };
        let download = async {
            let mut pending = FuturesUnordered::new();
            let mut input_open = true;
            let mut first = None::<tokio::time::Instant>;
            let mut confirmed = false;
            while input_open || !pending.is_empty() {
                tokio::select! {
                    packet = receive.recv(), if input_open && pending.len() < MAX_REQUESTS => {
                        if let Some((packet, memory)) = packet {
                            first.get_or_insert_with(tokio::time::Instant::now);
                            let client = &self;
                            pending.push(async move {
                                let _packet_memory = memory;
                                tokio::time::timeout(REQUEST_TIMEOUT, client.post_media(packet))
                                    .await.map_err(|_| MediaError::new("http", "тайм-аут POST /api"))?
                            });
                        } else {
                            input_open = false;
                        }
                    }
                    reply = pending.next(), if !pending.is_empty() => {
                        let mut reply = reply.expect("ожидается ответ HTTP/2")?;
                        if reply.bytes.is_empty() { continue; }
                        if !reply.bytes.len().is_multiple_of(4) {
                            return Err(MediaError::new("mtproto", "неверное выравнивание ответа /api"));
                        }
                        let mut header = response_header(reply.bytes.len(), proto);
                        encrypt.apply_keystream(&mut header);
                        encrypt.apply_keystream(&mut reply.bytes);
                        if !confirmed {
                            let observed = observer.observe(&header).and_then(|_| observer.observe(&reply.bytes));
                            if observed == Ok(true) {
                                confirmed = true;
                                let latency = first.expect("ответ следует за запросом").elapsed();
                                telemetry.mark_mtproto_response(latency);
                                crate::stats::global().record_mtproto_response_with_client_latency(
                                    route.dc, "cf-h2", latency, telemetry.client_elapsed_us(),
                                );
                            }
                        }
                        telemetry.record_upstream_bytes((header.len() + reply.bytes.len()) as u64);
                        activity.touch();
                        writer.write_all(&header).await.map_err(|e| MediaError::new("client", e))?;
                        writer.write_all(&reply.bytes).await.map_err(|e| MediaError::new("client", e))?;
                        if confirmed {
                            route.confirmed();
                        }
                    }
                    _ = async {
                        if let Some(started) = first {
                            tokio::time::sleep_until(started + FIRST_RESPONSE_TIMEOUT).await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    }, if !confirmed && pending.is_empty() => return Err(no_first_response()),
                }
            }
            if first.is_some() && !confirmed {
                return Err(no_first_response());
            }
            Ok(())
        };
        tokio::select! {
            result = async { tokio::try_join!(upload, download) } => result.map(|_| ()),
            _ = activity.idle_reached(SESSION_IDLE_TIMEOUT) => Ok(()),
        }
    }
}

fn no_first_response() -> MediaError {
    MediaError::new("mtproto", "нет первого MTProto-ответа /api")
}

async fn read_packet(
    reader: &mut (impl AsyncRead + Unpin),
    cipher: &mut AesCtr256,
    proto: ProtoTag,
    budget: &Option<Arc<MemoryBudget>>,
) -> io::Result<Option<(Bytes, Option<BudgetReservation>)>> {
    let mut header = [0; 4];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    cipher.apply_keystream(&mut header[..1]);
    let len = if proto == ProtoTag::Abridged && header[0] & 0x7f < 0x7f {
        usize::from(header[0] & 0x7f) * 4
    } else {
        reader.read_exact(&mut header[1..]).await?;
        cipher.apply_keystream(&mut header[1..]);
        if proto == ProtoTag::Abridged {
            (u32::from_le_bytes(header) >> 8) as usize * 4
        } else {
            (u32::from_le_bytes(header) & 0x7fff_ffff) as usize
        }
    };
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "некорректный пакет MTProto для /api",
        )
    };
    let padding = usize::from(proto == ProtoTag::PaddedIntermediate) * 15;
    if !(24..=MAX_PACKET + padding).contains(&len) {
        return Err(invalid());
    }
    let memory = reserve(budget, len)?;
    let mut body = vec![0; len];
    reader.read_exact(&mut body).await?;
    cipher.apply_keystream(&mut body);
    if proto == ProtoTag::PaddedIntermediate {
        let inner = if body[..8] == [0; 8] {
            20usize.saturating_add(u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize)
        } else {
            24 + (len - 24) / 16 * 16
        };
        if !(24..=len).contains(&inner) || len - inner > 15 {
            return Err(invalid());
        }
        body.truncate(inner);
    }
    if body.len() > MAX_PACKET || !body.len().is_multiple_of(4) {
        return Err(invalid());
    }
    Ok(Some((Bytes::from(body), memory)))
}

fn response_header(len: usize, proto: ProtoTag) -> Vec<u8> {
    if proto == ProtoTag::Abridged {
        let words = (len / 4) as u32;
        if words < 127 {
            vec![words as u8]
        } else {
            ((words << 8) | 0x7f).to_le_bytes().to_vec()
        }
    } else {
        (len as u32).to_le_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests;
